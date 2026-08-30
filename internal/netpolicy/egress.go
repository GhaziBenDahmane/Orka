package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
)

const maxAllowedCIDRs = 64

var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// Resolver is the subset of net.Resolver used by Policy. It is an interface so
// policy behavior can be tested without depending on external DNS.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Policy prevents tenant-configured destinations from reaching private host
// networks unless an operator has explicitly allowed the destination CIDR.
// Resolution is repeated by DialContext so a validation-time DNS answer cannot
// be swapped for an internal address at connection time.
type Policy struct {
	Allowed  []netip.Prefix
	Resolver Resolver
	Dialer   *net.Dialer
}

func ParseAllowedCIDRs(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxAllowedCIDRs {
		return nil, fmt.Errorf("egress private CIDR allowlist may contain at most %d networks", maxAllowedCIDRs)
	}
	result := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" {
			return nil, fmt.Errorf("egress private CIDR allowlist contains invalid CIDR %q", value)
		}
		prefix = prefix.Masked()
		if _, duplicate := seen[prefix]; duplicate {
			return nil, fmt.Errorf("egress private CIDR allowlist contains duplicate CIDR %q", value)
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	return result, nil
}

func (p *Policy) CheckHost(ctx context.Context, host string) error {
	_, err := p.ResolveHost(ctx, host)
	return err
}

// ResolveHost returns every permitted address for host. Callers that delegate
// connection setup to another process can pin that process to these addresses.
func (p *Policy) ResolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	addresses, err := p.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if !p.permitted(address) {
			return nil, fmt.Errorf("egress policy blocks address %s for host %q", address, host)
		}
	}
	return addresses, nil
}

func (p *Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid egress address %q: %w", address, err)
	}
	addresses, err := p.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := p.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	for _, candidate := range addresses {
		if !p.permitted(candidate) {
			return nil, fmt.Errorf("egress policy blocks address %s for host %q", candidate, host)
		}
	}
	var failures []error
	for _, candidate := range addresses {
		target := net.JoinHostPort(candidate.String(), port)
		connection, dialErr := dialer.DialContext(ctx, network, target)
		if dialErr == nil {
			return connection, nil
		}
		failures = append(failures, dialErr)
	}
	return nil, fmt.Errorf("dial egress host %q: %w", host, errors.Join(failures...))
}

// Transport deliberately ignores proxy environment variables. Otherwise a
// proxy would resolve the tenant-controlled target outside this policy.
func (p *Policy) Transport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = p.DialContext
	return transport
}

func (p *Policy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("egress host is empty")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return nil, errors.New("scoped IP addresses are not valid egress destinations")
		}
		return []netip.Addr{address.Unmap()}, nil
	}
	if len(host) > 253 {
		return nil, errors.New("egress hostname is too long")
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabel.MatchString(label) {
			return nil, fmt.Errorf("egress hostname %q is invalid", host)
		}
	}
	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve egress host %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve egress host %q: no addresses", host)
	}
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.Zone() != "" {
			return nil, fmt.Errorf("resolve egress host %q: scoped address is not allowed", host)
		}
		result = append(result, address.Unmap())
	}
	return result, nil
}

func (p *Policy) permitted(address netip.Addr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	for _, prefix := range p.Allowed {
		if prefix.Contains(address) {
			return true
		}
	}
	return address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !sharedAddressSpace.Contains(address)
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")
