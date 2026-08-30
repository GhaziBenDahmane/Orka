package netpolicy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

func TestPolicyBlocksSpecialUseAddressesByDefault(t *testing.T) {
	policy := &Policy{Resolver: staticResolver{
		"public.example": {netip.MustParseAddr("203.0.113.10")},
		"mixed.example":  {netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("10.0.0.8")},
	}}
	for _, host := range []string{"127.0.0.1", "10.0.0.8", "169.254.169.254", "100.64.0.1", "::1", "mixed.example"} {
		if err := policy.CheckHost(context.Background(), host); err == nil || !strings.Contains(err.Error(), "blocks address") {
			t.Errorf("host %q error=%v", host, err)
		}
	}
	if err := policy.CheckHost(context.Background(), "public.example"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyAllowsOnlyExplicitPrivateNetworks(t *testing.T) {
	allowed, err := ParseAllowedCIDRs("10.20.0.0/16, fd00:1234::/48")
	if err != nil {
		t.Fatal(err)
	}
	policy := &Policy{Allowed: allowed}
	for _, host := range []string{"10.20.4.8", "fd00:1234::5"} {
		if err = policy.CheckHost(context.Background(), host); err != nil {
			t.Errorf("allowed host %q: %v", host, err)
		}
	}
	for _, host := range []string{"10.21.4.8", "fd00:5678::5"} {
		if err = policy.CheckHost(context.Background(), host); err == nil {
			t.Errorf("unlisted host %q was allowed", host)
		}
	}
}

func TestParseAllowedCIDRsFailsClosed(t *testing.T) {
	for _, value := range []string{"not-a-cidr", "10.0.0.1", "10.0.0.0/8,10.0.0.0/8", strings.Repeat("10.0.0.0/8,", maxAllowedCIDRs+1)} {
		if _, err := ParseAllowedCIDRs(value); err == nil {
			t.Errorf("invalid allowlist %q was accepted", value)
		}
	}
}

func TestHTTPTransportEnforcesPolicyAtDialTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()

	blockedClient := &http.Client{Transport: (&Policy{}).Transport()}
	if _, err := blockedClient.Get(server.URL); err == nil || !strings.Contains(err.Error(), "egress policy blocks") {
		t.Fatalf("loopback request error=%v", err)
	}
	allowed, err := ParseAllowedCIDRs("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	allowedClient := &http.Client{Transport: (&Policy{Allowed: allowed}).Transport()}
	response, err := allowedClient.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

func TestHTTPTransportRejectsMixedDNSBeforeConnecting(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := ParseAllowedCIDRs("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	policy := &Policy{Allowed: allowed, Resolver: staticResolver{"mixed.example": {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.8")}}}
	client := &http.Client{Transport: policy.Transport()}
	if _, err = client.Get("http://mixed.example:" + parsed.Port()); err == nil || !strings.Contains(err.Error(), "egress policy blocks") {
		t.Fatalf("mixed DNS request error=%v", err)
	}
	if calls != 0 {
		t.Fatalf("mixed DNS request reached allowed address %d time(s)", calls)
	}
}
