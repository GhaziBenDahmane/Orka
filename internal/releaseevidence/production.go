package releaseevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const ProductionCertificationSchema = 1
const maxProductionCertificationBytes = 256 << 10

var (
	commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
	digestPattern = regexp.MustCompile(`^ghcr\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*@sha256:[a-f0-9]{64}$`)
	hashPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

var requiredProductionGates = [...]string{
	"external-integrations",
	"production-data-upgrade",
	"production-storage-recovery",
	"multi-host-swarm",
	"hardening-review",
	"control-plane-recovery",
	"live-dokploy-cutover",
	"production-topology-soak",
}

type ProductionCertification struct {
	SchemaVersion  int                       `json:"schemaVersion"`
	SourceCommit   string                    `json:"sourceCommit"`
	CandidateImage string                    `json:"candidateImage"`
	Environment    string                    `json:"environment"`
	Owner          string                    `json:"owner"`
	CreatedAt      time.Time                 `json:"createdAt"`
	ExpiresAt      time.Time                 `json:"expiresAt"`
	Gates          map[string]ProductionGate `json:"gates"`
}

type ProductionGate struct {
	Owner       string             `json:"owner"`
	CompletedAt time.Time          `json:"completedAt"`
	Evidence    []ProductionRecord `json:"evidence"`
}

type ProductionRecord struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

func DecodeProductionCertification(reader io.Reader) (ProductionCertification, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxProductionCertificationBytes+1))
	if err != nil {
		return ProductionCertification{}, fmt.Errorf("read production certification: %w", err)
	}
	if len(data) > maxProductionCertificationBytes {
		return ProductionCertification{}, fmt.Errorf("production certification exceeds %d bytes", maxProductionCertificationBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var certification ProductionCertification
	if err = decoder.Decode(&certification); err != nil {
		return ProductionCertification{}, fmt.Errorf("decode production certification: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return ProductionCertification{}, errors.New("decode production certification: multiple JSON values")
		}
		return ProductionCertification{}, fmt.Errorf("decode production certification: %w", err)
	}
	return certification, nil
}

func (c ProductionCertification) Validate(expectedCommit, expectedImage string, now time.Time) error {
	if c.SchemaVersion != ProductionCertificationSchema {
		return fmt.Errorf("schemaVersion must be %d", ProductionCertificationSchema)
	}
	if !commitPattern.MatchString(c.SourceCommit) || c.SourceCommit != expectedCommit {
		return errors.New("sourceCommit must match the exact 40-character candidate commit")
	}
	if !digestPattern.MatchString(c.CandidateImage) || c.CandidateImage != expectedImage {
		return errors.New("candidateImage must match the exact lowercase GHCR digest")
	}
	if err := boundedText("environment", c.Environment, 128); err != nil {
		return err
	}
	if err := boundedText("owner", c.Owner, 200); err != nil {
		return err
	}
	now = now.UTC()
	if c.CreatedAt.IsZero() || c.CreatedAt.After(now.Add(5*time.Minute)) || c.CreatedAt.Before(now.Add(-30*24*time.Hour)) {
		return errors.New("createdAt must be within the last 30 days and not in the future")
	}
	if !c.ExpiresAt.After(now) || !c.ExpiresAt.After(c.CreatedAt) || c.ExpiresAt.After(c.CreatedAt.Add(31*24*time.Hour)) {
		return errors.New("expiresAt must be after now and createdAt, and no more than 31 days after creation")
	}
	if len(c.Gates) != len(requiredProductionGates) {
		return fmt.Errorf("gates must contain exactly %d required production gates", len(requiredProductionGates))
	}
	required := make(map[string]struct{}, len(requiredProductionGates))
	for _, name := range requiredProductionGates {
		required[name] = struct{}{}
		gate, ok := c.Gates[name]
		if !ok {
			return fmt.Errorf("required production gate %q is missing", name)
		}
		if err := validateProductionGate(name, gate, c.CreatedAt); err != nil {
			return err
		}
	}
	for name := range c.Gates {
		if _, ok := required[name]; !ok {
			return fmt.Errorf("unknown production gate %q", name)
		}
	}
	return nil
}

func validateProductionGate(name string, gate ProductionGate, certifiedAt time.Time) error {
	if err := boundedText("gate "+name+" owner", gate.Owner, 200); err != nil {
		return err
	}
	if gate.CompletedAt.IsZero() || gate.CompletedAt.After(certifiedAt.Add(5*time.Minute)) || gate.CompletedAt.Before(certifiedAt.Add(-30*24*time.Hour)) {
		return fmt.Errorf("gate %q completedAt must be within 30 days before certification", name)
	}
	if len(gate.Evidence) == 0 || len(gate.Evidence) > 20 {
		return fmt.Errorf("gate %q must contain between 1 and 20 evidence records", name)
	}
	seen := make(map[string]struct{}, len(gate.Evidence))
	for index, record := range gate.Evidence {
		if err := boundedText(fmt.Sprintf("gate %s evidence %d name", name, index), record.Name, 200); err != nil {
			return err
		}
		parsed, err := url.Parse(record.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(record.URL) > 2048 {
			return fmt.Errorf("gate %q evidence %d URL must be a credential-free HTTPS URL without query or fragment", name, index)
		}
		if !hashPattern.MatchString(record.SHA256) {
			return fmt.Errorf("gate %q evidence %d sha256 must be 64 lowercase hexadecimal characters", name, index)
		}
		if _, exists := seen[record.URL]; exists {
			return fmt.Errorf("gate %q contains duplicate evidence URL %q", name, record.URL)
		}
		seen[record.URL] = struct{}{}
	}
	return nil
}

func boundedText(name, value string, maximum int) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > maximum || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s must be non-empty, trimmed, and at most %d bytes", name, maximum)
	}
	return nil
}
