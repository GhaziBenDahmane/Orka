package releaseevidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validCertification(now time.Time) ProductionCertification {
	gates := make(map[string]ProductionGate, len(requiredProductionGates))
	for _, name := range requiredProductionGates {
		gates[name] = ProductionGate{
			Owner:       "platform-team",
			CompletedAt: now.Add(-time.Hour),
			Evidence: []ProductionRecord{{
				Name:   name + " report",
				URL:    "https://evidence.example.test/releases/" + name + ".json",
				SHA256: strings.Repeat("a", 64),
			}},
		}
	}
	return ProductionCertification{
		SchemaVersion:  ProductionCertificationSchema,
		SourceCommit:   strings.Repeat("b", 40),
		CandidateImage: "ghcr.io/acme/orka@sha256:" + strings.Repeat("c", 64),
		Environment:    "production-eu",
		Owner:          "release-manager",
		CreatedAt:      now,
		ExpiresAt:      now.Add(7 * 24 * time.Hour),
		Gates:          gates,
	}
}

func TestProductionCertificationValidation(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	valid := validCertification(now)
	if err := valid.Validate(valid.SourceCommit, valid.CandidateImage, now); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*ProductionCertification)
		want   string
	}{
		{"wrong commit", func(c *ProductionCertification) { c.SourceCommit = strings.Repeat("d", 40) }, "sourceCommit"},
		{"mutable image", func(c *ProductionCertification) { c.CandidateImage = "ghcr.io/acme/orka:latest" }, "candidateImage"},
		{"expired", func(c *ProductionCertification) { c.ExpiresAt = now.Add(-time.Minute) }, "expiresAt"},
		{"stale", func(c *ProductionCertification) { c.CreatedAt = now.Add(-31 * 24 * time.Hour) }, "createdAt"},
		{"missing gate", func(c *ProductionCertification) { delete(c.Gates, requiredProductionGates[0]) }, "exactly"},
		{"unknown gate", func(c *ProductionCertification) { c.Gates["invented"] = c.Gates[requiredProductionGates[0]] }, "exactly"},
		{"no evidence", func(c *ProductionCertification) {
			gate := c.Gates[requiredProductionGates[0]]
			gate.Evidence = nil
			c.Gates[requiredProductionGates[0]] = gate
		}, "evidence records"},
		{"credential URL", func(c *ProductionCertification) {
			gate := c.Gates[requiredProductionGates[0]]
			gate.Evidence[0].URL = "https://token@example.test/report"
			c.Gates[requiredProductionGates[0]] = gate
		}, "credential-free"},
		{"query URL", func(c *ProductionCertification) {
			gate := c.Gates[requiredProductionGates[0]]
			gate.Evidence[0].URL += "?token=secret"
			c.Gates[requiredProductionGates[0]] = gate
		}, "credential-free"},
		{"invalid hash", func(c *ProductionCertification) {
			gate := c.Gates[requiredProductionGates[0]]
			gate.Evidence[0].SHA256 = "ABC"
			c.Gates[requiredProductionGates[0]] = gate
		}, "sha256"},
		{"control character", func(c *ProductionCertification) { c.Owner = "release\nmanager" }, "owner"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := validCertification(now)
			test.mutate(&candidate)
			err := candidate.Validate(valid.SourceCommit, valid.CandidateImage, now)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDecodeProductionCertificationRejectsUnknownAndTrailingData(t *testing.T) {
	for _, input := range []string{
		`{"schemaVersion":1,"unknown":true}`,
		`{} {}`,
	} {
		if _, err := DecodeProductionCertification(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted invalid document %s", input)
		}
	}
}

func TestDecodeProductionCertificationRoundTripAndSizeLimit(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	want := validCertification(now)
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeProductionCertification(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err = got.Validate(want.SourceCommit, want.CandidateImage, now); err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeProductionCertification(strings.NewReader(strings.Repeat(" ", maxProductionCertificationBytes+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized document error=%v", err)
	}
}
