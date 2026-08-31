package releaseevidence

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

type productionEvidenceRoundTripper func(*http.Request) (*http.Response, error)

func (f productionEvidenceRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestVerifyProductionEvidence(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	certification := validCertification(now)
	body := []byte("independently reviewed production evidence\n")
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	for name, gate := range certification.Gates {
		gate.Evidence[0].SHA256 = digest
		certification.Gates[name] = gate
	}
	requests := 0
	client := &http.Client{Transport: productionEvidenceRoundTripper(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodGet || request.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("unexpected evidence request method=%s accept-encoding=%q", request.Method, request.Header.Get("Accept-Encoding"))
		}
		return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header), Request: request}, nil
	})}
	if err := verifyProductionEvidence(context.Background(), certification, client, 1024); err != nil {
		t.Fatal(err)
	}
	if requests != len(requiredProductionGates) {
		t.Fatalf("evidence requests=%d want=%d", requests, len(requiredProductionGates))
	}
}

func TestVerifyProductionEvidenceRejectsInvalidArtifact(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		statusCode int
		body       string
		maxBytes   int64
		want       string
	}{
		{name: "status", statusCode: http.StatusNotFound, body: "missing", maxBytes: 1024, want: "HTTP status 404"},
		{name: "oversized", statusCode: http.StatusOK, body: "too large", maxBytes: 4, want: "exceeds 4 bytes"},
		{name: "hash mismatch", statusCode: http.StatusOK, body: "different", maxBytes: 1024, want: "sha256 mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			certification := validCertification(now)
			client := &http.Client{Transport: productionEvidenceRoundTripper(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.statusCode, ContentLength: int64(len(test.body)), Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header), Request: request}, nil
			})}
			err := verifyProductionEvidence(context.Background(), certification, client, test.maxBytes)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
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
		{"future", func(c *ProductionCertification) { c.CreatedAt = now.Add(time.Second) }, "createdAt"},
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
		{"invalid URL host", func(c *ProductionCertification) {
			gate := c.Gates[requiredProductionGates[0]]
			gate.Evidence[0].URL = "https://bad_label.example.test/report"
			c.Gates[requiredProductionGates[0]] = gate
		}, "valid host"},
		{"invalid URL port", func(c *ProductionCertification) {
			gate := c.Gates[requiredProductionGates[0]]
			gate.Evidence[0].URL = "https://evidence.example.test:65536/report"
			c.Gates[requiredProductionGates[0]] = gate
		}, "valid host"},
		{"encoded URL path", func(c *ProductionCertification) {
			gate := c.Gates[requiredProductionGates[0]]
			gate.Evidence[0].URL = "https://evidence.example.test/reports%2fhidden.json"
			c.Gates[requiredProductionGates[0]] = gate
		}, "canonical"},
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
