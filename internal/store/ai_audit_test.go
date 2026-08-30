package store

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAnalyzeAIAuditWorkloadReportsOnlyImageProvenanceCounts(t *testing.T) {
	serviceID := uuid.New()
	compose := `services:
  pinned:
    image: registry.example.test/team/private@sha256:` + strings.Repeat("a", 64) + `
    environment:
      SECRET_VALUE: do-not-expose
  mutable:
    image: registry.example.test/team/private:latest
  source:
    build: ./private-source
  incomplete:
    command: [sleep, infinity]
`
	posture := analyzeAIAuditWorkload(serviceID, compose)
	if posture.ServiceID != serviceID || !posture.DefinitionParseable || posture.ContainerCount != 4 || posture.DigestPinnedImages != 1 || posture.MutableImages != 1 || posture.BuildOnlyServices != 1 || posture.MissingImageOrBuild != 1 {
		t.Fatalf("workload posture=%#v", posture)
	}
}

func TestAnalyzeAIAuditWorkloadFailsClosedForMalformedDefinitions(t *testing.T) {
	for _, compose := range []string{"not: [valid", "services: {}", "services: {api: invalid}"} {
		if posture := analyzeAIAuditWorkload(uuid.New(), compose); posture.DefinitionParseable {
			t.Fatalf("malformed Compose reported valid: %#v", posture)
		}
	}
}
