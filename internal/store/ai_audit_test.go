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
    volumes:
      - uploads:/srv/uploads
      - /host/path:/srv/bind
      - type: volume
        source: cache
        target: /srv/cache
      - type: tmpfs
        target: /tmp
  source:
    build: ./private-source
    volumes:
      - uploads:/other
  incomplete:
    command: [sleep, infinity]
volumes:
  uploads: {}
  cache: {}
  unused: {}
`
	posture := analyzeAIAuditWorkload(serviceID, compose)
	if posture.ServiceID != serviceID || !posture.DefinitionParseable || posture.ContainerCount != 4 || posture.DigestPinnedImages != 1 || posture.MutableImages != 1 || posture.BuildOnlyServices != 1 || posture.MissingImageOrBuild != 1 || strings.Join(posture.NamedVolumes, ",") != "cache,uploads" {
		t.Fatalf("workload posture=%#v", posture)
	}
}

func TestAnalyzeAIAuditWorkloadFailsClosedForMalformedDefinitions(t *testing.T) {
	for _, compose := range []string{"not: [valid", "services: {}", "services: {api: invalid}", "services: {api: {image: app, volumes: invalid}}", "services: {api: {image: app}, volumes: []}"} {
		if posture := analyzeAIAuditWorkload(uuid.New(), compose); posture.DefinitionParseable {
			t.Fatalf("malformed Compose reported valid: %#v", posture)
		}
	}
}
