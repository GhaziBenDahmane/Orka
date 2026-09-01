package deploy

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestEncodeAuditArchiveIncludesChainManifest(t *testing.T) {
	organizationID, batchID := uuid.New(), uuid.New()
	createdAt := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	batch := store.AuditArchiveBatch{ID: batchID, OrganizationID: organizationID, FirstEventID: 10, LastEventID: 11, PreviousSHA256: "previous", CreatedAt: createdAt}
	events := []store.AuditEvent{{ID: 10, Action: "project.create", ResourceType: "project", Metadata: json.RawMessage(`{}`)}, {ID: 11, Action: "service.create", ResourceType: "service", Metadata: json.RawMessage(`{}`)}}
	contents, digest, err := encodeAuditArchive(batch, events)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 || !bytes.Contains(contents, []byte(`"previousSha256":"previous"`)) || !bytes.Contains(contents, []byte(`"id":11`)) {
		t.Fatalf("digest=%q contents=%s", digest, contents)
	}
	contentsAgain, digestAgain, err := encodeAuditArchive(batch, events)
	if err != nil || digestAgain != digest || !bytes.Equal(contentsAgain, contents) {
		t.Fatal("audit archive encoding is not deterministic")
	}
}

func TestEncodeAuditArchiveRejectsWrongRange(t *testing.T) {
	_, _, err := encodeAuditArchive(store.AuditArchiveBatch{FirstEventID: 2, LastEventID: 2}, []store.AuditEvent{{ID: 1}})
	if err == nil {
		t.Fatal("out-of-range event was accepted")
	}
}
