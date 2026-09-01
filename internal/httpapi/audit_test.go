package httpapi

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/store"
)

func TestEncodeAuditExportEnforcesByteLimit(t *testing.T) {
	items := []store.AuditEvent{
		{ID: 1, Action: "first", Metadata: json.RawMessage(`{"key":"value"}`)},
		{ID: 2, Action: "second", Metadata: json.RawMessage(`{"key":"value"}`)},
	}
	complete, err := encodeAuditExport(items, 4096)
	if err != nil || len(complete) == 0 || complete[len(complete)-1] != '\n' {
		t.Fatalf("complete export bytes=%d err=%v", len(complete), err)
	}
	partialLimit := len(complete) - 1
	partial, err := encodeAuditExport(items, partialLimit)
	if !errors.Is(err, errAuditExportTooLarge) || partial != nil {
		t.Fatalf("bounded export bytes=%d err=%v", len(partial), err)
	}
}
