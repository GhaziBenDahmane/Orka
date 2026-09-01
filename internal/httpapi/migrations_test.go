package httpapi

import (
	"strings"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/store"
)

func TestMigrationResourceCursorRoundTripAndFilterBinding(t *testing.T) {
	want := store.MigrationResourcePageCursor{SourceOrganizationID: "source-org", SourceKind: "application", SourceID: "app-42"}
	encoded, err := encodeMigrationResourceCursor("source-org", want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeMigrationResourceCursor(encoded, "source-org")
	if err != nil || *got != want {
		t.Fatalf("cursor=%#v err=%v", got, err)
	}
	if _, err = decodeMigrationResourceCursor(encoded, "other-source"); err == nil {
		t.Fatal("cursor was accepted with a different source filter")
	}
	for _, invalid := range []string{"not-base64!", "e30", strings.Repeat("a", 8193)} {
		if _, err = decodeMigrationResourceCursor(invalid, "source-org"); err == nil {
			t.Fatalf("invalid cursor %q was accepted", invalid[:min(len(invalid), 32)])
		}
	}
}

func TestNormalizeMigrationAcknowledgements(t *testing.T) {
	got, err := normalizeMigrationAcknowledgements([]string{" application:app-1 ", "source_credential:github:credential-1", "application:app-1"})
	if err != nil || len(got) != 2 || got[0] != "application:app-1" || got[1] != "source_credential:github:credential-1" {
		t.Fatalf("acknowledgements=%#v err=%v", got, err)
	}
	for _, invalid := range [][]string{{""}, {"missing-colon"}, {":missing-kind"}, {"missing-source:"}, {strings.Repeat("a", 1025) + ":id"}} {
		if _, err = normalizeMigrationAcknowledgements(invalid); err == nil {
			t.Fatalf("invalid acknowledgement %#v was accepted", invalid)
		}
	}
	tooMany := make([]string, 1001)
	for index := range tooMany {
		tooMany[index] = "application:item"
	}
	if _, err = normalizeMigrationAcknowledgements(tooMany); err == nil {
		t.Fatal("oversized acknowledgement list was accepted")
	}
}
