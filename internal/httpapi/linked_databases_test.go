package httpapi

import (
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/database"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestPrepareLinkedPasswordOnlyDatabases(t *testing.T) {
	server := &Server{Databases: database.NewRegistry()}
	service := store.ComposeService{ComposeYAML: "services:\n  db:\n    image: example/database:1\n"}
	for _, engine := range []string{"redis", "valkey", "qdrant", "meilisearch"} {
		t.Run(engine, func(t *testing.T) {
			item, credentials, err := server.prepareLinkedDatabase(service, uuid.New(), linkedDatabaseInput{
				Name: "Application data", Engine: engine, ConnectionServiceName: "db", Password: "secret",
			})
			if err != nil {
				t.Fatal(err)
			}
			if item.Engine != engine || item.ManagementKind != "compose" || credentials["password"] != "secret" {
				t.Fatalf("linked database=%#v credentials=%#v", item, credentials)
			}
			if credentials["database"] != "" || credentials["username"] != "" {
				t.Fatalf("password-only engine gained identity credentials: %#v", credentials)
			}
		})
	}
}
