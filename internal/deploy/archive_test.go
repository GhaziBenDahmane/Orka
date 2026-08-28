package deploy

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func zipFixture(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for name, body := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestExtractArchiveStripsSingleRoot(t *testing.T) {
	data := zipFixture(t, map[string]string{"release/Dockerfile": "FROM scratch", "release/app/config.txt": "ok"})
	destination := t.TempDir()
	if err := ValidateArchive(data); err != nil {
		t.Fatal(err)
	}
	if err := ExtractArchive(data, destination); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "Dockerfile"))
	if err != nil || string(content) != "FROM scratch" {
		t.Fatalf("unexpected extraction: %q, %v", content, err)
	}
	if _, err = os.Stat(filepath.Join(destination, "release")); !os.IsNotExist(err) {
		t.Fatalf("wrapping directory was not removed: %v", err)
	}
}

func TestValidateArchiveRejectsUnsafeEntries(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", `windows\\escape`, "a/../escape"} {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			if err := ValidateArchive(zipFixture(t, map[string]string{name: "bad"})); err == nil {
				t.Fatal("expected unsafe path rejection")
			}
		})
	}
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	header := &zip.FileHeader{Name: "link"}
	header.SetMode(os.ModeSymlink | 0o777)
	entry, _ := writer.CreateHeader(header)
	_, _ = entry.Write([]byte("../escape"))
	_ = writer.Close()
	if err := ValidateArchive(data.Bytes()); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestValidateArchiveRejectsConflictingPaths(t *testing.T) {
	data := zipFixture(t, map[string]string{"folder/child": "one", "folder": "two"})
	if err := ValidateArchive(data); err == nil {
		t.Fatal("expected file and child conflict rejection")
	}
}

func TestValidateArchiveRejectsDuplicatePaths(t *testing.T) {
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for range 2 {
		entry, err := writer.Create("duplicate.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = entry.Write([]byte("same")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateArchive(data.Bytes()); err == nil {
		t.Fatal("expected duplicate path rejection")
	}
}

func TestBuildArchiveUsesExtractedWorkspace(t *testing.T) {
	directory := t.TempDir()
	dockerPath := filepath.Join(directory, "docker")
	logPath := filepath.Join(directory, "result")
	t.Setenv("DOCKYARD_BUILD_TEST_LOG", logPath)
	script := "#!/bin/sh\nfor value do last=$value; done\ntest -f \"$last/Dockerfile\"\nprintf '%s' \"$last\" >\"$DOCKYARD_BUILD_TEST_LOG\"\n"
	if err := os.WriteFile(dockerPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	source := store.ApplicationSource{ContextDirectory: ".", Dockerfile: "Dockerfile", BuildType: "dockerfile", RegistryImage: "registry.example.test/acme/drop"}
	tag, _, err := (Builder{DockerBin: dockerPath}).BuildArchive(context.Background(), source, uuid.MustParse("00000000-0000-0000-0000-000000000125"), Credential{}, zipFixture(t, map[string]string{"release/Dockerfile": "FROM scratch"}))
	if err != nil {
		t.Fatal(err)
	}
	if tag != "registry.example.test/acme/drop:00000000-0000-0000-0000-000000000125" {
		t.Fatalf("tag=%q", tag)
	}
	workspace, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(string(workspace)); !os.IsNotExist(err) {
		t.Fatalf("temporary workspace was not removed: %v", err)
	}
}
