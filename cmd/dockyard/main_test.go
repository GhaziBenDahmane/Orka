package main

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPlatformHTTPServerUsesBoundedTransportSettings(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := newPlatformHTTPServer(":8080", handler, 35*time.Second)
	if server.Handler == nil || server.ReadHeaderTimeout != 10*time.Second || server.ReadTimeout != 35*time.Second || server.WriteTimeout != 35*time.Second || server.IdleTimeout != 2*time.Minute || server.MaxHeaderBytes != 64<<10 {
		t.Fatalf("unsafe HTTP server settings: %+v", server)
	}
}

func TestValidateEgressPolicyCommand(t *testing.T) {
	if err := validateEgressPolicy([]string{"--cidrs", "10.40.0.0/16,fd00:40::/48"}); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{{"--cidrs", "not-a-cidr"}, {"--cidrs", "10.0.0.0/8,10.0.0.0/8"}, {"unexpected"}} {
		if err := validateEgressPolicy(arguments); err == nil {
			t.Errorf("arguments %q were accepted", arguments)
		}
	}
}

func TestReadRestrictedMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master-key")
	want := []byte(strings.Repeat("k", 32))
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(want)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readRestrictedMasterKey(path)
	if err != nil || string(got) != string(want) {
		t.Fatalf("key=%x err=%v", got, err)
	}
	clear(got)
}

func TestReadRestrictedMasterKeyRejectsUnsafeInput(t *testing.T) {
	directory := t.TempDir()
	valid := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	worldReadable := filepath.Join(directory, "world-readable")
	if err := os.WriteFile(worldReadable, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRestrictedMasterKey(worldReadable); err == nil || !strings.Contains(err.Error(), "no group or other permissions") {
		t.Fatalf("world-readable key error=%v", err)
	}
	invalid := filepath.Join(directory, "invalid")
	if err := os.WriteFile(invalid, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRestrictedMasterKey(invalid); err == nil || !strings.Contains(err.Error(), "base64-encoded 32-byte") {
		t.Fatalf("invalid key error=%v", err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(invalid, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRestrictedMasterKey(symlink); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink key error=%v", err)
	}
}
