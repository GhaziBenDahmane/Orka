package main

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPlatformHTTPServerUsesBoundedTransportSettings(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := newPlatformHTTPServer(":8080", handler, 35*time.Second)
	if server.Handler == nil || server.ReadHeaderTimeout != 10*time.Second || server.ReadTimeout != 35*time.Second || server.WriteTimeout != 35*time.Second || server.IdleTimeout != 2*time.Minute || server.MaxHeaderBytes != 64<<10 {
		t.Fatalf("unsafe HTTP server settings: %+v", server)
	}
}

func TestServerClusterValues(t *testing.T) {
	clusterID := uuid.New()
	values := serverClusterValues{}
	if err := values.Set(" source-server = " + clusterID.String()); err != nil || values["source-server"] != clusterID {
		t.Fatalf("mapping=%#v err=%v", values, err)
	}
	if err := values.Set("source-server=" + clusterID.String()); err != nil {
		t.Fatalf("idempotent mapping failed: %v", err)
	}
	for _, value := range []string{"", "missing-separator", "source=not-a-uuid", "source=00000000-0000-0000-0000-000000000000", "source-server=" + uuid.NewString()} {
		if err := values.Set(value); err == nil {
			t.Errorf("invalid mapping %q was accepted", value)
		}
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

func TestValidateEdgeSubnetCommand(t *testing.T) {
	for _, cidr := range []string{"10.255.250.0/24", "172.20.0.0/16", "192.168.42.0/28"} {
		if err := validateEdgeSubnet([]string{"--cidr", cidr}); err != nil {
			t.Errorf("CIDR %q rejected: %v", cidr, err)
		}
	}
	for _, arguments := range [][]string{
		nil,
		{"--cidr", "0.0.0.0/0"},
		{"--cidr", "10.0.0.0/8"},
		{"--cidr", "10.20.0.1/24"},
		{"--cidr", "192.0.2.0/24"},
		{"--cidr", "fd00::/64"},
		{"--cidr", "192.168.42.0/29"},
		{"--cidr", "10.20.0.0/24", "unexpected"},
	} {
		if err := validateEdgeSubnet(arguments); err == nil {
			t.Errorf("arguments %q were accepted", arguments)
		}
	}
}

func TestValidateDatabaseURLCommand(t *testing.T) {
	if err := validateDatabaseURL(nil, strings.NewReader("postgres://dockyard:secret@postgres:5432/dockyard?sslmode=disable\n")); err != nil {
		t.Fatal(err)
	}
	if err := validateDatabaseURL([]string{"--require-tls"}, strings.NewReader("postgres://dockyard@example.test/dockyard?sslmode=verify-full")); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		arguments []string
		input     string
	}{
		{input: "not-a-url"},
		{arguments: []string{"--require-tls"}, input: "postgres://dockyard@example.test/dockyard?sslmode=disable"},
		{arguments: []string{"unexpected"}, input: "postgres://dockyard@example.test/dockyard"},
		{input: strings.Repeat("x", 65537)},
	} {
		if err := validateDatabaseURL(test.arguments, strings.NewReader(test.input)); err == nil {
			t.Errorf("arguments=%q input length=%d were accepted", test.arguments, len(test.input))
		}
	}
}

func TestValidateBundledDatabaseCredentialsCommand(t *testing.T) {
	valid := "correct horse battery staple\x00postgres://dockyard:correct%20horse%20battery%20staple@postgres:5432/dockyard?sslmode=disable"
	if err := validateBundledDatabaseCredentials(nil, strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		arguments []string
		input     string
	}{
		{arguments: []string{"unexpected"}, input: valid},
		{input: "missing separator"},
		{input: valid + "\x00extra"},
		{input: "wrong password value\x00postgres://dockyard:correct%20horse%20battery%20staple@postgres:5432/dockyard?sslmode=disable"},
		{input: strings.Repeat("x", 69634)},
	} {
		if err := validateBundledDatabaseCredentials(test.arguments, strings.NewReader(test.input)); err == nil {
			t.Errorf("arguments=%q input length=%d were accepted", test.arguments, len(test.input))
		}
	}
}

func TestValidateAgentEndpointsCommand(t *testing.T) {
	valid := []string{
		"--control-plane-url", "https://dockyard.example.test",
		"--agent-url", "https://agents.example.test:8444",
	}
	if err := validateAgentEndpoints(valid); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"--control-plane-url", "http://dockyard.example.test", "--agent-url", "https://agents.example.test"},
		{"--control-plane-url", "https://dockyard.example.test", "--agent-url", "https://agents.example.test/mtls"},
		{"--control-plane-url", "https://dockyard.example.test"},
		append(append([]string{}, valid...), "unexpected"),
	} {
		if err := validateAgentEndpoints(arguments); err == nil {
			t.Errorf("arguments %q were accepted", arguments)
		}
	}
}

func TestValidateAIAuditorConfig(t *testing.T) {
	valid := []string{"--control-plane-url", "https://dockyard.example.test", "--model-url", "http://9router:20128/v1", "--model", "provider/model"}
	if err := validateAIAuditorConfig(valid); err != nil {
		t.Fatalf("valid AI auditor config: %v", err)
	}
	for _, arguments := range [][]string{
		{"--control-plane-url", "http://dockyard.example.test", "--model-url", "http://9router:20128/v1", "--model", "provider/model"},
		{"--control-plane-url", "https://dockyard.example.test/path", "--model-url", "http://9router:20128/v1", "--model", "provider/model"},
		{"--control-plane-url", "https://dockyard.example.test", "--model-url", "http://public.example.test/v1", "--model", "provider/model"},
		{"--control-plane-url", "https://dockyard.example.test", "--model-url", "http://9router:20128/v1", "--model", ""},
		{"--control-plane-url", "https://dockyard.example.test", "--model-url", "http://9router:20128/v1", "--model", "bad\nmodel"},
	} {
		if err := validateAIAuditorConfig(arguments); err == nil {
			t.Fatalf("accepted invalid AI auditor config %#v", arguments)
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
