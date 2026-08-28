package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/deploy"
)

type fakeScheduler struct {
	stack, compose string
	environment    map[string]string
	artifact       []byte
	wantArtifact   []byte
}

func (f *fakeScheduler) Deploy(_ context.Context, stack, compose string, environment map[string]string) (string, error) {
	f.stack, f.compose, f.environment = stack, compose, environment
	return "deployed", nil
}
func (*fakeScheduler) Remove(context.Context, string) (string, error)        { return "", nil }
func (*fakeScheduler) RemoveVolumes(context.Context, string) (string, error) { return "", nil }
func (*fakeScheduler) Logs(context.Context, string, int) (string, error)     { return "", nil }
func (*fakeScheduler) Nodes(context.Context) ([]deploy.Node, error)          { return nil, nil }
func (f *fakeScheduler) RunContainerJob(_ context.Context, _, _, mount string, _ map[string]string, command []string) (string, error) {
	if f.artifact != nil {
		return "dumped", os.WriteFile(filepath.Join(mount, command[len(command)-1]), f.artifact, 0600)
	}
	if f.wantArtifact != nil {
		actual, err := os.ReadFile(filepath.Join(mount, command[len(command)-1]))
		if err != nil {
			return "", err
		}
		if !bytes.Equal(actual, f.wantArtifact) {
			return "", errors.New("restored artifact mismatch")
		}
		return "restored", nil
	}
	return "", errors.New("unused")
}

func TestExecuteArtifactJobEncryptsUploadAndDecryptsDownload(t *testing.T) {
	plaintxt := []byte("remote database backup")
	var stored []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			stored, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write(stored)
	}))
	defer server.Close()
	key := bytes.Repeat([]byte{9}, 32)
	upload := deploy.RemoteArtifactJob{Mode: "upload", Network: "db_default", Image: "postgres", Command: []string{"pg_dump", "backup.dump"}, ArtifactName: "backup.dump", TransferURL: server.URL, EncryptionKey: base64.RawStdEncoding.EncodeToString(key), EncryptionAAD: "database-backup:test"}
	payload, _ := json.Marshal(upload)
	client := &Client{cfg: Config{StateDirectory: t.TempDir()}, swarm: &fakeScheduler{artifact: plaintxt}}
	encoded, err := client.executeCommand(context.Background(), command{Kind: "database.utility", Payload: payload})
	if err != nil || bytes.Contains(stored, plaintxt) {
		t.Fatalf("upload err=%v encrypted=%q", err, stored)
	}
	var result deploy.RemoteArtifactResult
	if err = json.Unmarshal([]byte(encoded), &result); err != nil || result.SHA256 == "" || result.PlaintextSHA256 == "" {
		t.Fatalf("result=%q err=%v", encoded, err)
	}

	download := upload
	download.Mode = "download"
	download.SHA256 = result.SHA256
	download.PlaintextSHA256 = result.PlaintextSHA256
	payload, _ = json.Marshal(download)
	client.swarm = &fakeScheduler{wantArtifact: plaintxt}
	if _, err = client.executeCommand(context.Background(), command{Kind: "database.utility", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	box, _ := cryptox.New(key)
	var decoded bytes.Buffer
	if err = box.DecryptStream(&decoded, bytes.NewReader(stored), upload.EncryptionAAD); err != nil || !bytes.Equal(decoded.Bytes(), plaintxt) {
		t.Fatalf("decrypt err=%v value=%q", err, decoded.Bytes())
	}
}

func TestExecuteDeployCommand(t *testing.T) {
	scheduler := &fakeScheduler{}
	client := &Client{swarm: scheduler}
	output, err := client.executeCommand(context.Background(), command{Kind: "swarm.deploy", Payload: []byte(`{"stackName":"demo","compose":"services: {}","environment":{"TOKEN":"secret"}}`)})
	if err != nil || output != "deployed" {
		t.Fatalf("output=%q err=%v", output, err)
	}
	if scheduler.stack != "demo" || scheduler.compose != "services: {}" || scheduler.environment["TOKEN"] != "secret" {
		t.Fatalf("unexpected dispatch: %#v", scheduler)
	}
}

func TestExecuteRejectsUnknownCommand(t *testing.T) {
	client := &Client{swarm: &fakeScheduler{}}
	if _, err := client.executeCommand(context.Background(), command{Kind: "shell.exec", Payload: []byte(`{}`)}); err == nil {
		t.Fatal("expected unknown command to be rejected")
	}
}

func TestExecuteAgentUpgradeRequiresDigestAndFixedService(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "args")
	dockerBin := filepath.Join(directory, "docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + logPath + "\n"
	if err := os.WriteFile(dockerBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	client := &Client{cfg: Config{DockerBin: dockerBin, ServiceName: "dockyard-agent_agent"}}
	image := "registry.example/dockyard@sha256:" + strings.Repeat("a", 64)
	payload, _ := json.Marshal(map[string]string{"image": image})
	if _, err := client.executeCommand(context.Background(), command{Kind: "agent.upgrade", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	arguments, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "service\nupdate\n--detach=true\n--update-order\nstart-first\n--with-registry-auth\n--image\n" + image + "\ndockyard-agent_agent\n"
	if string(arguments) != want {
		t.Fatalf("docker arguments=%q want=%q", arguments, want)
	}
	if _, err := client.executeCommand(context.Background(), command{Kind: "agent.upgrade", Payload: []byte(`{"image":"registry.example/dockyard:latest"}`)}); err == nil {
		t.Fatal("expected mutable agent image tag to be rejected")
	}
}
