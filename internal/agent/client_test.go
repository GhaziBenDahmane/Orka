package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/bendahma/dokploy-go/internal/deploy"
)

type fakeScheduler struct {
	stack, compose string
	environment    map[string]string
}

func (f *fakeScheduler) Deploy(_ context.Context, stack, compose string, environment map[string]string) (string, error) {
	f.stack, f.compose, f.environment = stack, compose, environment
	return "deployed", nil
}
func (*fakeScheduler) Remove(context.Context, string) (string, error)    { return "", nil }
func (*fakeScheduler) Logs(context.Context, string, int) (string, error) { return "", nil }
func (*fakeScheduler) Nodes(context.Context) ([]deploy.Node, error)      { return nil, nil }
func (*fakeScheduler) RunContainerJob(context.Context, string, string, string, map[string]string, []string) (string, error) {
	return "", errors.New("unused")
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
