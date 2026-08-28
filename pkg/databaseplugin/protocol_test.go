package databaseplugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

type testDriver struct{}

func (testDriver) Describe() Description { return Description{Name: "example", DefaultVersion: "1"} }
func (testDriver) Render(request RenderRequest) (Result, error) {
	return Result{ComposeYAML: "services: {}", InternalURL: "example://" + request.Name, Version: request.Version}, nil
}
func (testDriver) Backup(UtilityRequest) (Plan, error)  { return Plan{}, errors.New("unsupported") }
func (testDriver) Restore(UtilityRequest) (Plan, error) { return Plan{}, errors.New("unsupported") }
func (testDriver) Readiness(UtilityRequest) (Plan, error) {
	return Plan{Image: "example:1", Command: []string{"check"}}, nil
}

func TestServeProtocol(t *testing.T) {
	for _, request := range []Request{
		{ProtocolVersion: ProtocolVersion, Operation: "describe"},
		{ProtocolVersion: ProtocolVersion, Operation: "render", Render: &RenderRequest{Name: "db", Version: "1"}},
		{ProtocolVersion: 99, Operation: "describe"},
	} {
		input, _ := json.Marshal(request)
		var output bytes.Buffer
		if err := Serve(testDriver{}, bytes.NewReader(input), &output); err != nil {
			t.Fatal(err)
		}
		var response Response
		if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.ProtocolVersion != ProtocolVersion {
			t.Fatalf("response=%s err=%v", output.String(), err)
		}
		if request.ProtocolVersion == 99 && response.Error == "" {
			t.Fatal("expected incompatible protocol to be rejected")
		}
	}
}
