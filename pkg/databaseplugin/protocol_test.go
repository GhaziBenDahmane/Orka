package databaseplugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
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

type panicDriver struct{}

func (panicDriver) Describe() Description                  { panic("unexpected Describe call") }
func (panicDriver) Render(RenderRequest) (Result, error)   { panic("unexpected Render call") }
func (panicDriver) Backup(UtilityRequest) (Plan, error)    { panic("unexpected Backup call") }
func (panicDriver) Restore(UtilityRequest) (Plan, error)   { panic("unexpected Restore call") }
func (panicDriver) Readiness(UtilityRequest) (Plan, error) { panic("unexpected Readiness call") }

func TestServeRejectsMalformedProtocolInput(t *testing.T) {
	tests := map[string]string{
		"unknown field":  `{"protocolVersion":1,"operation":"describe","unexpected":true}`,
		"trailing value": `{"protocolVersion":1,"operation":"describe"} {}`,
		"empty input":    ``,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if err := Serve(panicDriver{}, strings.NewReader(input), &bytes.Buffer{}); err == nil {
				t.Fatal("malformed protocol input was accepted")
			}
		})
	}

	oversized := bytes.Repeat([]byte("x"), MaxRequestBytes+1)
	if err := Serve(panicDriver{}, bytes.NewReader(oversized), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized request error=%v", err)
	}
}

func TestServeRejectsOperationConfusedRequests(t *testing.T) {
	tests := []Request{
		{ProtocolVersion: ProtocolVersion, Operation: "describe", Render: &RenderRequest{}},
		{ProtocolVersion: ProtocolVersion, Operation: "render", Render: &RenderRequest{}, Utility: &UtilityRequest{}},
		{ProtocolVersion: ProtocolVersion, Operation: "backup"},
		{ProtocolVersion: ProtocolVersion, Operation: "unknown"},
	}
	for _, request := range tests {
		input, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err = Serve(panicDriver{}, bytes.NewReader(input), &output); err != nil {
			t.Fatal(err)
		}
		var response Response
		if err = json.Unmarshal(output.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Error != "invalid request shape" || response.Description != nil || response.Result != nil || response.Plan != nil {
			t.Fatalf("confused request response=%#v", response)
		}
	}
}
