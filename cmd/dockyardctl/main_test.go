package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestCommandRequestMappings(t *testing.T) {
	tests := []struct {
		args   []string
		method string
		path   string
	}{
		{[]string{"projects"}, http.MethodGet, "/v1/projects"},
		{[]string{"environments", "project-id"}, http.MethodGet, "/v1/projects/project-id/environments"},
		{[]string{"deploy", "service-id"}, http.MethodPost, "/v1/services/service-id/deployments"},
		{[]string{"cluster-token", "cluster-id"}, http.MethodPost, "/v1/clusters/cluster-id/enrollment-tokens"},
		{[]string{"request", "delete", "/v1/services/id"}, http.MethodDelete, "/v1/services/id"},
	}
	for _, test := range tests {
		method, path, _, err := commandRequest(test.args, strings.NewReader(""))
		if err != nil || method != test.method || path != test.path {
			t.Fatalf("args=%v method=%q path=%q err=%v", test.args, method, path, err)
		}
	}
}

func TestJSONFromStdin(t *testing.T) {
	method, path, input, err := commandRequest([]string{"create-service", "environment-id", "-"}, strings.NewReader(`{"name":"demo"}`))
	if err != nil || method != http.MethodPost || path != "/v1/environments/environment-id/services" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	value := input.(map[string]any)
	if value["name"] != "demo" {
		t.Fatalf("input=%#v", input)
	}
}
