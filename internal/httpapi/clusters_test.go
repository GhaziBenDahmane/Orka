package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/deploy"
)

func TestAgentCommandResultLimitsMatchAgentOutputContract(t *testing.T) {
	if !validAgentCommandResult(strings.Repeat("o", deploy.MaxRemoteCommandOutputBytes), strings.Repeat("e", deploy.MaxRemoteCommandErrorBytes)) {
		t.Fatal("protocol-sized command result was rejected")
	}
	if validAgentCommandResult(strings.Repeat("o", deploy.MaxRemoteCommandOutputBytes+1), "") {
		t.Fatal("oversized command output was accepted")
	}
	if validAgentCommandResult("", strings.Repeat("e", deploy.MaxRemoteCommandErrorBytes+1)) {
		t.Fatal("oversized command error was accepted")
	}
}

func TestAgentCommandResultWorstCaseJSONFitsEndpointLimit(t *testing.T) {
	payload, err := json.Marshal(map[string]string{
		"output": strings.Repeat("\x00", deploy.MaxRemoteCommandOutputBytes),
		"error":  strings.Repeat("\x00", deploy.MaxRemoteCommandErrorBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= 3<<20 || len(payload) > deploy.MaxRemoteCommandRequestBytes {
		t.Fatalf("encoded command result size=%d is outside the protocol envelope", len(payload))
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/agent/commands/id/complete", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	var decoded struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if !decodeLimit(recorder, request, &decoded, deploy.MaxRemoteCommandRequestBytes) {
		t.Fatalf("protocol-sized result rejected: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !validAgentCommandResult(decoded.Output, decoded.Error) {
		t.Fatal("decoded command result violated field limits")
	}
}
