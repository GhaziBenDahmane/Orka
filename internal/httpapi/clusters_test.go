package httpapi

import (
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/deploy"
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
