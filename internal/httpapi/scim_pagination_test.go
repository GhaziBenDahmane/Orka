package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSCIMPage(t *testing.T) {
	for _, test := range []struct {
		name                 string
		query                string
		wantStart, wantCount int
		wantError            bool
	}{
		{name: "defaults", wantStart: 1, wantCount: 100},
		{name: "bounded page", query: "?startIndex=201&count=25", wantStart: 201, wantCount: 25},
		{name: "count only", query: "?startIndex=1&count=0", wantStart: 1, wantCount: 0},
		{name: "zero start", query: "?startIndex=0", wantError: true},
		{name: "negative count", query: "?count=-1", wantError: true},
		{name: "oversized count", query: "?count=101", wantError: true},
		{name: "malformed", query: "?startIndex=first", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			start, count, err := scimPage(httptest.NewRequest("GET", "/scim/v2/Users"+test.query, nil))
			if (err != nil) != test.wantError {
				t.Fatalf("scimPage error=%v, wantError=%v", err, test.wantError)
			}
			if err == nil && (start != test.wantStart || count != test.wantCount) {
				t.Fatalf("scimPage=(%d,%d), want (%d,%d)", start, count, test.wantStart, test.wantCount)
			}
		})
	}
}

func TestSCIMJSONUsesSCIMMediaType(t *testing.T) {
	recorder := httptest.NewRecorder()
	scimError(recorder, http.StatusBadRequest, "invalid")
	if got := recorder.Header().Get("Content-Type"); got != "application/scim+json" {
		t.Fatalf("Content-Type=%q", got)
	}
	if !strings.Contains(recorder.Body.String(), `"detail":"invalid"`) {
		t.Fatalf("unexpected body %q", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status":"400"`) {
		t.Fatalf("SCIM error status is not encoded as a string: %q", recorder.Body.String())
	}
}

func TestDecodeSCIMAcceptsExtensionAttributes(t *testing.T) {
	var payload struct {
		UserName string `json:"userName"`
	}
	request := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(`{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:example:extension"],
		"userName":"user@example.test",
		"name":{"givenName":"Example","familyName":"User"},
		"emails":[{"value":"user@example.test","primary":true}],
		"urn:example:extension":{"department":"Engineering"}
	}`))
	request.Header.Set("Content-Type", "application/scim+json; charset=utf-8")
	recorder := httptest.NewRecorder()
	if !decodeSCIM(recorder, request, &payload) || payload.UserName != "user@example.test" {
		t.Fatalf("extension-bearing payload rejected: status=%d body=%q payload=%#v", recorder.Code, recorder.Body.String(), payload)
	}
}

func TestDecodeSCIMRejectsTrailingJSONWithSCIMError(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(`{} {}`))
	request.Header.Set("Content-Type", "application/scim+json")
	recorder := httptest.NewRecorder()
	if decodeSCIM(recorder, request, &map[string]any{}) {
		t.Fatal("multiple JSON values were accepted")
	}
	if recorder.Code != http.StatusBadRequest || recorder.Header().Get("Content-Type") != "application/scim+json" {
		t.Fatalf("status=%d Content-Type=%q body=%q", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response["status"] != "400" {
		t.Fatalf("invalid SCIM error response: %#v err=%v", response, err)
	}
}

func TestNormalizeSCIMUserPatchOperations(t *testing.T) {
	operations, err := normalizeSCIMUserPatchOperations([]scimUserPatchOperation{{
		Op: "Replace",
		Value: map[string]any{
			"active":      true,
			"displayName": "Example User",
			"externalId":  "directory-user",
			"userName":    "user@example.test",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"username", "displayname", "externalid", "active"}
	if len(operations) != len(wantPaths) {
		t.Fatalf("operation count=%d, want %d", len(operations), len(wantPaths))
	}
	for index, want := range wantPaths {
		if operations[index].Path != want {
			t.Errorf("operation %d path=%q, want %q", index, operations[index].Path, want)
		}
	}
	if _, err = normalizeSCIMUserPatchOperations([]scimUserPatchOperation{{Op: "add", Path: "active", Value: true}}); err == nil {
		t.Fatal("unsupported operation was accepted")
	}
	if _, err = normalizeSCIMUserPatchOperations([]scimUserPatchOperation{{Op: "replace", Value: map[string]any{"unknown": "value"}}}); err == nil {
		t.Fatal("unsupported pathless attribute was accepted")
	}
	tooManyUserOperations := make([]scimUserPatchOperation, scimMaxPatchOperations+1)
	for index := range tooManyUserOperations {
		tooManyUserOperations[index] = scimUserPatchOperation{Op: "replace", Path: "active", Value: true}
	}
	if _, err = normalizeSCIMUserPatchOperations(tooManyUserOperations); err == nil {
		t.Fatal("oversized user patch operation list was accepted")
	}
}

func TestDecodeSCIMMembersEnforcesBatchLimit(t *testing.T) {
	members := make([]scimMember, scimMaxGroupMembers+1)
	encoded, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeSCIMMembers(encoded); err == nil {
		t.Fatal("oversized SCIM member batch was accepted")
	}
}

func TestNormalizeSCIMGroupPatchOperationsExpandsPathlessReplace(t *testing.T) {
	operations, err := normalizeSCIMGroupPatchOperations([]scimGroupPatchOperation{{
		Op: "replace",
		Value: json.RawMessage(`{
			"members":[{"value":"00000000-0000-0000-0000-000000000001"}],
			"externalId":"directory-group",
			"displayName":"Platform",
			"role":"developer"
		}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"displayname", "externalid", "role", "members"}
	if len(operations) != len(wantPaths) {
		t.Fatalf("operation count=%d, want %d", len(operations), len(wantPaths))
	}
	for index, want := range wantPaths {
		if operations[index].Path != want || operations[index].Op != "replace" {
			t.Errorf("operation %d=%#v, want replace %s", index, operations[index], want)
		}
	}
	for name, input := range map[string][]scimGroupPatchOperation{
		"empty":        nil,
		"pathless add": {{Op: "add", Value: json.RawMessage(`{"members":[]}`)}},
		"unknown":      {{Op: "replace", Value: json.RawMessage(`{"unknown":true}`)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, normalizeErr := normalizeSCIMGroupPatchOperations(input); normalizeErr == nil {
				t.Fatal("invalid group patch was accepted")
			}
		})
	}
	tooManyGroupOperations := make([]scimGroupPatchOperation, scimMaxPatchOperations+1)
	for index := range tooManyGroupOperations {
		tooManyGroupOperations[index] = scimGroupPatchOperation{Op: "replace", Path: "displayName", Value: json.RawMessage(`"Platform"`)}
	}
	if _, err = normalizeSCIMGroupPatchOperations(tooManyGroupOperations); err == nil {
		t.Fatal("oversized group patch operation list was accepted")
	}
	expandedGroupOperations := make([]scimGroupPatchOperation, scimMaxPatchOperations/4+1)
	for index := range expandedGroupOperations {
		expandedGroupOperations[index] = scimGroupPatchOperation{Op: "replace", Value: json.RawMessage(`{"displayName":"Platform","externalId":"directory","role":"viewer","members":[]}`)}
	}
	if _, err = normalizeSCIMGroupPatchOperations(expandedGroupOperations); err == nil {
		t.Fatal("oversized expanded group patch operation list was accepted")
	}
}
