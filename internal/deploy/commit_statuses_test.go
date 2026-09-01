package deploy

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/GhaziBenDahmane/Orka/internal/store"
)

func TestCommitStatusRequests(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	tests := []struct {
		name, provider, repository, server, username, wantURL, wantAuth, wantState string
	}{
		{"github", "github", "https://github.com/acme/widget.git", "github.com", "bot", "https://api.github.com/repos/acme/widget/statuses/" + sha, "Bearer token", `"state":"success"`},
		{"gitea", "gitea", "ssh://git@git.example.test/acme/widget.git", "git.example.test", "git", "https://git.example.test/api/v1/repos/acme/widget/statuses/" + sha, "token token", `"state":"success"`},
		{"gitlab", "gitlab", "https://gitlab.example.test/platform/group/widget.git", "gitlab.example.test", "bot", "https://gitlab.example.test/api/v4/projects/platform%2Fgroup%2Fwidget/statuses/" + sha, "token", "state=success"},
		{"bitbucket", "bitbucket", "https://bitbucket.org/acme/widget.git", "bitbucket.org", "bot", "https://api.bitbucket.org/2.0/repositories/acme/widget/commit/" + sha + "/statuses/build", "Basic ", `"state":"SUCCESSFUL"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			delivery := store.CommitStatusDelivery{Provider: test.provider, RepositoryURL: test.repository, CredentialServer: test.server, CredentialUsername: test.username, CommitSHA: sha, Context: "dockyard/deploy", State: "success"}
			req, err := commitStatusRequest(context.Background(), delivery, "token")
			if err != nil {
				t.Fatal(err)
			}
			if req.URL.String() != test.wantURL {
				t.Fatalf("URL = %q, want %q", req.URL.String(), test.wantURL)
			}
			auth := req.Header.Get("Authorization")
			if test.provider == "gitlab" {
				auth = req.Header.Get("PRIVATE-TOKEN")
			}
			if !strings.HasPrefix(auth, test.wantAuth) {
				t.Fatalf("authorization = %q", auth)
			}
			body, _ := io.ReadAll(req.Body)
			if !strings.Contains(string(body), test.wantState) {
				t.Fatalf("body = %s", body)
			}
			if test.provider == "gitlab" {
				if _, err = url.ParseQuery(string(body)); err != nil {
					t.Fatal(err)
				}
			} else if !json.Valid(body) {
				t.Fatalf("body is not JSON: %s", body)
			}
		})
	}
}

func TestCommitStatusRejectsCredentialExfiltration(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	_, err := commitStatusRequest(context.Background(), store.CommitStatusDelivery{Provider: "gitea", RepositoryURL: "https://victim.example/acme/widget.git", CredentialServer: "attacker.example", CommitSHA: sha, Context: "dockyard/deploy", State: "pending"}, "secret")
	if err == nil {
		t.Fatal("mismatched credential and repository hosts were accepted")
	}
}

func TestCommitStatusRejectsUnsafeProviderInputs(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	base := store.CommitStatusDelivery{Provider: "gitea", RepositoryURL: "https://git.example.test/acme/widget.git", CredentialServer: "git.example.test", CredentialUsername: "bot", CommitSHA: sha, Context: "dockyard/deploy", State: "pending"}
	tests := []struct {
		name   string
		mutate func(*store.CommitStatusDelivery) string
	}{
		{"repository whitespace", func(value *store.CommitStatusDelivery) string {
			value.RepositoryURL = " " + value.RepositoryURL
			return "secret"
		}},
		{"repository malformed host", func(value *store.CommitStatusDelivery) string {
			value.RepositoryURL = "https://bad_label.example.test/acme/widget.git"
			value.CredentialServer = "bad_label.example.test"
			return "secret"
		}},
		{"repository invalid port", func(value *store.CommitStatusDelivery) string {
			value.RepositoryURL = "https://git.example.test:65536/acme/widget.git"
			return "secret"
		}},
		{"repository SSH password", func(value *store.CommitStatusDelivery) string {
			value.RepositoryURL = "ssh://git:password@git.example.test/acme/widget.git"
			return "secret"
		}},
		{"empty path segment", func(value *store.CommitStatusDelivery) string {
			value.RepositoryURL = "https://git.example.test/acme//widget.git"
			return "secret"
		}},
		{"server path injection", func(value *store.CommitStatusDelivery) string {
			value.CredentialServer = "git.example.test/attacker"
			return "secret"
		}},
		{"server credentials", func(value *store.CommitStatusDelivery) string {
			value.CredentialServer = "user@git.example.test"
			return "secret"
		}},
		{"server dangling port", func(value *store.CommitStatusDelivery) string {
			value.CredentialServer = "git.example.test:"
			return "secret"
		}},
		{"unknown state", func(value *store.CommitStatusDelivery) string { value.State = "successful"; return "secret" }},
		{"invalid context", func(value *store.CommitStatusDelivery) string { value.Context = "deploy status"; return "secret" }},
		{"oversized token", func(*store.CommitStatusDelivery) string { return strings.Repeat("t", maxCommitStatusTokenBytes+1) }},
		{"newline token", func(*store.CommitStatusDelivery) string { return "secret\nheader" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			delivery := base
			token := test.mutate(&delivery)
			if _, err := commitStatusRequest(context.Background(), delivery, token); err == nil {
				t.Fatal("unsafe commit-status input was accepted")
			}
		})
	}
}

func TestCommitStatusSupportsValidatedSelfHostedPort(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	delivery := store.CommitStatusDelivery{Provider: "gitea", RepositoryURL: "ssh://git@git.example.test:2222/acme/widget.git", CredentialServer: "git.example.test:8443", CredentialUsername: "git", CommitSHA: sha, Context: "dockyard/deploy", State: "success"}
	req, err := commitStatusRequest(context.Background(), delivery, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.String() != "https://git.example.test:8443/api/v1/repos/acme/widget/statuses/"+sha {
		t.Fatalf("request URL = %v", req.URL)
	}
}
