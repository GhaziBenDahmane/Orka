package deploy

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
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
	_, err := commitStatusRequest(context.Background(), store.CommitStatusDelivery{Provider: "gitea", RepositoryURL: "https://victim.example/acme/widget.git", CredentialServer: "attacker.example", CommitSHA: "abcdef012345", Context: "dockyard/deploy", State: "pending"}, "secret")
	if err == nil {
		t.Fatal("mismatched credential and repository hosts were accepted")
	}
}
