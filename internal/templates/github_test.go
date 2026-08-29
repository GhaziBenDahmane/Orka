package templates

import "testing"

func TestGitHubArchiveURL(t *testing.T) {
	got, err := GitHubArchiveURL("https://github.com/acme/catalog.git", "main")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://codeload.github.com/acme/catalog/tar.gz/main" {
		t.Fatalf("url=%q", got)
	}
	for _, invalid := range []string{"http://github.com/acme/catalog", "https://evil.test/acme/catalog", "https://github.com/acme/catalog/extra", "https://user@github.com/acme/catalog", "https://github.com/acme/catalog?x=1"} {
		if _, err := GitHubArchiveURL(invalid, "main"); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
}
