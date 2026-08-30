package ociref

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for raw, wantRegistry := range map[string]string{
		"postgres":                                      "docker.io",
		"library/postgres:17-alpine":                    "docker.io",
		"ghcr.io/acme/api:v1@" + digest:                 "ghcr.io",
		"localhost:5000/team/api@" + digest:             "localhost:5000",
		"[2001:db8::1]:5000/acme/api:release@" + digest: "[2001:db8::1]:5000",
	} {
		reference, err := Parse(raw)
		if err != nil || reference.Registry != wantRegistry {
			t.Errorf("Parse(%q) = %#v, %v; registry want %q", raw, reference, err, wantRegistry)
		}
	}
}

func TestParseRejectsMalformedReferences(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, raw := range []string{
		"", " postgres", "postgres ", "ghcr.io//app", "ghcr.io/acme/app/", "ghcr.io/Acme/app",
		"registry.example.test:0/acme/app", "registry.example.test:65536/acme/app", "bad_label.example.test/acme/app",
		"localhost:/app", "team/../app", "app:", "app:bad/tag", "app@sha512:" + strings.Repeat("a", 64),
		"app@" + digest + "@" + digest, "app@sha256:" + strings.Repeat("A", 64), strings.Repeat("a", maxRepositoryBytes+1),
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestRepositoryAndDigestClassification(t *testing.T) {
	digest := "sha256:" + strings.Repeat("b", 64)
	if _, err := ParseRepository("ghcr.io/acme/app"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"ghcr.io/acme/app:latest", "ghcr.io/acme/app@" + digest} {
		if _, err := ParseRepository(raw); err == nil {
			t.Errorf("ParseRepository(%q) unexpectedly succeeded", raw)
		}
	}
	if !IsDigestPinned("ghcr.io/acme/app:v1@"+digest) || IsDigestPinned("ghcr.io/acme/app:v1") || IsDigestPinned("bad path@"+digest) {
		t.Fatal("digest pin classification is incorrect")
	}
}

func TestNormalizeRegistryAuthority(t *testing.T) {
	for raw, want := range map[string]string{
		"registry.example.test":      "registry.example.test",
		"REGISTRY.EXAMPLE.TEST:5000": "registry.example.test:5000",
		"[2001:db8::1]:5000":         "[2001:db8::1]:5000",
	} {
		if got, err := NormalizeRegistryAuthority(raw); err != nil || got != want {
			t.Errorf("NormalizeRegistryAuthority(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", " registry.example.test", "https://registry.example.test", "user@registry.example.test", "registry.example.test/path", "registry.example.test?query", "registry.example.test:", "bad_label.example.test"} {
		if got, err := NormalizeRegistryAuthority(raw); err == nil {
			t.Errorf("NormalizeRegistryAuthority(%q) = %q; want error", raw, got)
		}
	}
}
