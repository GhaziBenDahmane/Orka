package netpolicy

import (
	"strings"
	"testing"
)

func TestValidateHTTPURL(t *testing.T) {
	for _, raw := range []string{
		"https://objects.example.test/archive?signature=value",
		"http://127.0.0.1:9000/archive",
		"https://[2001:db8::1]:9443/archive",
	} {
		if _, err := ValidateHTTPURL(raw, 4096); err != nil {
			t.Errorf("valid URL %q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"", " https://objects.example.test/archive", "ftp://objects.example.test/archive",
		"https://user@objects.example.test/archive", "https://bad_label.example.test/archive",
		"https://-bad.example.test/archive", "https://objects.example.test:/archive",
		"https://objects.example.test:0/archive", "https://objects.example.test:65536/archive",
		"https://[not-an-ip]/archive", "https://objects.example.test/archive#fragment",
		"https://objects.example.test/" + strings.Repeat("a", 4096),
	} {
		if _, err := ValidateHTTPURL(raw, 4096); err == nil {
			t.Errorf("unsafe URL %q was accepted", raw)
		}
	}
}
