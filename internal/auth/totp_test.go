package auth

import (
	"testing"
	"time"
)

func TestVerifyTOTPRFC6238SHA1VectorAndSkew(t *testing.T) {
	// RFC 6238 SHA-1 seed "12345678901234567890".
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	at := time.Unix(59, 0)
	counter, ok := VerifyTOTP(secret, "287082", at)
	if !ok || counter != 1 {
		t.Fatalf("RFC vector rejected: counter=%d ok=%v", counter, ok)
	}
	if _, ok = VerifyTOTP(secret, "287082", at.Add(30*time.Second)); !ok {
		t.Fatal("one-step clock skew was rejected")
	}
	if _, ok = VerifyTOTP(secret, "287082", at.Add(60*time.Second)); ok {
		t.Fatal("two-step clock skew was accepted")
	}
	if _, ok = VerifyTOTP(secret, "28708x", at); ok {
		t.Fatal("non-numeric code was accepted")
	}
}

func TestTOTPEnrollmentMaterial(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil || len(secret) != 32 {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	uri, err := TOTPURI(secret, "Orka", "user@example.test")
	if err != nil || uri == "" {
		t.Fatalf("URI error: %v", err)
	}
	codes, err := NewRecoveryCodes()
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("codes=%d err=%v", len(codes), err)
	}
	seen := map[string]bool{}
	for _, code := range codes {
		normalized := NormalizeRecoveryCode(code)
		if len(normalized) != 16 || seen[normalized] {
			t.Fatalf("invalid or duplicate recovery code %q", code)
		}
		seen[normalized] = true
	}
}
