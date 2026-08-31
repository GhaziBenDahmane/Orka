package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("a-secure-password")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "a-secure-password") {
		t.Fatal("password should verify")
	}
	if VerifyPassword(hash, "incorrect-password") {
		t.Fatal("incorrect password verified")
	}
}

func TestVerifyPasswordOrDummyNeverAuthenticatesMissingAccount(t *testing.T) {
	for _, password := range []string{"", "wrong-password", strings.Repeat("x", MaxPasswordBytes)} {
		if VerifyPasswordOrDummy("", password) {
			t.Fatalf("missing account authenticated with password length %d", len(password))
		}
	}
	hash, err := HashPassword("a-secure-password")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPasswordOrDummy(hash, "a-secure-password") || VerifyPasswordOrDummy(hash, "wrong-password") {
		t.Fatal("real account verification semantics changed")
	}
}

func TestPasswordLengthIsBounded(t *testing.T) {
	if _, err := HashPassword(strings.Repeat("a", MaxPasswordBytes)); err != nil {
		t.Fatalf("maximum-length password rejected: %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", MaxPasswordBytes+1)); err == nil {
		t.Fatal("oversized password accepted")
	}
	hash, err := HashPassword("a-secure-password")
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPassword(hash, strings.Repeat("a", MaxPasswordBytes+1)) {
		t.Fatal("oversized password verified")
	}
}

func TestVerifyPasswordRejectsUnsafeArgonParameters(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	for _, parameters := range []string{
		"m=1048576,t=3,p=2",
		"m=65536,t=100,p=2",
		"m=65536,t=3,p=255",
		"m=65536,t=3,p=0",
		"m=65536,t=3,p=2,trailing=true",
	} {
		encoded := fmt.Sprintf("$argon2id$v=19$%s$%s$%s", parameters, salt, key)
		if VerifyPassword(encoded, "a-secure-password") {
			t.Fatalf("unsafe parameters %q were accepted", parameters)
		}
	}
}

func TestVerifyPasswordRejectsUnsafeEncodedSizes(t *testing.T) {
	validParameters := "m=65536,t=3,p=2"
	shortSalt := base64.RawStdEncoding.EncodeToString(make([]byte, minArgonSaltLen-1))
	longKey := base64.RawStdEncoding.EncodeToString(make([]byte, maxArgonKeyLen+1))
	validSalt := base64.RawStdEncoding.EncodeToString(make([]byte, minArgonSaltLen))
	validKey := base64.RawStdEncoding.EncodeToString(make([]byte, argonKeyLen))
	for _, encoded := range []string{
		fmt.Sprintf("$argon2id$v=19$%s$%s$%s", validParameters, shortSalt, validKey),
		fmt.Sprintf("$argon2id$v=19$%s$%s$%s", validParameters, validSalt, longKey),
		strings.Repeat("a", maxEncodedPasswordHashSize+1),
	} {
		if VerifyPassword(encoded, "a-secure-password") {
			t.Fatal("unsafe encoded password hash was accepted")
		}
	}
}
