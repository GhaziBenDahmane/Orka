package auth

import "testing"

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
