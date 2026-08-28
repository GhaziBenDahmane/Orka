package cryptox

import "testing"

func TestRoundTripAndContextBinding(t *testing.T) {
	box, err := New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.Encrypt([]byte("secret"), "one")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := box.Decrypt(ciphertext, "one")
	if err != nil || string(plain) != "secret" {
		t.Fatalf("round trip failed: %q %v", plain, err)
	}
	if _, err := box.Decrypt(ciphertext, "two"); err == nil {
		t.Fatal("ciphertext was not context-bound")
	}
}
