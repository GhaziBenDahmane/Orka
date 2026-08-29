package cryptox

import (
	"bytes"
	"testing"
)

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

func TestResourceContextRejectsCiphertextTransplantAndReadsLegacy(t *testing.T) {
	box, err := New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := box.Encrypt([]byte("environment"), ResourceContext("compose-env", "service-a"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := box.DecryptResource(bound, "compose-env", "service-a", "compose-env")
	if err != nil || string(plain) != "environment" {
		t.Fatalf("bound resource decrypt = %q, %v", plain, err)
	}
	if _, err = box.DecryptResource(bound, "compose-env", "service-b", "compose-env"); err == nil {
		t.Fatal("resource-bound ciphertext was accepted for another service")
	}
	legacy, err := box.Encrypt([]byte("legacy"), "compose-env")
	if err != nil {
		t.Fatal(err)
	}
	plain, err = box.DecryptResource(legacy, "compose-env", "service-a", "compose-env")
	if err != nil || string(plain) != "legacy" {
		t.Fatalf("legacy decrypt = %q, %v", plain, err)
	}
}

func TestEncryptedStreamRoundTripAndTamperDetection(t *testing.T) {
	box, err := New(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte("stream-data-"), 12000)
	var ciphertext, decrypted bytes.Buffer
	if err = box.EncryptStream(&ciphertext, bytes.NewReader(plaintext), "backup:test"); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext.Bytes(), []byte("stream-data")) {
		t.Fatal("ciphertext contains plaintext")
	}
	if err = box.DecryptStream(&decrypted, bytes.NewReader(ciphertext.Bytes()), "backup:test"); err != nil || !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatalf("stream round trip failed: %v", err)
	}
	tampered := append([]byte{}, ciphertext.Bytes()...)
	tampered[len(tampered)/2] ^= 1
	if err = box.DecryptStream(&bytes.Buffer{}, bytes.NewReader(tampered), "backup:test"); err == nil {
		t.Fatal("tampered stream was accepted")
	}
	if err = box.DecryptStream(&bytes.Buffer{}, bytes.NewReader(ciphertext.Bytes()[:len(ciphertext.Bytes())-1]), "backup:test"); err == nil {
		t.Fatal("truncated stream was accepted")
	}
	if err = box.DecryptStream(&bytes.Buffer{}, bytes.NewReader(ciphertext.Bytes()), "backup:other"); err == nil {
		t.Fatal("stream context mismatch was accepted")
	}
}
