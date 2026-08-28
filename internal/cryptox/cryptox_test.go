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
