package migrate

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
)

func TestDecryptDokploy(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := []byte("123456789012")
	sealed := aead.Seal(nil, nonce, []byte("A=one\nB='two words'"), nil)
	ciphertext, tag := sealed[:len(sealed)-aead.Overhead()], sealed[len(sealed)-aead.Overhead():]
	payload := append(append(append([]byte{}, nonce...), tag...), ciphertext...)
	encoded := "enc:v1:" + base64.StdEncoding.EncodeToString(payload)
	plain, err := decryptDokploy(encoded, [][]byte{key})
	if err != nil || plain != "A=one\nB='two words'" {
		t.Fatalf("plain = %q, err = %v", plain, err)
	}
	env := parseEnv(plain)
	if env["A"] != "one" || env["B"] != "two words" {
		t.Fatalf("unexpected environment: %#v", env)
	}
}

func TestParseDokployKeys(t *testing.T) {
	keys, err := ParseDokployKeys([]byte("3031323334353637383930313233343536373839303132333435363738393031\n"))
	if err != nil || len(keys) != 1 || len(keys[0]) != 32 {
		t.Fatalf("keys = %#v, err = %v", keys, err)
	}
	if _, err = ParseDokployKeys([]byte("not-a-key")); err == nil {
		t.Fatal("expected invalid key error")
	}
}

func TestMappedIDsAreStableAndTargetScoped(t *testing.T) {
	first := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.MustParse("00000000-0000-0000-0000-000000000001")}
	second := first
	second.TargetOrganizationID = uuid.MustParse("00000000-0000-0000-0000-000000000002")
	if mappedID(first, "compose", "abc") != mappedID(first, "compose", "abc") {
		t.Fatal("mapping is not deterministic")
	}
	if mappedID(first, "compose", "abc") == mappedID(second, "compose", "abc") {
		t.Fatal("mapping is not target scoped")
	}
}
