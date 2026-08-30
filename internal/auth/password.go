package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime                  = 3
	argonMemory                = 64 * 1024
	argonThreads               = 2
	argonKeyLen                = 32
	MaxPasswordBytes           = 1024
	maxEncodedPasswordHashSize = 512
	minArgonMemory             = 8 * 1024
	maxArgonMemory             = 256 * 1024
	maxArgonTime               = 10
	maxArgonThreads            = 16
	minArgonSaltLen            = 16
	maxArgonSaltLen            = 64
	minArgonKeyLen             = 16
	maxArgonKeyLen             = 64
)

func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must contain at least 12 characters")
	}
	if len(password) > MaxPasswordBytes {
		return "", fmt.Errorf("password must not exceed %d bytes", MaxPasswordBytes)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyPassword(encoded, password string) bool {
	if len(password) > MaxPasswordBytes || len(encoded) > maxEncodedPasswordHashSize {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var memory uint32
	var iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	if fmt.Sprintf("m=%d,t=%d,p=%d", memory, iterations, threads) != parts[3] || memory < minArgonMemory || memory > maxArgonMemory || iterations < 1 || iterations > maxArgonTime || threads < 1 || threads > maxArgonThreads {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minArgonSaltLen || len(salt) > maxArgonSaltLen {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < minArgonKeyLen || len(want) > maxArgonKeyLen {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
