package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	TOTPPeriod        = int64(30)
	TOTPSecretBytes   = 20
	RecoveryCodeCount = 10
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a 160-bit RFC 6238 secret in unpadded base32 form.
func NewTOTPSecret() (string, error) {
	secret := make([]byte, TOTPSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32NoPadding.EncodeToString(secret), nil
}

func TOTPURI(secret, issuer, account string) (string, error) {
	if _, err := decodeTOTPSecret(secret); err != nil {
		return "", err
	}
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	if issuer == "" || account == "" {
		return "", errors.New("TOTP issuer and account are required")
	}
	query := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + query.Encode(), nil
}

// VerifyTOTP accepts the current step and one step of clock skew in either
// direction. It returns the matched counter so the store can reject replay.
func VerifyTOTP(secret, code string, now time.Time) (int64, bool) {
	key, err := decodeTOTPSecret(secret)
	if err != nil || len(code) != 6 {
		return 0, false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	current := now.Unix() / TOTPPeriod
	for offset := int64(-1); offset <= 1; offset++ {
		counter := current + offset
		want := totpCode(key, counter)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
}

// TOTPCode returns the code for an exact time and is useful to authenticator
// clients and deterministic conformance tests.
func TOTPCode(secret string, at time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	return totpCode(key, at.Unix()/TOTPPeriod), nil
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	decoded, err := base32NoPadding.DecodeString(secret)
	if err != nil || len(decoded) != TOTPSecretBytes {
		return nil, errors.New("invalid TOTP secret")
	}
	return decoded, nil
}

func totpCode(key []byte, counter int64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(counter))
	digest := hmac.New(sha1.New, key)
	_, _ = digest.Write(message[:])
	sum := digest.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000)
}

func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		value := make([]byte, 10)
		if _, err := rand.Read(value); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		encoded := strings.ToLower(base32NoPadding.EncodeToString(value))
		codes[i] = encoded[:4] + "-" + encoded[4:8] + "-" + encoded[8:12] + "-" + encoded[12:]
	}
	return codes, nil
}

func NormalizeRecoveryCode(code string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}
