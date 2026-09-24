// Package mfa implements TOTP two-factor authentication: secret generation,
// QR provisioning URI, code validation and one-time recovery codes.
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP period & digits (RFC 6238 defaults).
const (
	period   = 30
	digits   = 6
	skew     = 1 // allow ±1 window
	algoName = "SHA1"
)

// GenerateSecret returns a new base32 TOTP secret (32 chars, 160 bits).
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToUpper(enc.EncodeToString(b)), nil
}

// ProvisioningURI builds an otpauth:// URI for authenticator apps.
func ProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(account)
	if issuer != "" {
		label = url.PathEscape(issuer) + ":" + label
	}
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", algoName)
	q.Set("digits", fmt.Sprintf("%d", digits))
	q.Set("period", fmt.Sprintf("%d", period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Verify checks a TOTP code within the allowed clock skew. Returns true on match.
func Verify(secret, code string) bool {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return false
	}
	code = strings.TrimSpace(code)
	now := time.Now().Unix()
	for i := -skew; i <= skew; i++ {
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(now+int64(i*period))/uint64(period))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// hotp computes a 6-digit HMAC-SHA1 OTP for the given counter.
func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	val := (uint32(sum[off])&0x7f)<<24 |
		uint32(sum[off+1])<<16 |
		uint32(sum[off+2])<<8 |
		uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, val%mod)
}

// GenerateRecoveryCodes returns n recovery codes (each "xxxx-xxxx-xxxx").
func GenerateRecoveryCodes(n int) ([]string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		// 每个字符独立取随机字节，避免复用导致的熵损失与模偏差。
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		var sb strings.Builder
		for j := 0; j < 12; j++ {
			if j == 4 || j == 8 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(b[j])%len(alphabet)])
		}
		out = append(out, sb.String())
	}
	return out, nil
}

// VerifyRecoveryCode checks and consumes a recovery code from the stored list.
// Returns the remaining codes.
func VerifyRecoveryCode(codes []string, input string) (bool, []string) {
	input = strings.ToUpper(strings.TrimSpace(input))
	for i, c := range codes {
		if subtle.ConstantTimeCompare([]byte(strings.ToUpper(strings.TrimSpace(c))), []byte(input)) == 1 {
			remaining := append([]string{}, codes[:i]...)
			remaining = append(remaining, codes[i+1:]...)
			return true, remaining
		}
	}
	return false, codes
}
