package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// GenerateTOTPSecret returns a base32 encoded secret (without padding)
func GenerateTOTPSecret() (string, error) {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
	return s, nil
}

// TOTPCode computes a 6-digit code for given secret at given time step
func TOTPCode(secret string, t time.Time, step int64) (string, error) {
	if step == 0 {
		step = 30
	}
	counter := uint64(t.Unix() / step)
	// decode base32
	sec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, sec)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	// dynamic truncation
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off])&0x7f)<<24 | (uint32(sum[off+1])&0xff)<<16 | (uint32(sum[off+2])&0xff)<<8 | (uint32(sum[off+3]) & 0xff)
	code = code % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// ValidateTOTP checks current +/-1 window
func ValidateTOTP(secret string, code string) bool {
	now := time.Now()
	for _, d := range []int64{-30, 0, 30} {
		c, err := TOTPCode(secret, now.Add(time.Duration(d)*time.Second), 30)
		if err == nil && c == code {
			return true
		}
	}
	return false
}

// BuildTOTPURI builds an otpauth URL for QR code
func BuildTOTPURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s:%s?%s", url.PathEscape(issuer), url.PathEscape(account), v.Encode())
}
