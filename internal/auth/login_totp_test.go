package auth

import (
	"encoding/hex"
	"testing"
	"time"
)

// RFC 4226 Appendix D HOTP vectors. The secret is the ASCII string
// "12345678901234567890" — its base32 form is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
var rfc4226 = []struct {
	counter uint64
	expect  string
}{
	{0, "755224"},
	{1, "287082"},
	{2, "359152"},
	{3, "969429"},
	{4, "338314"},
	{5, "254676"},
	{6, "287922"},
	{7, "162583"},
	{8, "399871"},
	{9, "520489"},
}

func TestGenerateHOTPMatchesRFC4226(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tc := range rfc4226 {
		got := generateHOTP(secret, tc.counter, 6)
		if got != tc.expect {
			t.Errorf("counter=%d got=%s want=%s", tc.counter, got, tc.expect)
		}
	}
}

func TestValidateTOTPCodeAcceptsCurrentStep(t *testing.T) {
	// We can't pin the wall clock without time mocking, so we ask the validator
	// to verify the code we just generated for the current step.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Now().UTC().Unix() / 30
	rawSecret, err := decodeBase32Secret(secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	code := generateHOTP(rawSecret, uint64(now), 6)
	if err := ValidateTOTPCode(secret, code); err != nil {
		t.Fatalf("current code rejected: %v", err)
	}
}

func TestValidateTOTPCodeTolerance(t *testing.T) {
	// Verify ±1 step tolerance: a code from the previous step must still pass.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	prevStep := uint64(time.Now().UTC().Unix()/30 - 1)
	rawSecret, _ := decodeBase32Secret(secret)
	code := generateHOTP(rawSecret, prevStep, 6)
	if err := ValidateTOTPCode(secret, code); err != nil {
		t.Errorf("prev-step code rejected: %v", err)
	}
}

func TestValidateTOTPCodeRejectsGarbage(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if err := ValidateTOTPCode(secret, "000000"); err == nil {
		t.Error("expected error for all-zero code")
	}
	if err := ValidateTOTPCode(secret, ""); err == nil {
		t.Error("expected error for empty code")
	}
}

func TestDeriveLoginTOTPKeyDeterministic(t *testing.T) {
	authKey, _ := hex.DecodeString(
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	)
	k1, err := DeriveLoginTOTPKey(authKey)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	defer k1.Destroy()
	k2, err := DeriveLoginTOTPKey(authKey)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	defer k2.Destroy()

	if string(k1.Bytes()) != string(k2.Bytes()) {
		t.Error("HKDF over same auth_key must produce identical keys")
	}
	if len(k1.Bytes()) != 32 {
		t.Errorf("login-totp key length %d, want 32", len(k1.Bytes()))
	}
}

func TestDeriveLoginTOTPKeyRejectsEmpty(t *testing.T) {
	if _, err := DeriveLoginTOTPKey(nil); err == nil {
		t.Error("expected error for empty auth_key")
	}
}
