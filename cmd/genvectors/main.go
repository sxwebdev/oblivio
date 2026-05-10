// genvectors emits testdata/crypto-vectors.json — the canonical set of
// cross-language test vectors consumed by both internal/crypto (Go) and
// frontend/packages/crypto (TS). The Go side here is authoritative: TS
// must reproduce every byte. See plan §13.2.
//
// Inputs are deterministic (fixed bytes, fixed counters) so two runs are
// byte-identical; the generator never reads OS entropy.
//
// Usage:
//
//	go run ./cmd/genvectors > testdata/crypto-vectors.json
//	# or
//	go run ./cmd/genvectors -o testdata/crypto-vectors.json
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA1.
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/text/unicode/norm"
)

// Domain-separation constants — mirror exactly the labels in
// frontend/packages/crypto/src/types.ts.
const (
	hkdfAuthInfo      = "oblivio/auth/v1"
	hkdfBlindInfo     = "oblivio/blind/v1"
	hkdfLoginTOTPInfo = "oblivio/login-totp/v1"
	vaultWrapAAD      = "vault-wrap"
	recoveryWrapAAD   = "recovery"
	verifierText      = "oblivio-verify"
)

type vectors struct {
	Argon2ID     []argon2Vector   `json:"argon2id"`
	HKDF         []hkdfVector     `json:"hkdf"`
	AESGCM       []aesGCMVector   `json:"aes_gcm"`
	Verifier     []verifierVector `json:"verifier"`
	BlindIndex   []blindVector    `json:"blind_index"`
	TOTPRFC6238  []totpVector     `json:"totp_rfc6238"`
	RecoveryWrap []recoveryVector `json:"recovery_wrap"`
	ItemWrap     []itemVector     `json:"item_wrap"`
}

type argon2Vector struct {
	Password string `json:"password"`
	SaltHex  string `json:"salt_hex"`
	T        uint32 `json:"t"`
	MKiB     uint32 `json:"m_kib"`
	P        uint8  `json:"p"`
	HashHex  string `json:"hash_hex"`
}

type hkdfVector struct {
	IKMHex string `json:"ikm_hex"`
	Info   string `json:"info"`
	Salt   string `json:"salt"`
	OutHex string `json:"out_hex"`
}

type aesGCMVector struct {
	KeyHex        string `json:"key_hex"`
	NonceHex      string `json:"nonce_hex"`
	AADHex        string `json:"aad_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	CiphertextHex string `json:"ciphertext_hex"` // includes 16-byte tag
}

type verifierVector struct {
	MasterKeyHex string `json:"master_key_hex"`
	NonceHex     string `json:"nonce_hex"` // fixed so output is deterministic
	VerifierHex  string `json:"verifier_hex"`
}

type blindVector struct {
	VaultKeyHex string `json:"vault_key_hex"`
	Title       string `json:"title"`
	HashHex     string `json:"hash_hex"`
}

type totpVector struct {
	SecretBase32 string `json:"secret_b32"`
	Unix         int64  `json:"unix"`
	Period       int64  `json:"period"`
	Digits       int    `json:"digits"`
	Code         string `json:"code"`
}

type recoveryVector struct {
	RecoveryCode string `json:"recovery_code"` // raw user input (with dashes)
	SaltHex      string `json:"salt_hex"`
	NonceHex     string `json:"nonce_hex"`
	VaultKeyHex  string `json:"vault_key_hex"`
	WrappedHex   string `json:"wrapped_hex"`
}

type itemVector struct {
	VaultKeyHex string `json:"vault_key_hex"`
	ItemKeyHex  string `json:"item_key_hex"`
	NonceHex    string `json:"nonce_hex"`
	VaultID     string `json:"vault_id"`
	ItemID      string `json:"item_id"`
	Version     int64  `json:"version"`
	WrappedHex  string `json:"wrapped_hex"`
}

func main() {
	out := flag.String("o", "", "output file (defaults to stdout)")
	flag.Parse()

	v, err := build()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := jsonEncoder(*out)
	if err := enc(v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func jsonEncoder(path string) func(any) error {
	if path == "" {
		return func(v any) error {
			e := json.NewEncoder(os.Stdout)
			e.SetIndent("", "  ")
			return e.Encode(v)
		}
	}
	return func(v any) error {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		e := json.NewEncoder(f)
		e.SetIndent("", "  ")
		return e.Encode(v)
	}
}

func build() (*vectors, error) {
	v := &vectors{}

	// Argon2id — three cases at low params so vitest can run them in
	// well under 30 s on a laptop. Vectors are short by design; correctness
	// (not stress) is the goal.
	for i, c := range []struct {
		password string
		saltSeed byte
		t        uint32
		m        uint32
		p        uint8
	}{
		{"hunter2", 0x01, 1, 1 << 10, 1},                      // 1 MiB
		{"correct-horse-battery-staple", 0x02, 2, 2 << 10, 1}, // 2 MiB
		{"пароль-юникод-✓", 0x03, 1, 1 << 10, 1},
	} {
		salt := fillBytes(16, c.saltSeed)
		hash := argon2.IDKey([]byte(c.password), salt, c.t, c.m, c.p, 32)
		v.Argon2ID = append(v.Argon2ID, argon2Vector{
			Password: c.password,
			SaltHex:  hex.EncodeToString(salt),
			T:        c.t, MKiB: c.m, P: c.p,
			HashHex: hex.EncodeToString(hash),
		})
		_ = i
	}

	// HKDF — three cases, each using a different info/salt pair.
	for _, c := range []struct {
		ikmSeed byte
		info    string
		salt    string
	}{
		{0x10, hkdfAuthInfo, "alice@example.com"},
		{0x11, hkdfBlindInfo, ""},
		{0x12, hkdfLoginTOTPInfo, ""},
	} {
		ikm := fillBytes(32, c.ikmSeed)
		out := hkdfDerive(ikm, []byte(c.info), []byte(c.salt), 32)
		v.HKDF = append(v.HKDF, hkdfVector{
			IKMHex: hex.EncodeToString(ikm),
			Info:   c.info,
			Salt:   c.salt,
			OutHex: hex.EncodeToString(out),
		})
	}

	// AES-256-GCM — three cases varying AAD shape.
	for _, c := range []struct {
		keySeed   byte
		nonceSeed byte
		aad       []byte
		pt        []byte
	}{
		{0x20, 0x21, []byte("vault-wrap"), []byte("hello world")},
		{0x22, 0x23, []byte{}, []byte("")}, // empty AAD, empty plaintext
		{0x24, 0x25, []byte("oblivio/login-totp/v1"), bytes32(0x26)},
	} {
		key := fillBytes(32, c.keySeed)
		nonce := fillBytes(12, c.nonceSeed)
		ct, err := aesGCMSeal(key, nonce, c.pt, c.aad)
		if err != nil {
			return nil, fmt.Errorf("aes-gcm: %w", err)
		}
		v.AESGCM = append(v.AESGCM, aesGCMVector{
			KeyHex:        hex.EncodeToString(key),
			NonceHex:      hex.EncodeToString(nonce),
			AADHex:        hex.EncodeToString(c.aad),
			PlaintextHex:  hex.EncodeToString(c.pt),
			CiphertextHex: hex.EncodeToString(ct),
		})
	}

	// Verifier — seal of constant sentinel under master_key with fixed
	// nonce so output is deterministic. Production code uses random nonces.
	for _, seed := range []byte{0x30, 0x31} {
		mk := fillBytes(32, seed)
		nonce := fillBytes(12, seed^0x80)
		ct, err := aesGCMSeal(mk, nonce, []byte(verifierText), []byte(vaultWrapAAD))
		if err != nil {
			return nil, fmt.Errorf("verifier seal: %w", err)
		}
		// Envelope = nonce || ct+tag.
		envelope := append(append([]byte{}, nonce...), ct...)
		v.Verifier = append(v.Verifier, verifierVector{
			MasterKeyHex: hex.EncodeToString(mk),
			NonceHex:     hex.EncodeToString(nonce),
			VerifierHex:  hex.EncodeToString(envelope),
		})
	}

	// Blind index over titles. Spec: HMAC-SHA256(K_blind, NFKC(lower(title)))
	// where K_blind = HKDF(vault_key, "oblivio/blind/v1", "").
	for _, c := range []struct {
		keySeed byte
		title   string
	}{
		{0x40, "GitHub"},
		{0x40, "github"}, // same vault_key, expect different normalized → same hash
		{0x40, "Café"},
		{0x41, "GitHub"}, // different vault_key → different hash
		{0x42, "ＧｉｔＨｕｂ"}, // NFKC fullwidth ASCII → "github"
	} {
		vaultKey := fillBytes(32, c.keySeed)
		hash := blindIndex(vaultKey, c.title)
		v.BlindIndex = append(v.BlindIndex, blindVector{
			VaultKeyHex: hex.EncodeToString(vaultKey),
			Title:       c.title,
			HashHex:     hex.EncodeToString(hash),
		})
	}

	// TOTP — RFC 6238 reference vectors (Appendix B), SHA-1 only.
	rfcSecret := "12345678901234567890" // 20 ASCII bytes
	rfcB32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(rfcSecret))
	for _, c := range []struct {
		unix int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		v.TOTPRFC6238 = append(v.TOTPRFC6238, totpVector{
			SecretBase32: rfcB32,
			Unix:         c.unix,
			Period:       30,
			Digits:       8,
			Code:         c.code,
		})
	}
	// One 6-digit case derived live, so TS/Go both agree without an RFC reference.
	{
		secret := []byte("HelloHelloHelloHello")
		b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
		code := generateHOTP(secret, uint64(1700000000/30), 6)
		v.TOTPRFC6238 = append(v.TOTPRFC6238, totpVector{
			SecretBase32: b32,
			Unix:         1700000000,
			Period:       30,
			Digits:       6,
			Code:         code,
		})
	}

	// Recovery wrap: full round-trip envelope. Argon2id KDF with low params
	// for speed; AES-GCM seal with fixed nonce for determinism.
	for _, c := range []struct {
		code      string
		saltSeed  byte
		nonceSeed byte
		vaultSeed byte
	}{
		{"AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", 0x50, 0x51, 0x52},
		{"aaaaa bbbbb-ccccc DDDDD-eeeee", 0x53, 0x54, 0x55}, // tests normalize
	} {
		salt := fillBytes(16, c.saltSeed)
		nonce := fillBytes(12, c.nonceSeed)
		vault := fillBytes(32, c.vaultSeed)
		recoveryKey := argon2.IDKey([]byte(normalizeRecoveryCode(c.code)), salt, 1, 1<<10, 1, 32)
		ct, err := aesGCMSeal(recoveryKey, nonce, vault, []byte(recoveryWrapAAD))
		if err != nil {
			return nil, fmt.Errorf("recovery seal: %w", err)
		}
		envelope := append(append([]byte{}, nonce...), ct...)
		v.RecoveryWrap = append(v.RecoveryWrap, recoveryVector{
			RecoveryCode: c.code,
			SaltHex:      hex.EncodeToString(salt),
			NonceHex:     hex.EncodeToString(nonce),
			VaultKeyHex:  hex.EncodeToString(vault),
			WrappedHex:   hex.EncodeToString(envelope),
		})
	}

	// Item wrap: wrap item_key under vault_key with AAD bound to triple.
	for i, c := range []struct {
		vaultSeed byte
		itemSeed  byte
		nonceSeed byte
		vaultID   string
		itemID    string
		version   int64
	}{
		{0x60, 0x61, 0x62, "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000a01", 1},
		{0x60, 0x63, 0x64, "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000a02", 3},
	} {
		vault := fillBytes(32, c.vaultSeed)
		item := fillBytes(32, c.itemSeed)
		nonce := fillBytes(12, c.nonceSeed)
		aad := fmt.Sprintf("%s|%s|%d|wrap", c.vaultID, c.itemID, c.version)
		ct, err := aesGCMSeal(vault, nonce, item, []byte(aad))
		if err != nil {
			return nil, fmt.Errorf("item seal: %w", err)
		}
		envelope := append(append([]byte{}, nonce...), ct...)
		v.ItemWrap = append(v.ItemWrap, itemVector{
			VaultKeyHex: hex.EncodeToString(vault),
			ItemKeyHex:  hex.EncodeToString(item),
			NonceHex:    hex.EncodeToString(nonce),
			VaultID:     c.vaultID,
			ItemID:      c.itemID,
			Version:     c.version,
			WrappedHex:  hex.EncodeToString(envelope),
		})
		_ = i
	}

	return v, nil
}

// hkdfDerive matches frontend/packages/crypto/kdf.ts:hkdfSha256 — note that
// our WebCrypto wrapper passes salt as the salt argument to HKDF, which is
// the standard contract (not an inversion despite the slot name).
func hkdfDerive(ikm, info, salt []byte, length int) []byte {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

func aesGCMSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, plaintext, aad), nil
}

func blindIndex(vaultKey []byte, title string) []byte {
	k := hkdfDerive(vaultKey, []byte(hkdfBlindInfo), nil, 32)
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte(strings.ToLower(norm.NFKC.String(title))))
	return mac.Sum(nil)
}

func normalizeRecoveryCode(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' || c == ' ' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out = append(out, c)
	}
	return string(out)
}

func generateHOTP(secret []byte, counter uint64, digits int) string {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]&0xff) << 16) |
		(uint32(sum[off+2]&0xff) << 8) |
		uint32(sum[off+3]&0xff)
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	v %= mod
	return fmt.Sprintf("%0*d", digits, v)
}

// fillBytes returns n bytes filled with seed XOR i. Cheap, deterministic,
// and produces values that vary enough for unit tests.
func fillBytes(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	return out
}

func bytes32(seed byte) []byte { return fillBytes(32, seed) }
