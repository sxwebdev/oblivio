package crypto

import (
	"crypto/rand"
	"testing"
)

// FuzzAESGCMOpen feeds random bytes at AESGCMOpen against a fixed key.
// Contract: never panic. Output may be an error (good) or a successful
// decryption — but only if the fuzzer accidentally produced a valid
// envelope, which is cryptographically negligible.
func FuzzAESGCMOpen(f *testing.F) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		f.Fatal(err)
	}
	// Seeds: a clean envelope plus a few short/garbled inputs.
	good, _ := AESGCMSeal(key, make([]byte, 12), []byte("seed"), []byte("aad"))
	for _, s := range [][]byte{
		good,
		nil,
		{},
		make([]byte, 10),                  // too short
		make([]byte, nonceSize+tagSize),   // nonce + empty cipher
		make([]byte, nonceSize+tagSize+1), // 1 byte of cipher
		append([]byte{}, append([]byte{0xff}, good[1:]...)...), // mutated
	} {
		f.Add(s, []byte("aad"))
	}
	f.Fuzz(func(t *testing.T, blob, aad []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on blob=%x aad=%q: %v", blob, aad, r)
			}
		}()
		_, _ = AESGCMOpen(key, blob, aad) // explicit ignore — we only care about no-panic
	})
}

// FuzzAESGCMSeal: invalid key/nonce lengths must error (not panic).
func FuzzAESGCMSeal(f *testing.F) {
	f.Add([]byte("short"), []byte("nonce-12byte"), []byte("plaintext"), []byte("aad"))
	f.Add(make([]byte, 32), make([]byte, 12), []byte("plaintext"), []byte("aad")) // valid
	f.Add(make([]byte, 33), make([]byte, 11), []byte(""), []byte(""))             // both wrong
	f.Fuzz(func(t *testing.T, key, nonce, pt, aad []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v", r)
			}
		}()
		_, _ = AESGCMSeal(key, nonce, pt, aad)
	})
}
