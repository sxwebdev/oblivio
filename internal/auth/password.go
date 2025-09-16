package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// HashPassword returns a PHC-style encoded argon2id hash string.
// Format: $argon2id$v=19$m=65536,t=2,p=1$<b64(salt)>$<b64(hash)>
func HashPassword(password string) (string, error) {
	// Params
	var (
		memory  uint32 = 64 * 1024 // 64 MB
		time    uint32 = 2
		threads uint8  = 1
		saltLen        = 16
		keyLen         = 32
	)
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(keyLen))
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, time, threads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

// VerifyPassword checks a password against an encoded argon2id hash
func VerifyPassword(password string, encoded string) (bool, error) {
	// parse encoded
	var alg string
	var v int
	var memory, time uint32
	var threads uint8
	var saltB64, hashB64 string
	if _, err := fmt.Sscanf(encoded, "$%3s$v=%d$m=%d,t=%d,p=%d$%s$%s", &alg, &v, &memory, &time, &threads, &saltB64, &hashB64); err != nil {
		return false, err
	}
	if alg != "argon2id" || v != 19 {
		return false, errors.New("unsupported hash format")
	}
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false, err
	}
	expected, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		return false, err
	}
	dk := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expected)))
	if subtle.ConstantTimeCompare(dk, expected) == 1 {
		return true, nil
	}
	return false, nil
}
