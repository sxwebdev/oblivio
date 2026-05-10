package auth

import (
	"strings"
	"testing"
)

// fastParams keeps Argon2id cheap so unit tests don't spend seconds on KDFs.
// Production parameters live in the user_kdf_params table; the parser must
// handle either.
var fastParams = Argon2Params{T: 1, MKiB: 1 << 10, P: 1}

func TestHashAuthKey_RoundTrip(t *testing.T) {
	hash, err := HashAuthKey([]byte("k_auth"), fastParams)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyAuthKey([]byte("k_auth"), hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("verify should succeed for correct key")
	}
	bad, err := VerifyAuthKey([]byte("wrong"), hash)
	if err != nil {
		t.Fatal(err)
	}
	if bad {
		t.Fatal("verify should fail for wrong key")
	}
}

func TestHashAuthKey_EmptyInput(t *testing.T) {
	if _, err := HashAuthKey(nil, fastParams); err == nil {
		t.Fatal("expected error for empty auth key")
	}
}

func TestHashAuthKey_RandomSaltVariesOutput(t *testing.T) {
	a, err := HashAuthKey([]byte("k"), fastParams)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashAuthKey([]byte("k"), fastParams)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("salt should produce different hashes for identical input")
	}
}

func TestHashAuthKey_EncodesParams(t *testing.T) {
	p := Argon2Params{T: 3, MKiB: 65536, P: 2}
	hash, err := HashAuthKey([]byte("k"), p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("missing prefix: %q", hash)
	}
	if !strings.Contains(hash, "m=65536") || !strings.Contains(hash, "t=3") || !strings.Contains(hash, "p=2") {
		t.Fatalf("params not encoded: %q", hash)
	}
}

// parsePHC is the high-risk surface: malformed strings under attacker
// control must never accidentally validate. The table below covers each
// branch in the parser.
func TestParsePHC_Errors(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"wrong_parts", "$argon2id$v=19$"},
		{"bad_algo", "$argon2i$v=19$m=1024,t=1,p=1$AAAA$BBBB"},
		{"bad_version", "$argon2id$v=18$m=1024,t=1,p=1$AAAA$BBBB"},
		{"truncated_params", "$argon2id$v=19$m=1024,t=1$AAAA$BBBB"},
		{"non_kv_param", "$argon2id$v=19$m=1024,xxx,p=1$AAAA$BBBB"},
		{"non_numeric_param", "$argon2id$v=19$m=abc,t=1,p=1$AAAA$BBBB"},
		{"unknown_param", "$argon2id$v=19$z=1,t=1,p=1$AAAA$BBBB"},
		{"bad_salt_b64", "$argon2id$v=19$m=1024,t=1,p=1$!!!!$BBBB"},
		{"bad_hash_b64", "$argon2id$v=19$m=1024,t=1,p=1$QUFB$!!!!"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := VerifyAuthKey([]byte("k"), c.in); err == nil {
				t.Fatalf("expected parse error for %s", c.in)
			}
		})
	}
}

func TestVerifyAuthKey_CrossWithDifferentKey(t *testing.T) {
	// A hash for "k_one" must not validate "k_two" — independent of the
	// internal hash format. Belt-and-braces over TestHashAuthKey_RoundTrip
	// which uses the same params; this one varies inputs.
	hash, err := HashAuthKey([]byte("k_one"), fastParams)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyAuthKey([]byte("k_two"), hash)
	if err != nil {
		t.Fatalf("Verify with wrong key returned error: %v", err)
	}
	if ok {
		t.Fatal("wrong key unexpectedly verified")
	}
}
