package auth

import "testing"

// FuzzParsePHC drives malformed PHC strings at VerifyAuthKey. The contract
// is binary: either return (false, nil) or (false, err) — *never* panic and
// *never* return (true, nil) for the wrong key.
//
// Seeds come from real PHC strings produced by HashAuthKey plus a small
// pool of pathological inputs. The fuzzer mutates them, so a single panic
// failure here counts as a CVE.
func FuzzParsePHC(f *testing.F) {
	// Seed: a known-good hash.
	good, err := HashAuthKey([]byte("seed"), Argon2Params{T: 1, MKiB: 1 << 10, P: 1})
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		good,
		"",
		"$argon2id$",
		"$argon2id$v=19$",
		"$argon2id$v=19$m=1024,t=1,p=1$$$",
		"$argon2id$v=19$m=0,t=0,p=0$AAAA$BBBB",
		"$argon2id$v=99$m=1024,t=1,p=1$AAAA$BBBB",
		"$argon2i$v=19$m=1024,t=1,p=1$AAAA$BBBB",
		"$argon2id$v=19$m=4294967295,t=4294967295,p=255$AAAA$BBBB",
		"$argon2id$v=19$m=1024,t=1,p=1$" + string([]byte{0xff, 0xfe}) + "$BBBB",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on %q: %v", s, r)
			}
		}()
		// We deliberately do not assert (true, nil) here. The fuzzer can
		// legitimately stumble onto re-hashes of "seed" via the seed pool,
		// and we don't want false positives. The contract under fuzz is
		// "never panic on attacker-controlled PHC".
		_, _ = VerifyAuthKey([]byte("seed"), s)
	})
}
