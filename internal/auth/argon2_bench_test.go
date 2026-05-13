package auth

import "testing"

// BenchmarkHashAuthKey tracks the cost of a single login Argon2id pass
// across a couple of representative parameter sets. Production picks one
// per user (typically 3/128 MiB / 4 threads); the slim variant is what we
// use in CI to keep tests fast. Run via `make bench` to detect regressions.
func BenchmarkHashAuthKey_Slim(b *testing.B) {
	p := Argon2Params{T: 1, MKiB: 1 << 10, P: 1}
	key := []byte("benchkey")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := HashAuthKey(key, p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashAuthKey_Production(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping production-params Argon2id under -short")
	}
	// Matches the default user_kdf_params in §4.2.
	p := Argon2Params{T: 3, MKiB: 128 << 10, P: 4}
	key := []byte("benchkey")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := HashAuthKey(key, p); err != nil {
			b.Fatal(err)
		}
	}
}
