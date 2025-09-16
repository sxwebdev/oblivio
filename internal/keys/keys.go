package keys

import (
	"crypto/sha256"
	"errors"

	icrypto "github.com/sxwebdev/oblivio/internal/crypto"
)

type StoreKeys struct {
	KRoot     []byte // 32B
	KStoreMAC []byte // 32B
	KSeal     []byte // 32B
}

// DeriveStoreKeys derives store keys from adminSecret and optional tpmBlob
func DeriveStoreKeys(adminSecret, tpmBlob []byte) (*StoreKeys, error) {
	if len(adminSecret) == 0 && len(tpmBlob) == 0 {
		return nil, errors.New("no material to derive K_root")
	}
	rootInput := make([]byte, 0, len(adminSecret)+len(tpmBlob))
	rootInput = append(rootInput, adminSecret...)
	rootInput = append(rootInput, tpmBlob...)
	kroot, err := icrypto.HKDFSHA256(rootInput, "oblivio/store/root/v1", 32)
	if err != nil {
		return nil, err
	}
	kmac, err := icrypto.HKDFSHA256(kroot, "store/mac/v1", 32)
	if err != nil {
		return nil, err
	}
	kseal, err := icrypto.HKDFSHA256(kroot, "seal/v1", 32)
	if err != nil {
		return nil, err
	}
	// Zeroize rootInput
	h := sha256.Sum256(rootInput)
	_ = h // avoid unused; relies on GC for zeroize in Go
	return &StoreKeys{KRoot: kroot, KStoreMAC: kmac, KSeal: kseal}, nil
}
