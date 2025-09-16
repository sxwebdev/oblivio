package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cockroachdb/pebble/v2"
	icrypto "github.com/sxwebdev/oblivio/internal/crypto"
)

type Seal struct {
	Counter    uint64   `json:"counter"`
	RootGlobal [32]byte `json:"root_global"`
	TS         int64    `json:"ts"`
}

// ComputeRoot recomputes global Merkle-like root from all items: Root(global) = H(vault_id|Root(vault)) where Root(vault) = Merkle(sorted item hashes)
func (d *DB) ComputeRoot() ([32]byte, error) {
	type byVault struct {
		vault string
		items [][32]byte
	}
	vaultMap := map[string]*byVault{}
	it, err := d.db.NewIter(nil)
	if err != nil {
		return [32]byte{}, err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		k := it.Key()
		if !bytes.HasPrefix(k, []byte("it:")) {
			continue
		}
		parts := bytes.Split(k, []byte{':'})
		if len(parts) != 3 {
			continue
		}
		vaultID := string(parts[1])
		itemID := string(parts[2])
		// Hash per item
		ct := it.Value()
		hct := sha256.Sum256(ct)
		// H_item = SHA256("item"|vault_id|item_id|version|SHA256(ciphertext)); assume version=1
		ver := make([]byte, 4)
		binary.BigEndian.PutUint32(ver, 1)
		h := sha256.New()
		h.Write([]byte("item"))
		h.Write([]byte(vaultID))
		h.Write([]byte(itemID))
		h.Write(ver)
		h.Write(hct[:])
		var hItem [32]byte
		copy(hItem[:], h.Sum(nil))
		v := vaultMap[vaultID]
		if v == nil {
			v = &byVault{vault: vaultID}
			vaultMap[vaultID] = v
		}
		v.items = append(v.items, hItem)
	}
	// Compute per-vault roots
	vaultRoots := make([][32]byte, 0, len(vaultMap))
	vaultIDs := make([]string, 0, len(vaultMap))
	for id := range vaultMap {
		vaultIDs = append(vaultIDs, id)
	}
	sort.Strings(vaultIDs)
	for _, id := range vaultIDs {
		v := vaultMap[id]
		// sort by item hash
		sort.Slice(v.items, func(i, j int) bool { return bytes.Compare(v.items[i][:], v.items[j][:]) < 0 })
		// Merkle-ish: fold pairwise
		r := merkleRoot(v.items)
		// H(vault_id|root_vault)
		hv := sha256.New()
		hv.Write([]byte(id))
		hv.Write(r[:])
		var vr [32]byte
		copy(vr[:], hv.Sum(nil))
		vaultRoots = append(vaultRoots, vr)
	}
	// Global root
	root := merkleRoot(vaultRoots)
	return root, nil
}

func merkleRoot(nodes [][32]byte) [32]byte {
	if len(nodes) == 0 {
		return [32]byte{}
	}
	if len(nodes) == 1 {
		return nodes[0]
	}
	// if odd, duplicate last
	var level [][32]byte
	if len(nodes)%2 == 1 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}
	for i := 0; i < len(nodes); i += 2 {
		h := sha256.New()
		h.Write(nodes[i][:])
		h.Write(nodes[i+1][:])
		var out [32]byte
		copy(out[:], h.Sum(nil))
		level = append(level, out)
	}
	return merkleRoot(level)
}

// Seal state AEAD encode/decode
func (d *DB) EncodeSeal(kSeal []byte, s Seal) ([]byte, []byte, error) {
	a, err := icrypto.NewXChaCha20Poly1305(kSeal)
	if err != nil {
		return nil, nil, err
	}
	// nonce random is external; for simplicity here we use ts+counter deterministic to reduce RNG needs in MVP. Replace with CSPRNG.
	nonce := make([]byte, a.NonceSize())
	binary.BigEndian.PutUint64(nonce[:8], s.Counter)
	binary.BigEndian.PutUint64(nonce[8:16], uint64(s.TS))
	copy(nonce[16:], []byte{0, 0, 0, 1})
	b, _ := json.Marshal(s)
	aad := []byte("seal|v1")
	ct, err := a.Seal(nonce, b, aad)
	if err != nil {
		return nil, nil, err
	}
	return nonce, ct, nil
}

func (d *DB) DecodeSeal(kSeal []byte, nonce, ct []byte) (*Seal, error) {
	a, err := icrypto.NewXChaCha20Poly1305(kSeal)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nonce, ct, []byte("seal|v1"))
	if err != nil {
		return nil, err
	}
	var s Seal
	if err := json.Unmarshal(pt, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (d *DB) WriteSeal(kSeal []byte, s Seal) error {
	nonce, ct, err := d.EncodeSeal(kSeal, s)
	if err != nil {
		return err
	}
	// store as nonce|ct
	val := append(append([]byte{}, nonce...), ct...)
	return d.db.Set(keySeal(), val, &pebble.WriteOptions{Sync: true})
}

func (d *DB) ReadSeal(kSeal []byte) (*Seal, error) {
	v, closer, err := d.db.Get(keySeal())
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	a, err := icrypto.NewXChaCha20Poly1305(kSeal)
	if err != nil {
		return nil, err
	}
	ns := a.NonceSize()
	if len(v) < ns {
		return nil, fmt.Errorf("seal: short value")
	}
	nonce := v[:ns]
	ct := v[ns:]
	return d.DecodeSeal(kSeal, nonce, ct)
}

func (d *DB) NewSeal(counter uint64, root [32]byte) Seal {
	return Seal{Counter: counter, RootGlobal: root, TS: time.Now().Unix()}
}
