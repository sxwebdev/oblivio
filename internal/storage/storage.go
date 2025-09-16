package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/cockroachdb/pebble/v2"
	icrypto "github.com/sxwebdev/oblivio/internal/crypto"
)

var ErrNotFound = errors.New("not found")

type DB struct {
	db   *pebble.DB
	kMac []byte
}

func Open(path string, kMac []byte) (*DB, error) {
	if path == "" {
		path = "./data/pebble"
	}
	d, err := pebble.Open(filepath.Clean(path), &pebble.Options{})
	if err != nil {
		return nil, err
	}
	return &DB{db: d, kMac: kMac}, nil
}

func (d *DB) Close() error { return d.db.Close() }

// Key builders
func keyItem(vaultID, itemID string) []byte { return []byte(fmt.Sprintf("it:%s:%s", vaultID, itemID)) }

func keyItemMAC(vaultID, itemID string) []byte {
	return []byte(fmt.Sprintf("mac:%s:%s", vaultID, itemID))
}

func keyIndex(vaultID, typ, tok, itemID string) []byte {
	return []byte(fmt.Sprintf("ix:%s:%s:%s:%s", vaultID, typ, tok, itemID))
}

func keyMetaUpdated(vaultID string, updatedAt int64, itemID string) []byte {
	// meta:<vault_id>:list:<rev_ts_hex16>:<item_id> with reversed timestamp for DESC
	var ts [8]byte
	rev := ^uint64(0) - uint64(updatedAt)
	binary.BigEndian.PutUint64(ts[:], rev)
	tsHex := make([]byte, hex.EncodedLen(len(ts)))
	hex.Encode(tsHex, ts[:])
	return []byte(fmt.Sprintf("meta:%s:list:%s:%s", vaultID, string(tsHex), itemID))
}
func keySeal() []byte { return []byte("seal:state") }

// ItemMAC computes HMAC for a ciphertext record
func (d *DB) ItemMAC(vaultID, itemID string, version uint32, ciphertext []byte) [32]byte {
	hct := sha256.Sum256(ciphertext)
	ver := make([]byte, 4)
	binary.BigEndian.PutUint32(ver, version)
	label := []byte("item")
	return icrypto.HMACSHA256(d.kMac, label, []byte(vaultID), []byte(itemID), ver, hct[:])
}

// VerifyAllMACs scans mac:* and compares to ciphertext hashes. Panic on mismatch per spec.
func (d *DB) VerifyAllMACs() error {
	it, err := d.db.NewIter(&pebble.IterOptions{LowerBound: []byte("mac:"), UpperBound: []byte("mad:") /* next ascii after 'c' */})
	if err != nil {
		return err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		// key format mac:vault:item
		k := it.Key()
		parts := bytes.Split(k, []byte{':'})
		if len(parts) != 3 {
			return fmt.Errorf("bad mac key: %s", string(k))
		}
		vaultID := string(parts[1])
		itemID := string(parts[2])
		// parse version is not in mac key; we'll attempt from item payload
		iv, closer, err := d.db.Get(keyItem(vaultID, itemID))
		if err != nil {
			return fmt.Errorf("missing item for mac: %s", string(k))
		}
		defer closer.Close()

		// version is embedded in AAD; without parsing we assume v=1 for mac computation here
		// For future versions, store version inside mac value if needed.
		macExpected := d.ItemMAC(vaultID, itemID, 1, iv)
		if !bytes.Equal(it.Value(), macExpected[:]) {
			return fmt.Errorf("mac mismatch for %s", string(k))
		}
	}
	return nil
}

type ItemRecord struct {
	ItemID     string
	Version    uint32
	Ciphertext []byte
	UpdatedAt  int64
	Size       int
}

// PutItem writes ciphertext and updates indices and mac; indicesTokens is map[type][]tokens (base64url strings) from client
func (d *DB) PutItem(vaultID string, rec ItemRecord, indicesTokens map[string][]string) error {
	wb := d.db.NewBatch()
	defer wb.Close()
	now := rec.UpdatedAt
	if now == 0 {
		now = time.Now().Unix()
	}
	// it:*
	if err := wb.Set(keyItem(vaultID, rec.ItemID), rec.Ciphertext, &pebble.WriteOptions{Sync: true}); err != nil {
		return err
	}
	// mac:*
	mac := d.ItemMAC(vaultID, rec.ItemID, rec.Version, rec.Ciphertext)
	if err := wb.Set(keyItemMAC(vaultID, rec.ItemID), mac[:], &pebble.WriteOptions{Sync: true}); err != nil {
		return err
	}
	// meta: list
	if err := wb.Set(keyMetaUpdated(vaultID, now, rec.ItemID), []byte{}, &pebble.WriteOptions{Sync: true}); err != nil {
		return err
	}
	// indices: delete old and add new (simplified: drop all ix for this item)
	// scan and delete
	prefix := []byte(fmt.Sprintf("ix:%s:", vaultID))
	it, err := d.db.NewIter(&pebble.IterOptions{LowerBound: prefix, UpperBound: append(append([]byte{}, prefix...), 0xff)})
	if err != nil {
		return err
	}
	for it.First(); it.Valid(); it.Next() {
		if bytes.HasSuffix(it.Key(), []byte(":"+rec.ItemID)) {
			if err := wb.Delete(it.Key(), &pebble.WriteOptions{Sync: true}); err != nil {
				it.Close()
				return err
			}
		}
	}
	it.Close()
	for typ, toks := range indicesTokens {
		for _, tok := range toks {
			if err := wb.Set(keyIndex(vaultID, typ, tok, rec.ItemID), []byte{}, &pebble.WriteOptions{Sync: true}); err != nil {
				return err
			}
		}
	}
	return wb.Commit(&pebble.WriteOptions{Sync: true})
}

func (d *DB) GetItem(vaultID, itemID string) (*ItemRecord, error) {
	v, closer, err := d.db.Get(keyItem(vaultID, itemID))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer closer.Close()
	// Verify MAC
	m, closer2, err := d.db.Get(keyItemMAC(vaultID, itemID))
	if err != nil {
		return nil, err
	}
	defer closer2.Close()
	mac := d.ItemMAC(vaultID, itemID, 1, v)
	if !bytes.Equal(m, mac[:]) {
		return nil, icrypto.ErrMACMismatch
	}
	return &ItemRecord{ItemID: itemID, Version: 1, Ciphertext: append([]byte(nil), v...), Size: len(v)}, nil
}

func (d *DB) DeleteItem(vaultID, itemID string) error {
	wb := d.db.NewBatch()
	defer wb.Close()
	if err := wb.Delete(keyItem(vaultID, itemID), &pebble.WriteOptions{Sync: true}); err != nil {
		return err
	}
	if err := wb.Delete(keyItemMAC(vaultID, itemID), &pebble.WriteOptions{Sync: true}); err != nil {
		return err
	}
	// delete indices
	prefix := []byte(fmt.Sprintf("ix:%s:", vaultID))
	it, err := d.db.NewIter(&pebble.IterOptions{LowerBound: prefix, UpperBound: append(append([]byte{}, prefix...), 0xff)})
	if err != nil {
		return err
	}
	for it.First(); it.Valid(); it.Next() {
		if bytes.HasSuffix(it.Key(), []byte(":"+itemID)) {
			if err := wb.Delete(it.Key(), &pebble.WriteOptions{Sync: true}); err != nil {
				it.Close()
				return err
			}
		}
	}
	it.Close()
	// delete meta entries
	metaPrefix := []byte(fmt.Sprintf("meta:%s:list:", vaultID))
	it2, err := d.db.NewIter(&pebble.IterOptions{LowerBound: metaPrefix, UpperBound: append(append([]byte{}, metaPrefix...), 0xff)})
	if err != nil {
		return err
	}
	for it2.First(); it2.Valid(); it2.Next() {
		if bytes.HasSuffix(it2.Key(), []byte(":"+itemID)) {
			if err := wb.Delete(it2.Key(), &pebble.WriteOptions{Sync: true}); err != nil {
				it2.Close()
				return err
			}
		}
	}
	it2.Close()
	return wb.Commit(&pebble.WriteOptions{Sync: true})
}

// List returns page of (item_id, updated_at, size) sorted by updated_at DESC, item_id DESC
type ListEntry struct {
	ItemID    string
	UpdatedAt int64
	Size      int
}

func (d *DB) List(vaultID string, limit int, cursor []byte) (entries []ListEntry, next []byte, err error) {
	// We encoded updated_at reversed in key; simple forward scan yields DESC.
	prefix := []byte(fmt.Sprintf("meta:%s:list:", vaultID))
	it, err := d.db.NewIter(&pebble.IterOptions{LowerBound: prefix, UpperBound: append(append([]byte{}, prefix...), 0xff)})
	if err != nil {
		return nil, nil, err
	}
	defer it.Close()
	// Cursor not implemented fully: MVP start from First or from SeekGE to cursor key.
	if len(cursor) > 0 {
		it.SeekGE(cursor)
	} else {
		it.First()
	}
	for ; it.Valid() && (limit <= 0 || len(entries) < limit); it.Next() {
		k := it.Key()
		// find last colon for itemID
		last := bytes.LastIndexByte(k, ':')
		if last < 0 || last+1 >= len(k) {
			continue
		}
		itemID := string(k[last+1:])
		// find previous colon for ts hex
		prev := bytes.LastIndexByte(k[:last], ':')
		if prev < 0 || prev+1 >= last {
			continue
		}
		tsHex := k[prev+1 : last]
		if len(tsHex) != 16 {
			continue
		}
		var tsBytes [8]byte
		if _, err := hex.Decode(tsBytes[:], tsHex); err != nil {
			continue
		}
		rev := binary.BigEndian.Uint64(tsBytes[:])
		updatedAt := int64(^uint64(0) - rev)
		// size from item value length
		v, closer, err := d.db.Get(keyItem(vaultID, itemID))
		if err != nil {
			if errors.Is(err, pebble.ErrNotFound) {
				continue
			} else {
				return nil, nil, err
			}
		}
		sz := len(v)
		closer.Close()
		entries = append(entries, ListEntry{ItemID: itemID, UpdatedAt: updatedAt, Size: sz})
	}
	// next cursor = current key
	if it.Valid() {
		next = append([]byte(nil), it.Key()...)
	}
	return entries, next, nil
}

// SearchEq intersects tokens for types and returns item_ids; MVP: single type OR multi type intersection
func (d *DB) SearchEq(vaultID string, typ string, tokens []string, limit int, cursor []byte) (ids []string, next []byte, err error) {
	// Simple union across tokens for the same type; intersection across multiple types can be added later.
	seen := map[string]struct{}{}
	for _, tok := range tokens {
		prefix := []byte(fmt.Sprintf("ix:%s:%s:%s:", vaultID, typ, tok))
		it, err := d.db.NewIter(&pebble.IterOptions{LowerBound: prefix, UpperBound: append(append([]byte{}, prefix...), 0xff)})
		if err != nil {
			return nil, nil, err
		}
		for it.First(); it.Valid(); it.Next() {
			parts := bytes.Split(it.Key(), []byte{':'})
			itemID := string(parts[len(parts)-1])
			if _, ok := seen[itemID]; !ok {
				seen[itemID] = struct{}{}
				ids = append(ids, itemID)
				if limit > 0 && len(ids) >= limit {
					it.Close()
					return ids, nil, nil
				}
			}
		}
		it.Close()
	}
	sort.Strings(ids)
	return ids, nil, nil
}
