package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cockroachdb/pebble/v2"
)

type UserRecord struct {
	Username   string `json:"username"`
	PassHash   string `json:"pass_hash"`
	CreatedAt  int64  `json:"created_at"`
	TOTPSecret string `json:"totp_secret,omitempty"`
	MFAEnabled bool   `json:"mfa_enabled"`
}

type SessionRecord struct {
	Token     string `json:"token"`
	Username  string `json:"username"`
	ExpiresAt int64  `json:"expires_at"`
}

func keyUser(username string) []byte { return []byte(fmt.Sprintf("usr:%s", username)) }
func keySession(token string) []byte { return []byte(fmt.Sprintf("sess:%s", token)) }

func (d *DB) GetUser(username string) (*UserRecord, error) {
	v, closer, err := d.db.Get(keyUser(username))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer closer.Close()
	var rec UserRecord
	if err := json.Unmarshal(v, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (d *DB) PutUser(rec UserRecord) error {
	if rec.CreatedAt == 0 {
		rec.CreatedAt = time.Now().Unix()
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return d.db.Set(keyUser(rec.Username), b, &pebble.WriteOptions{Sync: true})
}

func (d *DB) PutSession(rec SessionRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return d.db.Set(keySession(rec.Token), b, &pebble.WriteOptions{Sync: true})
}

func (d *DB) GetSession(token string) (*SessionRecord, error) {
	v, closer, err := d.db.Get(keySession(token))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer closer.Close()
	var rec SessionRecord
	if err := json.Unmarshal(v, &rec); err != nil {
		return nil, err
	}
	if rec.ExpiresAt > 0 && time.Now().Unix() > rec.ExpiresAt {
		return nil, ErrNotFound
	}
	return &rec, nil
}

func (d *DB) DeleteSession(token string) error {
	return d.db.Delete(keySession(token), &pebble.WriteOptions{Sync: true})
}
