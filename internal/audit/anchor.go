// External anchor for the audit hash-chain (plan §17.4).
//
// The chain in audit_log + system_state.audit_chain_head defends against
// accidental tampering. It does NOT defend against an attacker with full
// DB write access — such an attacker can rewrite both the rows and the
// head value coherently. Anchoring solves that by periodically signing the
// head with a key the attacker is unlikely to possess.
//
// The Signer interface lets the deployment pick its trust root:
//   - LocalSigner: Ed25519 key generated/loaded at process start, kept on
//     disk under 0o600. Sufficient for self-hosted single-node deploys —
//     the trust boundary is the OS user that runs the process.
//   - (future) VaultTransitSigner: HTTP calls to Vault transit. Stronger
//     trust root because the key never lives in process memory. Not
//     wired yet; the interface accepts it as a drop-in.

package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// stdEncoding is the std-base64 alphabet used to serialise the signer file.
// Padded form so the JSON is human-inspectable.
var stdEncoding = base64.StdEncoding

// Signer produces a detached signature over the current audit_chain_head.
// signerID labels which key was used so a rotating-key future deploy can
// verify older anchors against the right public key.
type Signer interface {
	Sign(ctx context.Context, head []byte) (signature []byte, signerID string, err error)
	// PublicKey returns the verifier-side material for the active key.
	// For LocalSigner this is the raw 32-byte Ed25519 public key.
	PublicKey() []byte
	// SignerID identifies the active key (suffix on disk, Vault key name,
	// etc.). Embedded in every anchor row.
	SignerID() string
}

// LocalSigner is the on-disk Ed25519 implementation. The private key lives
// in a JSON file under 0o600; the file is created on first start with a
// freshly generated keypair.
type LocalSigner struct {
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	signerID string
}

// NewLocalSigner loads or generates the signing key under `dir`. The signer
// ID derives from the first 8 hex chars of the public key — short enough
// to log, long enough to distinguish accidental key rotations.
func NewLocalSigner(dir string) (*LocalSigner, error) {
	if dir == "" {
		dir = "data/secrets"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit anchor: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, "audit_signer.json")

	type onDisk struct {
		Private string `json:"private_key"` // base64 ed25519 64-byte private
		Public  string `json:"public_key"`  // base64 ed25519 32-byte public
	}

	if data, err := os.ReadFile(path); err == nil {
		var od onDisk
		if err := json.Unmarshal(data, &od); err != nil {
			return nil, fmt.Errorf("audit anchor: parse %s: %w", path, err)
		}
		priv, err := base64Decode(od.Private)
		if err != nil {
			return nil, fmt.Errorf("audit anchor: decode priv: %w", err)
		}
		pub, err := base64Decode(od.Public)
		if err != nil {
			return nil, fmt.Errorf("audit anchor: decode pub: %w", err)
		}
		if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("audit anchor: malformed signer file")
		}
		return &LocalSigner{
			priv:     ed25519.PrivateKey(priv),
			pub:      ed25519.PublicKey(pub),
			signerID: signerIDFromPub(pub),
		}, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("audit anchor: read %s: %w", path, err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("audit anchor: generate key: %w", err)
	}
	od := onDisk{
		Private: base64Encode(priv),
		Public:  base64Encode(pub),
	}
	buf, _ := json.Marshal(od)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return nil, fmt.Errorf("audit anchor: write %s: %w", path, err)
	}
	return &LocalSigner{
		priv:     priv,
		pub:      pub,
		signerID: signerIDFromPub(pub),
	}, nil
}

// Sign returns ed25519(priv, head). signerID is short-form so it can be
// logged without bloating audit rows.
func (s *LocalSigner) Sign(_ context.Context, head []byte) ([]byte, string, error) {
	if s == nil {
		return nil, "", errors.New("audit anchor: signer not configured")
	}
	sig := ed25519.Sign(s.priv, head)
	return sig, s.signerID, nil
}

// PublicKey returns the raw 32-byte Ed25519 public key — used by the
// verifier path to check past anchors.
func (s *LocalSigner) PublicKey() []byte {
	if s == nil {
		return nil
	}
	return []byte(s.pub)
}

// SignerID returns the short hex form of the public key.
func (s *LocalSigner) SignerID() string {
	if s == nil {
		return ""
	}
	return s.signerID
}

func signerIDFromPub(pub []byte) string {
	const hexTable = "0123456789abcdef"
	out := make([]byte, 16)
	for i := 0; i < 8 && i < len(pub); i++ {
		out[2*i] = hexTable[pub[i]>>4]
		out[2*i+1] = hexTable[pub[i]&0x0f]
	}
	return "local:" + string(out)
}

func base64Encode(b []byte) string {
	return stdEncoding.EncodeToString(b)
}

func base64Decode(s string) ([]byte, error) {
	return stdEncoding.DecodeString(s)
}
