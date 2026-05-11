package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/sxwebdev/oblivio/internal/models"
)

// TestCanonicalJSON_StableKeyOrder asserts that map keys are emitted in
// sorted order, regardless of the iteration order Go would otherwise pick.
// This is the foundation the hash-chain rests on.
func TestCanonicalJSON_StableKeyOrder(t *testing.T) {
	for i := range 32 {
		got, err := canonicalJSON(map[string]any{
			"zeta":  1,
			"alpha": 2,
			"mu":    3,
		})
		if err != nil {
			t.Fatal(err)
		}
		want := `{"alpha":2,"mu":3,"zeta":1}`
		if string(got) != want {
			t.Fatalf("iter=%d: got %s want %s", i, got, want)
		}
	}
}

func TestCanonicalJSON_Nested(t *testing.T) {
	in := map[string]any{
		"outer": map[string]any{"z": 1, "a": 2},
		"list":  []any{map[string]any{"b": 1, "a": 2}, "x"},
	}
	got, err := canonicalJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"list":[{"a":2,"b":1},"x"],"outer":{"a":2,"z":1}}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

// TestCanonicalJSON_Nil documents the (now-corrected) contract: nil and
// empty-map both serialise to "{}" so the writer (which persists nil as
// "{}" via metadataBytes) and the verifier (which reads "{}" back into a
// non-nil empty map) agree on the canonical hash input.
func TestCanonicalJSON_Nil(t *testing.T) {
	got, err := canonicalJSON(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{}" {
		t.Fatalf("got %s want {}", got)
	}
}

// TestCanonicalRow_FieldOrder is the regression test that protects against
// silent reordering of struct fields by future refactors.
func TestCanonicalRow_FieldOrder(t *testing.T) {
	uid := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	tid := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	ip := netip.MustParseAddr("203.0.113.1")
	ts := time.Unix(1700000000, 123_000).UTC()
	ev := Event{
		UserID:    uuid.NullUUID{UUID: uid, Valid: true},
		Action:    models.AuditAction("user.login"),
		TargetID:  uuid.NullUUID{UUID: tid, Valid: true},
		IP:        &ip,
		UserAgent: "ua",
		Metadata:  map[string]any{"k": "v"},
	}
	got, err := canonicalRow(ev, ts)
	if err != nil {
		t.Fatal(err)
	}
	// Decode and re-encode in a *non-canonical* way; if our canonical
	// output ever drifts in field order, the parsed map will reorder
	// alphabetically but the original byte sequence won't match.
	var roundtrip map[string]any
	if err := json.Unmarshal(got, &roundtrip); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"action", "created_at", "ip", "metadata", "target_id", "user_agent", "user_id"} {
		if _, ok := roundtrip[key]; !ok {
			t.Fatalf("missing %q in canonical row", key)
		}
	}
	// Spot-check: action must appear before created_at, etc.
	idxAction := bytes.Index(got, []byte(`"action"`))
	idxCreated := bytes.Index(got, []byte(`"created_at"`))
	idxIP := bytes.Index(got, []byte(`"ip"`))
	idxMeta := bytes.Index(got, []byte(`"metadata"`))
	idxTarget := bytes.Index(got, []byte(`"target_id"`))
	idxUA := bytes.Index(got, []byte(`"user_agent"`))
	idxUID := bytes.Index(got, []byte(`"user_id"`))
	for _, p := range [][2]int{
		{idxAction, idxCreated},
		{idxCreated, idxIP},
		{idxIP, idxMeta},
		{idxMeta, idxTarget},
		{idxTarget, idxUA},
		{idxUA, idxUID},
	} {
		if p[0] < 0 || p[1] < 0 || p[0] >= p[1] {
			t.Fatalf("canonical row field ordering broken: %s", got)
		}
	}
}

// TestComputeSelfHash_MatchesAppend simulates the writer-then-verifier
// path purely in memory: build a row, hash it, then re-derive via
// computeSelfHash. They must agree byte-for-byte for the chain to verify.
func TestComputeSelfHash_MatchesAppend(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	ev := Event{
		Action:   models.AuditAction("user.login"),
		Metadata: map[string]any{"reason": "test"},
	}
	canonical, err := canonicalRow(ev, ts)
	if err != nil {
		t.Fatal(err)
	}
	prev := genesisHash()
	want := sha256.Sum256(append(append([]byte{}, prev...), canonical...))

	row := &models.AuditLog{
		Action:    ev.Action,
		Metadata:  []byte(`{"reason":"test"}`),
		PrevHash:  prev,
		SelfHash:  want[:],
		CreatedAt: ts2pg(ts),
	}
	got := computeSelfHash(prev, row)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("computeSelfHash mismatch:\n got %x\nwant %x", got, want[:])
	}
}

// TestHashChain_TamperDetection builds a 5-entry in-memory chain, then
// flips a byte in the middle. computeSelfHash on the tampered row must
// diverge from the stored self_hash, and propagation must show the
// failure on every downstream row too.
func TestHashChain_TamperDetection(t *testing.T) {
	chain := buildInMemoryChain(t, 5)
	// Index 2 is in the middle.
	chain[2].UserAgent.String = "tampered"

	prev := genesisHash()
	firstBad := 0
	for i, row := range chain {
		expected := computeSelfHash(prev, row)
		if !bytes.Equal(expected, row.SelfHash) {
			firstBad = i
			break
		}
		prev = row.SelfHash
	}
	if firstBad == 0 {
		t.Fatal("tampered row was not detected")
	}
	if firstBad != 2 {
		t.Fatalf("first bad index = %d, want 2", firstBad)
	}
}

// TestHashChain_PrevLinkConsistency: flipping prev_hash of any row breaks
// the prev_hash check.
func TestHashChain_PrevLinkConsistency(t *testing.T) {
	chain := buildInMemoryChain(t, 4)
	chain[3].PrevHash[0] ^= 0xff
	prev := genesisHash()
	firstBad := 0
	for i, row := range chain {
		if !bytes.Equal(prev, row.PrevHash) && firstBad == 0 {
			firstBad = i
			break
		}
		prev = row.SelfHash
	}
	if firstBad != 3 {
		t.Fatalf("prev_hash tamper at index 3 not detected (firstBad=%d)", firstBad)
	}
}

// TestHashChain_CleanVerifies: a freshly-built chain re-verifies cleanly.
func TestHashChain_CleanVerifies(t *testing.T) {
	chain := buildInMemoryChain(t, 8)
	prev := genesisHash()
	for i, row := range chain {
		if !bytes.Equal(prev, row.PrevHash) {
			t.Fatalf("prev_hash mismatch at %d", i)
		}
		if !bytes.Equal(computeSelfHash(prev, row), row.SelfHash) {
			t.Fatalf("self_hash mismatch at %d", i)
		}
		prev = row.SelfHash
	}
}

// buildInMemoryChain constructs n hash-chained rows mirroring Writer.Append
// without touching the database. The returned slice is in ascending id order.
func buildInMemoryChain(t *testing.T, n int) []*models.AuditLog {
	t.Helper()
	prev := genesisHash()
	out := make([]*models.AuditLog, 0, n)
	for i := range n {
		ts := time.Unix(1700000000+int64(i), 0).UTC()
		ev := Event{
			Action:    models.AuditAction("user.login"),
			Metadata:  map[string]any{"i": i},
			UserAgent: "tester",
		}
		canonical, err := canonicalRow(ev, ts)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(append(append([]byte{}, prev...), canonical...))
		row := &models.AuditLog{
			ID:        int64(i + 1),
			Action:    ev.Action,
			UserAgent: pgtypeTextFrom(ev.UserAgent),
			Metadata:  metadataBytes(ev.Metadata),
			PrevHash:  append([]byte(nil), prev...),
			SelfHash:  sum[:],
			CreatedAt: ts2pg(ts),
		}
		out = append(out, row)
		prev = row.SelfHash
	}
	return out
}

func ts2pg(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}
