package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzCanonicalJSON drives arbitrary JSON at the canonicaliser. The
// invariants we want to preserve:
//
//  1. Never panic on parseable JSON.
//  2. The canonical output is itself valid JSON (round-trips through
//     encoding/json).
//  3. The canonicaliser is *stable*: feeding back its own output yields
//     identical bytes. Hash-chain integrity depends on this.
func FuzzCanonicalJSON(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"a":1,"b":2}`,
		`{"b":2,"a":1}`,
		`{"nested":{"z":1,"a":2},"list":[3,2,1]}`,
		`{"k":[{"z":1,"a":2},{"a":3,"b":4}]}`,
		`{"u":null,"s":"x","f":1.5,"b":true}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var m map[string]any
		if err := json.Unmarshal(in, &m); err != nil {
			return // not parseable → outside scope
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on %s: %v", in, r)
			}
		}()
		first, err := canonicalJSON(m)
		if err != nil {
			t.Fatalf("first canonical: %v", err)
		}
		// Output must round-trip cleanly.
		var rt map[string]any
		if err := json.Unmarshal(first, &rt); err != nil {
			t.Fatalf("canonical output not valid JSON: %v\ngot %s", err, first)
		}
		// And re-canonicalising must give identical bytes (stable).
		second, err := canonicalJSON(rt)
		if err != nil {
			t.Fatalf("second canonical: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("canonicalJSON is not stable:\n first: %s\nsecond: %s", first, second)
		}
	})
}
