package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCaptureWriter_RecordsStatusAndBody(t *testing.T) {
	rec := httptest.NewRecorder()
	c := &captureWriter{ResponseWriter: rec, buf: &bytes.Buffer{}, max: 1024}
	c.WriteHeader(http.StatusCreated)
	_, _ = c.Write([]byte("hello"))

	if c.status != http.StatusCreated {
		t.Fatalf("status=%d", c.status)
	}
	if c.buf.String() != "hello" {
		t.Fatalf("buf=%q", c.buf.String())
	}
	if c.truncated {
		t.Fatal("must not be truncated under cap")
	}
	if rec.Code != http.StatusCreated || rec.Body.String() != "hello" {
		t.Fatalf("downstream lost data: code=%d body=%q", rec.Code, rec.Body)
	}
}

func TestCaptureWriter_DefaultsToOK(t *testing.T) {
	c := &captureWriter{ResponseWriter: httptest.NewRecorder(), buf: &bytes.Buffer{}, max: 8}
	_, _ = c.Write([]byte("x"))
	if c.status != http.StatusOK {
		t.Fatalf("status=%d, want 200", c.status)
	}
}

func TestCaptureWriter_TruncatesAtCap(t *testing.T) {
	rec := httptest.NewRecorder()
	c := &captureWriter{ResponseWriter: rec, buf: &bytes.Buffer{}, max: 4}
	_, _ = c.Write([]byte("abcdef"))
	if !c.truncated {
		t.Fatal("truncated must be set when body exceeds max")
	}
	if c.buf.Len() != 4 {
		t.Fatalf("buf len=%d, want 4", c.buf.Len())
	}
	if rec.Body.String() != "abcdef" {
		// captureWriter forwards everything; only the *cache* is capped.
		t.Fatalf("downstream body=%q, want full passthrough", rec.Body.String())
	}
}

func TestCaptureWriter_WritePastMaxKeepsTruncatedFlag(t *testing.T) {
	c := &captureWriter{ResponseWriter: httptest.NewRecorder(), buf: &bytes.Buffer{}, max: 2}
	_, _ = c.Write([]byte("ab"))
	_, _ = c.Write([]byte("cd"))
	if !c.truncated {
		t.Fatal("expected truncated after second write")
	}
	if c.buf.String() != "ab" {
		t.Fatalf("buf=%q, want ab", c.buf.String())
	}
}

func TestProcedureFromPath_PassThrough(t *testing.T) {
	cases := []string{
		"/oblivio.v1.EntriesService/CreateEntry",
		"/oblivio.v1.AuthService/Register",
	}
	for _, p := range cases {
		if got := procedureFromPath(p); got != p {
			t.Fatalf("procedureFromPath(%q) = %q", p, got)
		}
	}
}

func TestReplay_WritesBodyAndStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	body := []byte("cached-body")
	replay(rec, http.StatusOK, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatalf("body=%q want %q", rec.Body.Bytes(), body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/proto" {
		t.Fatalf("Content-Type=%q want application/proto", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "11" {
		t.Fatalf("Content-Length=%q want 11", got)
	}
}

func TestReplay_KeepsExistingContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/grpc+proto")
	replay(rec, http.StatusOK, []byte("x"))
	if got := rec.Header().Get("Content-Type"); got != "application/grpc+proto" {
		t.Fatalf("Content-Type=%q want preserved", got)
	}
}
