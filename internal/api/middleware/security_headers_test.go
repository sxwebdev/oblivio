package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// expectedHeaders is the snapshot of every header value the middleware
// must emit on every response — including 4xx and 5xx. A drift in any
// string here is a security-relevant regression (e.g. weakening CSP).
//
// Comments next to each entry document the security property the value
// preserves; do not lower these without a deliberate review.
var expectedHeaders = map[string]string{
	// CSP — no inline scripts, no eval, no remote origins. 'wasm-unsafe-eval'
	// is required for the Argon2id WASM in the browser; everything else is
	// fully constrained.
	"Content-Security-Policy": "default-src 'self'; " +
		"script-src 'self' 'wasm-unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'none'; " +
		"form-action 'self'; " +
		"object-src 'none'; " +
		"upgrade-insecure-requests",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Embedder-Policy": "require-corp",
	"Cross-Origin-Resource-Policy": "same-origin",
	"X-Content-Type-Options":       "nosniff",
	"X-Frame-Options":              "DENY",
	"Referrer-Policy":              "no-referrer",
	"Permissions-Policy":           "clipboard-read=(self), clipboard-write=(self), interest-cohort=()",
}

func TestSecurityHeaders_Snapshot200(t *testing.T) {
	assertHeaders(t, http.StatusOK, false)
}

func TestSecurityHeaders_SnapshotErrorResponse(t *testing.T) {
	assertHeaders(t, http.StatusInternalServerError, false)
}

func TestSecurityHeaders_HSTSEmittedWhenEnabled(t *testing.T) {
	assertHeaders(t, http.StatusOK, true)
}

func TestSecurityHeaders_HSTSAbsentByDefault(t *testing.T) {
	rec := callHandler(http.StatusOK, false)
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must NOT be emitted when HSTS=false")
	}
}

func assertHeaders(t *testing.T, status int, hsts bool) {
	t.Helper()
	rec := callHandler(status, hsts)
	for k, want := range expectedHeaders {
		got := rec.Header().Get(k)
		if got != want {
			t.Fatalf("header %s:\n  got  %q\n  want %q", k, got, want)
		}
	}
	if hsts {
		if got, want := rec.Header().Get("Strict-Transport-Security"), "max-age=63072000; includeSubDomains; preload"; got != want {
			t.Fatalf("HSTS:\n  got  %q\n  want %q", got, want)
		}
	}
}

func callHandler(status int, hsts bool) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h := SecurityHeaders(SecurityHeadersConfig{HSTS: hsts}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("body"))
	}))
	h.ServeHTTP(rec, req)
	return rec
}
