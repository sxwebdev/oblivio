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
	assertHeaders(t, http.StatusOK, "/")
}

func TestSecurityHeaders_SnapshotErrorResponse(t *testing.T) {
	assertHeaders(t, http.StatusInternalServerError, "/")
}

// HSTS is intentionally NOT emitted by the application (M-1). The reverse
// proxy that terminates TLS is responsible for it; emitting it from the
// app would either be wrong in dev (plain HTTP) or duplicate the proxy's
// header in prod.
func TestSecurityHeaders_HSTSAbsent(t *testing.T) {
	rec := callHandler(http.StatusOK, "/")
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("Strict-Transport-Security must NOT be set by the app; the reverse proxy owns it")
	}
}

// Responses under /api/ MUST carry no-store so a downstream proxy or
// service-worker mistake cannot persist a token-bearing or
// ciphertext-bearing response (M-12).
func TestSecurityHeaders_APICacheControl(t *testing.T) {
	rec := callHandler(http.StatusOK, "/api/oblivio.v1.AuthService/Authorize")
	if got, want := rec.Header().Get("Cache-Control"), "no-store, no-cache, must-revalidate"; got != want {
		t.Fatalf("Cache-Control on /api:\n  got  %q\n  want %q", got, want)
	}
	if got, want := rec.Header().Get("Pragma"), "no-cache"; got != want {
		t.Fatalf("Pragma on /api:\n  got  %q\n  want %q", got, want)
	}
	if got, want := rec.Header().Get("Vary"), "Authorization"; got != want {
		t.Fatalf("Vary on /api:\n  got  %q\n  want %q", got, want)
	}
}

// Static-asset paths (everything outside /api/) must NOT force no-store;
// the SPA bundle must be cacheable by the browser.
func TestSecurityHeaders_StaticAssetsCacheable(t *testing.T) {
	rec := callHandler(http.StatusOK, "/assets/index.js")
	if got := rec.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("Cache-Control on static asset must be empty so the response is cacheable; got %q", got)
	}
}

func assertHeaders(t *testing.T, status int, path string) {
	t.Helper()
	rec := callHandler(status, path)
	for k, want := range expectedHeaders {
		got := rec.Header().Get(k)
		if got != want {
			t.Fatalf("header %s:\n  got  %q\n  want %q", k, got, want)
		}
	}
}

func callHandler(status int, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("body"))
	}))
	h.ServeHTTP(rec, req)
	return rec
}
