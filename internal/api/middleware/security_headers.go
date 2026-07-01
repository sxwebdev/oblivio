package middleware

import (
	"net/http"
	"strings"
)

// SecurityHeaders returns an http.Handler that applies the baseline
// security header set described in plan §10.5. The header values are
// constants so a snapshot test (added separately) can match exact strings
// and catch silent regressions.
//
// HSTS deliberately is NOT emitted here. The deployment terminates TLS at
// the reverse proxy, where the application receives plain HTTP and cannot
// emit Strict-Transport-Security on behalf of the public origin (M-1).
// Operators MUST configure HSTS on the proxy with at least:
//
//	max-age=63072000; includeSubDomains; preload
//
// Cache-Control: no-store is emitted for /api/* responses (M-12) so a
// downstream proxy or service-worker mistake cannot persist a token- or
// ciphertext-bearing response.
func SecurityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Content-Security-Policy", contentSecurityPolicy)
		hdr.Set("Cross-Origin-Opener-Policy", "same-origin")
		hdr.Set("Cross-Origin-Embedder-Policy", "require-corp")
		hdr.Set("Cross-Origin-Resource-Policy", "same-origin")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "no-referrer")
		hdr.Set("Permissions-Policy", permissionsPolicy)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hdr.Set("Cache-Control", "no-store, no-cache, must-revalidate")
			hdr.Set("Pragma", "no-cache")
			hdr.Set("Vary", "Authorization")
		}
		h.ServeHTTP(w, r)
	})
}

// Header values are kept as package-level constants so the snapshot test
// can pin them. Any change here is a deliberate, reviewable diff.
const (
	contentSecurityPolicy = "default-src 'self'; " +
		"script-src 'self' 'wasm-unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'none'; " +
		"form-action 'self'; " +
		"object-src 'none'; " +
		"upgrade-insecure-requests"

	permissionsPolicy = "clipboard-read=(self), clipboard-write=(self), interest-cohort=()"
)
