package middleware

import "net/http"

// SecurityHeadersConfig controls the optional pieces of the security
// header set. CSP, COOP, COEP, X-Content-Type-Options, Referrer-Policy
// and Permissions-Policy are always emitted.
type SecurityHeadersConfig struct {
	// HSTS controls Strict-Transport-Security emission. Enabled only when
	// the server terminates TLS itself (or when the operator forces it
	// behind a reverse proxy).
	HSTS bool
}

// SecurityHeaders returns an http.Handler that applies the baseline
// security header set described in plan §10.5. The header values are
// constants so a snapshot test (added separately) can match exact strings
// and catch silent regressions.
func SecurityHeaders(cfg SecurityHeadersConfig, h http.Handler) http.Handler {
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
		if cfg.HSTS {
			hdr.Set("Strict-Transport-Security", strictTransportSecurity)
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

	// 2 years, includeSubDomains, preload — matches the hstspreload.org
	// minimum requirement. Only emitted when TLS is in front of the app.
	strictTransportSecurity = "max-age=63072000; includeSubDomains; preload"
)
