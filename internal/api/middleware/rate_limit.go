// Package middleware: rate limiter for sensitive anonymous endpoints.
//
// We use an in-memory token-bucket (golang.org/x/time/rate) keyed by
// "kind:identifier". The plan §6.6 specifies a Postgres-backed bucket so a
// rate-limit decision survives restart and works in a multi-node deploy.
// We deliberately picked the in-memory variant in Sprint 4 (per user choice)
// because it avoids a DB round-trip on every Authorize/GetKDFParams. The
// `rate_limit_buckets` table is left in place for a future migration.
//
// The limiter is wired as an HTTP middleware (NOT a Connect interceptor) so
// it can see the client IP — the interceptor surface only exposes the
// ConnectRPC request, not net/http.Request. For per-email rate limiting we
// decode the protobuf body lazily and key on email when the procedure carries
// one.
package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/metrics"
)

// RateLimitMiddleware applies per-IP and per-email token-bucket limits to
// anonymous authentication procedures. A request that exceeds any bucket is
// rejected with 429 Too Many Requests; the response body is plain text so
// it shows up in browser network logs without protobuf decoding.
type RateLimitMiddleware struct {
	cfg config.RateLimits

	mu       sync.Mutex
	limiters map[string]*entry
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimitMiddleware constructs the middleware. A background goroutine
// is not needed: stale entries are reaped lazily during `bucket` lookups.
func NewRateLimitMiddleware(cfg config.RateLimits) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		cfg:      cfg,
		limiters: make(map[string]*entry),
	}
}

// Wrap installs the middleware. It mutates request bodies for procedures
// that we need to inspect (e.g. to read the `email` field) and re-installs
// the bytes so the downstream Connect handler still sees them.
func (m *RateLimitMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		procedure := procedureFromPath(r.URL.Path)
		rule, ok := proceduresWithRateLimit[procedure]
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		ip := clientIP(r)
		// Per-IP limit (always applied to listed procedures).
		ipLimit, ipBurst := rule.ipLimit(m.cfg)
		if ipLimit > 0 && !m.allow(rule.ipKey(ip), ipLimit, ipBurst) {
			metrics.RateLimitDropsTotal.WithLabelValues(procedure, "ip").Inc()
			tooMany(w, "rate limit exceeded (ip)")
			return
		}

		// Per-email limit (only when the request body carries an email).
		emailLimit, emailBurst := rule.emailLimit(m.cfg)
		if emailLimit > 0 {
			email, body, ok := peekEmail(r)
			if ok && email != "" {
				if !m.allow(rule.emailKey(email), emailLimit, emailBurst) {
					metrics.RateLimitDropsTotal.WithLabelValues(procedure, "email").Inc()
					tooMany(w, "rate limit exceeded (email)")
					return
				}
			}
			// Re-install body (peekEmail consumed it).
			if body != nil {
				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = int64(len(body))
			}
		}

		next.ServeHTTP(w, r)
	})
}

// allow returns true if a token is available. The Sprint-4 limiter resets
// stale entries (>10min) lazily to avoid an unbounded map.
func (m *RateLimitMiddleware) allow(key string, perMin uint32, burst int) bool {
	if perMin == 0 {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.limiters == nil {
		m.limiters = make(map[string]*entry)
	}
	now := time.Now()
	e, ok := m.limiters[key]
	if !ok {
		e = &entry{
			limiter: rate.NewLimiter(rate.Limit(float64(perMin)/60.0), burst),
		}
		m.limiters[key] = e
	}
	e.lastSeen = now

	// Best-effort GC every ~256 hits.
	if len(m.limiters) > 256 {
		for k, v := range m.limiters {
			if now.Sub(v.lastSeen) > 10*time.Minute {
				delete(m.limiters, k)
			}
		}
	}
	return e.limiter.AllowN(now, 1)
}

// procedureRule binds a procedure to the bucket configuration it consumes.
type procedureRule struct {
	kindIP    string
	kindEmail string // empty when the procedure has no email body
	ipPerMin  func(c config.RateLimits) uint32
	emailPer  func(c config.RateLimits) (perMin uint32, isPerHour bool)
}

func (r procedureRule) ipKey(ip string) string    { return r.kindIP + ":" + ip }
func (r procedureRule) emailKey(em string) string { return r.kindEmail + ":" + strings.ToLower(em) }

func (r procedureRule) ipLimit(c config.RateLimits) (perMin uint32, burst int) {
	if r.ipPerMin == nil {
		return 0, 0
	}
	v := r.ipPerMin(c)
	burst = max(int(v), 1)
	return v, burst
}

func (r procedureRule) emailLimit(c config.RateLimits) (perMin uint32, burst int) {
	if r.emailPer == nil || r.kindEmail == "" {
		return 0, 0
	}
	v, perHour := r.emailPer(c)
	if perHour {
		// Hour-scoped limit: a small per-minute equivalent with a generous
		// burst so the first few attempts go through immediately and the
		// hour cap is enforced over the long tail.
		perMin = v / 60
		if perMin == 0 {
			perMin = 1
		}
		burst = int(v)
	} else {
		perMin = v
		burst = int(v)
	}
	if burst < 1 {
		burst = 1
	}
	return perMin, burst
}

// proceduresWithRateLimit maps a fully-qualified procedure to its rule.
// Anything not listed here is unmetered.
var proceduresWithRateLimit = map[string]procedureRule{
	"/oblivio.v1.AuthService/Authorize": {
		kindIP:    "auth_login_ip",
		kindEmail: "auth_login_email",
		ipPerMin:  func(c config.RateLimits) uint32 { return c.AuthLoginPerIPPerMin },
		emailPer:  func(c config.RateLimits) (uint32, bool) { return c.AuthLoginPerEmailPerMin, false },
	},
	"/oblivio.v1.AuthService/GetKDFParams": {
		kindIP:   "kdf_params_ip",
		ipPerMin: func(c config.RateLimits) uint32 { return c.KDFParamsPerIPPerMin },
	},
	"/oblivio.v1.AuthService/GetRecoveryParams": {
		kindIP:   "kdf_params_ip",
		ipPerMin: func(c config.RateLimits) uint32 { return c.KDFParamsPerIPPerMin },
	},
	"/oblivio.v1.AuthService/RecoveryStart": {
		kindIP:    "recovery_ip",
		kindEmail: "recovery_email",
		ipPerMin:  func(c config.RateLimits) uint32 { return c.AuthLoginPerIPPerMin },
		emailPer:  func(c config.RateLimits) (uint32, bool) { return c.AuthLoginPerEmailPerMin, false },
	},
	"/oblivio.v1.AuthService/Register": {
		kindIP:   "register_ip",
		ipPerMin: func(c config.RateLimits) uint32 { return c.RegisterPerIPPerHour / 60 }, // amortised
		emailPer: nil,
	},
}

// peekEmail reads the request body, tries to extract an email field, and
// returns it alongside the consumed bytes. ConnectRPC ships JSON, protobuf
// and gRPC framings on the same endpoint; we only attempt the cheap JSON
// path here. Anything else just bypasses the per-email check.
func peekEmail(r *http.Request) (string, []byte, bool) {
	if r.Body == nil {
		return "", nil, false
	}
	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		return "", nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		return "", body, false
	}
	_ = r.Body.Close()
	var probe struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", body, true
	}
	return probe.Email, body, true
}

// clientIP extracts the best-guess remote address. We trust X-Forwarded-For
// only when the request comes from a loopback/private peer — otherwise an
// attacker on the open internet could spoof the header to evade the limiter.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if isTrustedProxy(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if rip := r.Header.Get("X-Real-IP"); rip != "" {
			return strings.TrimSpace(rip)
		}
	}
	return host
}

func isTrustedProxy(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, cidr := range trustedProxyNets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

var trustedProxyNets = func() []*net.IPNet {
	// RFC1918 private ranges + loopback + link-local. Same-host reverse
	// proxies typically live inside one of these.
	out := []*net.IPNet{}
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func tooMany(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(msg))
}
