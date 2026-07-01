// Package middleware: rate limiter for sensitive anonymous endpoints.
//
// Buckets live in Postgres (table `rate_limit_buckets`) so two server
// instances behind a load balancer share one set of counters. Each
// Allow() call performs a single INSERT ... ON CONFLICT DO UPDATE that
// atomically refills and consumes one token — see
// sql/queries/rate_limit_buckets/rate_limit_buckets.sql.
//
// The limiter is wired as an HTTP middleware (NOT a Connect interceptor) so
// it can see the client IP — the interceptor surface only exposes the
// ConnectRPC request, not net/http.Request. For per-email rate limiting we
// decode the protobuf body lazily and key on email when the procedure carries
// one (rate_limit_email.go).
//
// Failure mode: when the database is unreachable the limiter fails OPEN
// (returns true). The trade-off is that a DB outage doesn't lock everyone
// out; rate-limit metrics surface the spike so operators see what happened.
package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/metrics"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_rate_limit_buckets"
)

// RateLimitMiddleware applies per-IP and per-email token-bucket limits to
// anonymous authentication procedures. A request that exceeds any bucket is
// rejected with 429 Too Many Requests; the response body is plain text so
// it shows up in browser network logs without protobuf decoding.
type RateLimitMiddleware struct {
	cfg  config.RateLimits
	repo *repo_rate_limit_buckets.Queries
}

// NewRateLimitMiddleware constructs the middleware. `repo` is required —
// the in-memory variant has been retired in favour of Postgres-backed
// buckets so multi-instance deploys share state.
func NewRateLimitMiddleware(cfg config.RateLimits, repo *repo_rate_limit_buckets.Queries) *RateLimitMiddleware {
	return &RateLimitMiddleware{cfg: cfg, repo: repo}
}

// Wrap installs the per-IP HTTP-layer middleware. Per-email checks live in
// a separate ConnectRPC interceptor (rate_limit_email.go) because the
// browser ships protobuf-framed bodies and we don't want to write a
// content-type-aware peek for every framing.
func (m *RateLimitMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		procedure := procedureFromPath(r.URL.Path)
		rule, ok := proceduresWithRateLimit[procedure]
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		ip := clientIP(r)
		ipLimit, ipBurst := rule.ipLimit(m.cfg)
		if ipLimit > 0 && !m.Allow(r.Context(), rule.ipKey(ip), ipLimit, ipBurst) {
			metrics.RateLimitDropsTotal.WithLabelValues(procedure, "ip").Inc()
			tooMany(w, "rate limit exceeded (ip)")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Cfg returns the configured limits — used by the email interceptor that
// shares this middleware's bucket pool.
func (m *RateLimitMiddleware) Cfg() config.RateLimits { return m.cfg }

// Allow returns true if a token is available for the given key. `key` must
// be in "kind:identifier" form; the colon split is required to keep the
// table's primary key columns distinct.
//
// The DB function returns the bucket's token count AFTER decrement: a
// non-negative value means the request was allowed, a negative value means
// it was denied.
func (m *RateLimitMiddleware) Allow(ctx context.Context, key string, perMin uint32, burst int) bool {
	if perMin == 0 {
		return true
	}
	kind, ident, ok := splitBucketKey(key)
	if !ok {
		// Malformed key — treat as misconfigured limiter and let the
		// request through rather than 500-storming legitimate traffic.
		return true
	}
	// Cap the DB call so a slow Postgres doesn't stall the request thread.
	subCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	ratePerSec := float64(perMin) / 60.0
	tokens, err := m.repo.ConsumeRateLimit(subCtx, repo_rate_limit_buckets.ConsumeRateLimitParams{
		Kind:       kind,
		Key:        ident,
		Burst:      float64(burst),
		RatePerSec: ratePerSec,
	})
	if err != nil {
		// Fail open: a DB outage must not lock every user out of login.
		// The error is observable via the metrics counter and DB logs.
		metrics.RateLimitDropsTotal.WithLabelValues("db_error", "ip").Inc()
		return true
	}
	return tokens >= 0
}

// splitBucketKey turns "kind:identifier" into its parts. Returns ok=false
// for malformed input (no colon, empty kind, or empty identifier).
func splitBucketKey(s string) (kind, ident string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
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
	"/oblivio.v1.AuthService/CompleteMFA": {
		kindIP:   "mfa_complete_ip",
		ipPerMin: func(c config.RateLimits) uint32 { return c.CompleteMFAPerIPPerMin },
	},
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
