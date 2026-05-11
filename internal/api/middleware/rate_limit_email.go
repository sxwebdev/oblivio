// Per-email rate limiting for AuthService. The HTTP-side RateLimitMiddleware
// can't reliably read the email field — ConnectRPC ships protobuf, JSON or
// gRPC framings on the same endpoint and the browser defaults to protobuf,
// which the JSON peek skipped. This interceptor runs AFTER deserialisation
// so it can read req.Email directly from the parsed struct regardless of
// content-type.
//
// The interceptor shares the same in-memory bucket pool as the HTTP
// middleware via RateLimitMiddleware.Allow — so an email-bound bucket and
// the corresponding ip-bound bucket are accounted against a single source
// of truth (no double-counting, no drift).

package middleware

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"

	pb "github.com/sxwebdev/oblivio/internal/api/gen/go/oblivio/v1"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/metrics"
)

// NewEmailRateLimitInterceptor returns a Connect unary interceptor that
// enforces per-email quotas on AuthService procedures that accept an email.
// Procedures not in the map are passed through.
func NewEmailRateLimitInterceptor(rl *RateLimitMiddleware) connect.UnaryInterceptorFunc {
	cfg := rl.Cfg()
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure
			rule, ok := proceduresWithEmailRateLimit[procedure]
			if !ok {
				return next(ctx, req)
			}
			email := strings.ToLower(strings.TrimSpace(extractEmail(req)))
			if email == "" {
				return next(ctx, req)
			}
			perMin, burst := rule.emailLimit(cfg)
			if perMin == 0 {
				return next(ctx, req)
			}
			if !rl.Allow(rule.kindEmail+":"+email, perMin, burst) {
				metrics.RateLimitDropsTotal.WithLabelValues(procedure, "email").Inc()
				return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("rate limit exceeded for this email"))
			}
			return next(ctx, req)
		}
	}
}

// proceduresWithEmailRateLimit mirrors the email-side procedureRule lookup
// — only listed procedures get an email-bucket check.
var proceduresWithEmailRateLimit = map[string]procedureRule{
	"/oblivio.v1.AuthService/Authorize": {
		kindEmail: "auth_login_email",
		emailPer:  func(c config.RateLimits) (uint32, bool) { return c.AuthLoginPerEmailPerMin, false },
	},
	"/oblivio.v1.AuthService/RecoveryStart": {
		kindEmail: "recovery_email",
		emailPer:  func(c config.RateLimits) (uint32, bool) { return c.AuthLoginPerEmailPerMin, false },
	},
	"/oblivio.v1.AuthService/GetKDFParams": {
		kindEmail: "kdf_params_email",
		// Reuse the per-IP limit as a generous per-email cap so a single
		// account-enum spray doesn't trivially saturate the IP bucket.
		emailPer: func(c config.RateLimits) (uint32, bool) { return c.KDFParamsPerIPPerMin, false },
	},
	"/oblivio.v1.AuthService/GetRecoveryParams": {
		kindEmail: "recovery_email",
		emailPer:  func(c config.RateLimits) (uint32, bool) { return c.KDFParamsPerIPPerMin, false },
	},
	"/oblivio.v1.AuthService/ResendVerification": {
		// Re-issuing verification links is cheap server-side but a vector
		// for spamming the recipient's inbox. Cap at the same per-email
		// rate as the login-side checks.
		kindEmail: "resend_verification_email",
		emailPer:  func(c config.RateLimits) (uint32, bool) { return c.AuthLoginPerEmailPerMin, false },
	},
}

// extractEmail pulls the email field from the parsed request body of an
// AuthService procedure. Returns "" for procedures we don't know about.
func extractEmail(req connect.AnyRequest) string {
	switch m := req.Any().(type) {
	case *pb.AuthorizeRequest:
		return m.GetEmail()
	case *pb.GetKDFParamsRequest:
		return m.GetEmail()
	case *pb.GetRecoveryParamsRequest:
		return m.GetEmail()
	case *pb.RecoveryStartRequest:
		return m.GetEmail()
	case *pb.ResendVerificationRequest:
		return m.GetEmail()
	default:
		return ""
	}
}
