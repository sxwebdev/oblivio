package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ApplicationInfo is a gauge that tracks build and runtime information
var ApplicationInfo = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "application_info",
		Help: "build and runtime information",
	},
	[]string{
		"application",
		"version",
		"branch",
		"revision",
		"pipeline_id",
		"start_time",
	},
)

// LoginAttemptsTotal counts authorize attempts by outcome.
// outcome: "success" | "failure" | "mfa_challenge"
var LoginAttemptsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oblivio_login_attempts_total",
		Help: "Authorize attempts grouped by outcome",
	},
	[]string{"outcome"},
)

// RefreshAttemptsTotal counts refresh-token operations by outcome.
// outcome: "success" | "failure"
var RefreshAttemptsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oblivio_refresh_attempts_total",
		Help: "RefreshToken attempts grouped by outcome",
	},
	[]string{"outcome"},
)

// MFAAttemptsTotal counts MFA factor completion attempts.
// factor: "totp" | "webauthn", outcome: "success" | "failure"
var MFAAttemptsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oblivio_mfa_attempts_total",
		Help: "Multi-factor auth attempts grouped by factor and outcome",
	},
	[]string{"factor", "outcome"},
)

// EntryViewsTotal counts encrypted-blob fetches. A spike on this metric is
// the closest server-side signal of "user is decrypting things now" given
// the zero-knowledge design (the server never sees the plaintext itself).
var EntryViewsTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "oblivio_entry_views_total",
		Help: "Successful entry blob fetches (decryption events server-side proxy)",
	},
)

// RateLimitDropsTotal counts requests rejected by the rate limiter.
// procedure: full RPC name; kind: "ip" | "email"
var RateLimitDropsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oblivio_rate_limit_drops_total",
		Help: "Requests rejected by the rate limiter",
	},
	[]string{"procedure", "kind"},
)

// AuditChainVerifyRunsTotal counts how often the periodic chain verifier
// ran and whether it found a tamper.
// outcome: "ok" | "mismatch" | "error"
var AuditChainVerifyRunsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oblivio_audit_chain_verify_runs_total",
		Help: "Audit-chain verification runs grouped by outcome",
	},
	[]string{"outcome"},
)

// AuditChainHeight is a gauge holding the last verified chain length.
// Useful to detect a stalled writer or alarm storms.
var AuditChainHeight = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "oblivio_audit_chain_height",
		Help: "Last verified audit-chain height (max id)",
	},
)

// SessionsTerminatedTotal counts explicit session terminations by source.
// source: "self" | "all_except_current" | "delete_me"
var SessionsTerminatedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oblivio_sessions_terminated_total",
		Help: "Sessions explicitly revoked grouped by source",
	},
	[]string{"source"},
)

type BuildInfo struct {
	Application string
	Version     string
	Branch      string
	Revision    string
	PipelineID  string
}

func Init(info BuildInfo) {
	ApplicationInfo.WithLabelValues(
		info.Application,
		info.Version,
		info.Branch,
		info.Revision,
		info.PipelineID,
		time.Now().UTC().Format(time.RFC3339),
	).Set(1)
}
