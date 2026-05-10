package config

import (
	"net"
	"net/url"
	"time"

	"github.com/tkcrm/mx/launcher/ops"
	"github.com/tkcrm/mx/logger"
)

// Config is the root configuration for the oblivio service.
type Config struct {
	Log      logger.Config
	Ops      ops.Config
	Server   ServerConfig
	Postgres PostgresConfig
	Auth     AuthConfig
	WebAuthn WebAuthnConfig
	Jobs     JobsConfig
	Email    EmailConfig
}

// ServerConfig holds HTTP/ConnectRPC server settings.
type ServerConfig struct {
	Addr           string   `yaml:"addr" validate:"required" default:":8080"`
	AllowedOrigins []string `yaml:"allowed_origins"`
	TLS            TLSConfig
}

// TLSConfig optionally enables TLS termination at the application layer.
// When empty, the server runs plain HTTP (intended for reverse-proxy setups).
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// PostgresConfig describes the connection to the application database.
type PostgresConfig struct {
	Host     string `validate:"required" default:"localhost"`
	Port     string `validate:"required" default:"5432"`
	Database string `validate:"required"`
	Username string `validate:"required" vault:"true" secret:"true"`
	Password string `validate:"required" vault:"true" secret:"true"`
	SSLMode  string `yaml:"ssl_mode" default:"disable"`
}

// DSN returns a pgx v5 compatible connection URL.
func (c PostgresConfig) DSN() string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.Username, c.Password),
		Host:     net.JoinHostPort(c.Host, c.Port),
		Path:     c.Database,
		RawQuery: url.Values{"sslmode": {c.SSLMode}}.Encode(),
	}
	return u.String()
}

// AuthConfig holds authentication settings.
// Token signing secrets are loaded from Vault or generated on first run.
type AuthConfig struct {
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl" default:"20m"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" default:"720h"`

	AccessTokenSecretKey  string `yaml:"access_token_secret_key" vault:"true" secret:"true" usage:"signing key for access tokens; generated if empty"`
	RefreshTokenSecretKey string `yaml:"refresh_token_secret_key" vault:"true" secret:"true" usage:"signing key for refresh tokens; generated if empty"`

	Argon2Server Argon2Params `yaml:"argon2_server"`
	RateLimits   RateLimits   `yaml:"rate_limits"`
}

// Argon2Params parameterises server-side Argon2id over auth_key.
// Per plan §4.2: t=3, m=64 MiB, p=1.
type Argon2Params struct {
	T    uint32 `yaml:"t" default:"3"`
	MKiB uint32 `yaml:"m_kib" default:"65536"`
	P    uint8  `yaml:"p" default:"1"`
}

// RateLimits bounds anonymous and per-user request rates on sensitive endpoints.
type RateLimits struct {
	AuthLoginPerEmailPerMin uint32 `yaml:"auth_login_per_email_per_min" default:"5"`
	AuthLoginPerIPPerMin    uint32 `yaml:"auth_login_per_ip_per_min" default:"20"`
	KDFParamsPerIPPerMin    uint32 `yaml:"kdf_params_per_ip_per_min" default:"30"`
	RegisterPerIPPerHour    uint32 `yaml:"register_per_ip_per_hour" default:"5"`
}

// WebAuthnConfig configures the relying party for FIDO2/WebAuthn.
type WebAuthnConfig struct {
	RPID     string `yaml:"rp_id"`
	RPName   string `yaml:"rp_name" default:"Oblivio"`
	RPOrigin string `yaml:"rp_origin"`
}

// JobsConfig schedules background workers.
type JobsConfig struct {
	AuditChainVerifyCron string        `yaml:"audit_chain_verify_cron" default:"0 3 * * *"`
	RateLimitGCInterval  time.Duration `yaml:"rate_limit_gc_interval" default:"1h"`
	SessionsGCInterval   time.Duration `yaml:"sessions_gc_interval" default:"1h"`
}

// EmailConfig configures transactional email delivery (verification, recovery).
// When Provider is empty, email features are stubbed out (dev mode).
type EmailConfig struct {
	Provider string     `yaml:"provider"`
	From     string     `yaml:"from"`
	SMTP     SMTPConfig `yaml:"smtp"`
}

// SMTPConfig describes an SMTP relay.
type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     uint16 `yaml:"port" default:"587"`
	Username string `yaml:"username" vault:"true" secret:"true"`
	Password string `yaml:"password" vault:"true" secret:"true"`
}
