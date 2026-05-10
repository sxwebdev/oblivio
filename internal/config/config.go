package config

import (
	"net"
	"net/url"

	"github.com/tkcrm/mx/launcher/ops"
	"github.com/tkcrm/mx/logger"
)

type Config struct {
	Log      logger.Config
	Ops      ops.Config
	Server   ServerConfig
	Postgres PostgresConfig
	Auth     AuthConfig
	Jobs     JobsConfig
}

type ServerConfig struct {
	Addr              string `yaml:"addr" validate:"required" default:":8080"`
	ReflectionEnabled bool   `yaml:"reflection_enabled" default:"false"`
}

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
// SecretKeys are auto-generated on first run if empty.
type AuthConfig struct {
	AccessTokenSecretKey  string `yaml:"access_token_secret_key" validate:"required" vault:"true" secret:"true" usage:"randomly generated for signing access tokens"`
	RefreshTokenSecretKey string `yaml:"refresh_token_secret_key" validate:"required" vault:"true" secret:"true" usage:"randomly generated for signing refresh tokens"`
}

// JobsConfig configures the River background job scheduler.
type JobsConfig struct{}
