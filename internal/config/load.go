package config

import (
	"context"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/sxwebdev/xconfig"
	"github.com/sxwebdev/xconfig/decoders/xconfigdotenv"
	"github.com/sxwebdev/xconfig/decoders/xconfigyaml"
	"github.com/sxwebdev/xconfig/plugins"
	"github.com/sxwebdev/xconfig/plugins/loader"
	"github.com/sxwebdev/xconfig/plugins/validate"
	"github.com/sxwebdev/xconfig/sourcers/xconfigvault"
	"github.com/tkcrm/mx/logger"
)

// VaultConfig holds HashiCorp Vault configuration.
// Loaded from optional vault.env file + global environment variables.
type VaultConfig struct {
	Enabled         bool          `env:"VAULT_ENABLED"`
	Address         string        `env:"VAULT_ADDR" validate:"required_if=Enabled true"`
	SecretPath      string        `env:"VAULT_SECRET_PATH" validate:"required_if=Enabled true"`
	KubeRole        string        `env:"VAULT_KUBE_ROLE" validate:"required_if=Enabled true AuthKind kubernetes"`
	KubeJWTPath     string        `env:"VAULT_KUBE_JWT_PATH" validate:"required_if=Enabled true AuthKind kubernetes"`
	KubeMountPath   string        `env:"VAULT_KUBE_MOUNT_PATH" validate:"required_if=Enabled true AuthKind kubernetes" default:"kubernetes"`
	AuthKind        string        `env:"VAULT_AUTH_KIND" default:"kubernetes" example:"kubernetes,token"`
	Token           string        `env:"VAULT_TOKEN" validate:"required_if=Enabled true AuthKind token"`
	RefreshInterval time.Duration `env:"VAULT_REFRESH_INTERVAL" default:"20s"`
}

// LoadResult holds the result of loading configuration.
type LoadResult struct {
	XConfig     xconfig.Config
	Cleanup     func()
	Vault       VaultConfig
	VaultClient *xconfigvault.Client
}

// Load reads and parses the configuration file.
func Load(
	ctx context.Context,
	lg logger.ExtendedLogger,
	conf *Config,
	envPrefix string,
	configPaths []string,
) (*LoadResult, error) {
	v := validator.New()
	validatePlugin := validate.New(func(a any) error {
		return v.Struct(a)
	})

	// Load VaultConfig from optional .env file + global env vars
	vaultLoader, err := loader.NewLoader(map[string]loader.Unmarshal{
		"env": xconfigdotenv.New().Unmarshal,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create vault loader: %w", err)
	}
	if err := vaultLoader.AddFile(".env", true); err != nil {
		return nil, fmt.Errorf("failed to add .env: %w", err)
	}

	var vaultCfg VaultConfig
	if _, err := xconfig.Load(&vaultCfg,
		xconfig.WithSkipFlags(),
		xconfig.WithLoader(vaultLoader),
		xconfig.WithPlugins(validatePlugin),
	); err != nil {
		return nil, fmt.Errorf("failed to load vault config: %w", err)
	}

	// Load main config from YAML files
	l, err := loader.NewLoader(map[string]loader.Unmarshal{
		"yaml": xconfigyaml.New().Unmarshal,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create config loader: %w", err)
	}
	if err := l.AddFiles(configPaths, true); err != nil {
		return nil, fmt.Errorf("failed to add config files: %w", err)
	}

	result := &LoadResult{
		Cleanup: func() {},
		Vault:   vaultCfg,
	}

	userPlugins := make([]plugins.Plugin, 0, 2)

	if vaultCfg.Enabled {
		var vaultAuth xconfigvault.AuthMethod
		switch vaultCfg.AuthKind {
		case "kubernetes":
			vaultAuth = xconfigvault.WithKubernetesPath(vaultCfg.KubeRole, vaultCfg.KubeJWTPath, vaultCfg.KubeMountPath)
		case "token":
			vaultAuth = xconfigvault.WithToken(vaultCfg.Token)
		default:
			return nil, fmt.Errorf("unsupported vault auth kind: %s", vaultCfg.AuthKind)
		}

		client, err := xconfigvault.New(ctx, &xconfigvault.Config{
			Address:    vaultCfg.Address,
			Auth:       vaultAuth,
			SecretPath: vaultCfg.SecretPath,
			Metrics: xconfigvault.MetricsFunc(func(e xconfigvault.Event) {
				keysAndValues := []any{
					"type", string(e.Type),
				}

				if e.Message != "" {
					keysAndValues = append(keysAndValues, "message", e.Message)
				}

				if e.Error != nil {
					keysAndValues = append(
						keysAndValues,
						"error", e.Error,
						"attempt", e.Attempt,
					)
				}

				lg.Infow("vault event", keysAndValues...)
			}),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create vault client: %w", err)
		}

		result.VaultClient = client
		result.Cleanup = func() {
			if err := client.Close(); err != nil {
				lg.Errorw("failed to close vault client", "error", err)
			}
		}
		userPlugins = append(userPlugins, client.Plugin(ctx))
	}

	userPlugins = append(userPlugins, validatePlugin)

	xc, err := xconfig.Load(conf,
		xconfig.WithSkipFlags(),
		xconfig.WithDisallowUnknownFields(),
		xconfig.WithEnvPrefix(envPrefix),
		xconfig.WithLoader(l),
		xconfig.WithPlugins(userPlugins...),
	)
	if err != nil {
		result.Cleanup()
		return nil, fmt.Errorf("failed to load main config: %w", err)
	}

	result.XConfig = xc
	return result, nil
}
