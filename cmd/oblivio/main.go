package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/sxwebdev/xconfig"
	"github.com/sxwebdev/xconfig/decoders/xconfigdotenv"
	"github.com/sxwebdev/xconfig/decoders/xconfigyaml"
	"github.com/sxwebdev/xconfig/plugins/loader"
	"github.com/tkcrm/mx/launcher"
	"github.com/tkcrm/mx/logger"
	"github.com/urfave/cli/v3"
)

var (
	appName    = "oblivio"
	version    = "local"
	branch     = "unknown"
	revision   = "unknown"
	pipelineID = "unknown"
	buildDate  = "unknown"
	envPrefix  = "OBLIVIO"
)

func getBuildVersion() string {
	return fmt.Sprintf(
		"version: %s / revision: %s / branch: %s / pipeline ID: %s / build date: %s / go version: %s",
		version,
		revision,
		branch,
		pipelineID,
		buildDate,
		runtime.Version(),
	)
}

func defaultLoggerOpts() []logger.Option {
	return []logger.Option{
		logger.WithAppName(appName),
		logger.WithAppVersion(version),
	}
}

func loadLogger() (logger.ExtendedLogger, error) {
	// Load main config from YAML files
	ld, err := loader.NewLoader(map[string]loader.Unmarshal{
		"yaml": xconfigyaml.New().Unmarshal,
		"env":  xconfigdotenv.New().Unmarshal,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create config loader: %w", err)
	}

	if err := ld.AddFiles([]string{".env", "config.yaml"}, true); err != nil {
		return nil, fmt.Errorf("failed to add config files: %w", err)
	}

	var loggerCfg struct {
		Log logger.Config
	}
	if _, err := xconfig.Load(&loggerCfg,
		xconfig.WithSkipFlags(),
		xconfig.WithLoader(ld),
	); err != nil {
		return nil, fmt.Errorf("failed to load logger config: %w", err)
	}

	return logger.NewExtended(append(defaultLoggerOpts(), logger.WithConfig(loggerCfg.Log))...), nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), launcher.ShutdownSiganl()...)
	defer cancel()

	l, err := loadLogger()
	if err != nil {
		logger.Default().Fatalf("failed to load logger: %s", err)
		os.Exit(1)
	}

	app := &cli.Command{
		Name:    appName,
		Usage:   "Oblivio service",
		Version: getBuildVersion(),
		Suggest: true,
		Commands: []*cli.Command{
			startCMD(),
			configCMD(),
			migrationsCMD(),
			utilsCMD(),
			versionCMD(),
		},
	}

	if err := app.Run(ctx, os.Args); err != nil {
		l.Fatalf("failed to run: %s", err)
	}
}
