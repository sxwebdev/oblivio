package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"text/template"

	"github.com/goccy/go-yaml"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/templates"
	"github.com/sxwebdev/xconfig"
	"github.com/sxwebdev/xconfig/plugins/env"
	"github.com/urfave/cli/v3"
)

func cfgPathsFlag() *cli.StringSliceFlag {
	return &cli.StringSliceFlag{
		Name:    "config",
		Aliases: []string{"c"},
		Usage:   "path(s) to configuration files",
	}
}

func configCMD() *cli.Command {
	return &cli.Command{
		Name:  "config",
		Usage: "configuration utilities",
		Commands: []*cli.Command{
			{
				Name:  "genenvs",
				Usage: "generate config yaml template and ENVS.md",
				Action: func(_ context.Context, cl *cli.Command) error {
					conf := &config.Config{}

					if _, err := xconfig.Load(conf, xconfig.WithEnvPrefix(envPrefix)); err != nil {
						return fmt.Errorf("failed to load defaults: %w", err)
					}

					buf := bytes.NewBuffer(nil)
					enc := yaml.NewEncoder(buf, yaml.Indent(2))
					if err := enc.Encode(conf); err != nil {
						return fmt.Errorf("failed to encode yaml: %w", err)
					}
					if err := enc.Close(); err != nil {
						return fmt.Errorf("failed to close encoder: %w", err)
					}

					if err := os.WriteFile("config.template.yaml", buf.Bytes(), 0o600); err != nil {
						return fmt.Errorf("failed to write file: %w", err)
					}

					vaultMarkdown, err := xconfig.GenerateMarkdown(new(config.VaultConfig))
					if err != nil {
						return fmt.Errorf("failed to generate vault markdown: %w", err)
					}

					envMarkdown, err := xconfig.GenerateMarkdown(
						conf,
						xconfig.WithEnvPrefix(envPrefix),
						xconfig.WithPlugins(env.New(envPrefix)),
					)
					if err != nil {
						return fmt.Errorf("failed to generate env markdown: %w", err)
					}

					output := new(bytes.Buffer)
					cl.Root().Writer = output
					if err := cli.ShowAppHelp(cl.Root()); err != nil {
						return err
					}

					tmpl, err := template.ParseFS(templates.EnvsFS, "ENVS.go.tmpl")
					if err != nil {
						return err
					}

					data := struct {
						VaultEnvironments string
						AppEnvironments   string
					}{
						VaultEnvironments: vaultMarkdown,
						AppEnvironments:   envMarkdown,
					}

					buf = bytes.NewBuffer(nil)
					if err := tmpl.ExecuteTemplate(buf, "envs", data); err != nil {
						return err
					}

					if err := os.WriteFile("ENVS.md", buf.Bytes(), 0o600); err != nil {
						return err
					}

					return nil
				},
			},
		},
	}
}
