package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"text/template"

	"github.com/sxwebdev/oblivio/templates"
	"github.com/urfave/cli/v3"
)

func utilsCMD() *cli.Command {
	return &cli.Command{
		Name:  "utils",
		Usage: "custom cli utils",
		Commands: []*cli.Command{
			genReadmeCMD(),
		},
	}
}

func genReadmeCMD() *cli.Command {
	return &cli.Command{
		Name:  "readme",
		Usage: "generate markdown for all envs and config yaml template",
		Action: func(_ context.Context, cl *cli.Command) error {
			output := new(bytes.Buffer)
			cl.Root().Writer = output
			if err := cli.ShowAppHelp(cl.Root()); err != nil {
				return err
			}

			tmpl, err := template.ParseFS(templates.ReadmeFS, "README.go.tmpl")
			if err != nil {
				return err
			}

			data := struct {
				AppName  string
				AppBin   string
				AppUsage string
				AppHelp  string
			}{
				AppName:  strings.ReplaceAll(strings.ToTitle(appName), "-", " "),
				AppBin:   strings.ReplaceAll(appName, "-", "_"),
				AppUsage: cl.Usage,
				AppHelp:  output.String(),
			}

			buf := bytes.NewBuffer(nil)
			if err := tmpl.ExecuteTemplate(buf, "readme", data); err != nil {
				return err
			}

			if err := os.WriteFile("README.md", buf.Bytes(), 0o600); err != nil {
				return err
			}

			return nil
		},
	}
}
