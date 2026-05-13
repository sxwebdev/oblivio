// covgate parses a Go cover profile and enforces per-package coverage
// thresholds. Failing a threshold exits non-zero so CI blocks the merge.
//
// Usage:
//
//	covgate -profile coverage.out -config testdata/coverage.yaml
//
// Config format is intentionally tiny — a YAML file with one entry per
// rule. Each rule selects packages by prefix and asserts a minimum
// statement-coverage percentage:
//
//	rules:
//	  - prefix: github.com/sxwebdev/oblivio/internal/crypto
//	    min:    95
//	  - prefix: github.com/sxwebdev/oblivio/internal/auth
//	    min:    85
//	default_min: 0
//
// The tool ignores the rest of cover.go's machinery — it works directly
// off the textual profile so it has no test-time dependency.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

type rule struct {
	Prefix string  `yaml:"prefix"`
	Min    float64 `yaml:"min"`
}

type config struct {
	Rules      []rule  `yaml:"rules"`
	DefaultMin float64 `yaml:"default_min"`
}

type pkgCov struct {
	total   int
	covered int
}

func (p pkgCov) percent() float64 {
	if p.total == 0 {
		return 100.0
	}
	return 100.0 * float64(p.covered) / float64(p.total)
}

func main() {
	profile := flag.String("profile", "coverage.out", "path to go test cover profile")
	configPath := flag.String("config", "coverage.yaml", "thresholds config (YAML)")
	verbose := flag.Bool("v", false, "print per-package coverage even on success")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	coverage, err := parseProfile(*profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	pkgs := make([]string, 0, len(coverage))
	for k := range coverage {
		pkgs = append(pkgs, k)
	}
	sort.Strings(pkgs)

	failed := 0
	for _, pkg := range pkgs {
		cov := coverage[pkg]
		min, src := matchRule(pkg, cfg)
		got := cov.percent()
		ok := got >= min
		if *verbose || !ok {
			marker := "OK"
			if !ok {
				marker = "FAIL"
			}
			fmt.Fprintf(os.Stderr, "%-50s  %5.1f%% (min %5.1f%% from %s) %s\n",
				pkg, got, min, src, marker)
		}
		if !ok {
			failed++
		}
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d package(s) below coverage threshold\n", failed)
		os.Exit(1)
	}
}

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	// Sort rules by prefix length desc so a more-specific prefix wins.
	sort.Slice(cfg.Rules, func(i, j int) bool {
		return len(cfg.Rules[i].Prefix) > len(cfg.Rules[j].Prefix)
	})
	return &cfg, nil
}

func parseProfile(path string) (map[string]pkgCov, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	out := map[string]pkgCov{}
	s := bufio.NewScanner(f)
	first := true
	for s.Scan() {
		line := s.Text()
		if first {
			// Header: "mode: <set|count|atomic>". Skip it.
			first = false
			if strings.HasPrefix(line, "mode:") {
				continue
			}
		}
		// Each line: <pkg>/<file>:<startLine>.<startCol>,<endLine>.<endCol> <statements> <count>
		spaceA := strings.LastIndex(line, " ")
		if spaceA < 0 {
			continue
		}
		spaceB := strings.LastIndex(line[:spaceA], " ")
		if spaceB < 0 {
			continue
		}
		stmts, err := strconv.Atoi(line[spaceB+1 : spaceA])
		if err != nil {
			continue
		}
		count, err := strconv.Atoi(line[spaceA+1:])
		if err != nil {
			continue
		}
		// File ref ends at ":<line>"; the package is everything up to the
		// last "/" of the file path.
		filePart := line[:spaceB]
		before, _, ok := strings.Cut(filePart, ":")
		if !ok {
			continue
		}
		path := before
		slash := strings.LastIndex(path, "/")
		if slash < 0 {
			continue
		}
		pkg := path[:slash]
		cov := out[pkg]
		cov.total += stmts
		if count > 0 {
			cov.covered += stmts
		}
		out[pkg] = cov
	}
	return out, s.Err()
}

func matchRule(pkg string, cfg *config) (float64, string) {
	for _, r := range cfg.Rules {
		if strings.HasPrefix(pkg, r.Prefix) {
			return r.Min, r.Prefix
		}
	}
	return cfg.DefaultMin, "default"
}
