// internal/cli/lint.go
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"yl2lint/internal/config"
	"yl2lint/internal/linter"
	"yl2lint/internal/linter/rules"
	"yl2lint/internal/printer"
	"yl2lint/internal/runner"
	"yl2lint/internal/schema"
)

var (
	flagFix         bool
	flagInteractive bool
	flagFormat      string
)

func init() {
	lintCmd.Flags().BoolVar(&flagFix, "fix", false,
		"automatically inject missing required meta keys (from .yl2lint.yaml) with TODO placeholders and write the file")
	lintCmd.Flags().BoolVar(&flagInteractive, "interactive", false,
		"like --fix, but ask before adding each missing meta field")
	lintCmd.Flags().StringVar(&flagFormat, "format", "full",
		"output format: full (per-file listing), summary (counts by rule, then worst files), compact (one line per finding), json")
}

var lintCmd = &cobra.Command{
	Use:   "lint <file.yaral | directory>",
	Short: "Lint a YARA-L 2.0 file, or recursively lint every .yaral file in a directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runLint,
}

func runLint(cmd *cobra.Command, args []string) error {
	if flagNoColor {
		color.NoColor = true
	}

	cfg, cfgFile, err := config.Load(flagConfig)
	if err != nil {
		return err
	}

	if cfg.Schema.Path != "" {
		p := cfg.Schema.Path
		if !filepath.IsAbs(p) && cfgFile != "" {
			p = filepath.Join(filepath.Dir(cfgFile), p)
		}
		if err := schema.LoadExtra(p, cfg.Schema.Replace); err != nil {
			return err
		}
	}

	if flagFix || flagInteractive {
		if err := autofixMeta(args[0], cfg); err != nil {
			return err
		}
	}

	eng := linter.NewEngine(cfg, rules.All())

	workers := flagWorkers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	results, err := runner.Run(args[0], eng, workers)
	if err != nil {
		return err
	}

	if cfgFile != "" {
		faint := color.New(color.Faint)
		faint.Fprintf(os.Stdout, "config: %s\n\n", cfgFile)
	}

	switch flagFormat {
	case "full":
		printer.Print(os.Stdout, results)
	case "summary":
		printer.PrintSummary(os.Stdout, results)
	case "compact":
		printer.PrintCompact(os.Stdout, results)
	case "json":
		if err := printer.PrintJSON(os.Stdout, results); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown --format %q: want full, summary, compact, or json", flagFormat)
	}

	exitCode := 0
	for _, res := range results {
		if res.Err != nil {
			exitCode = 2
			continue
		}
		for _, v := range res.Violations {
			if v.Severity == linter.Error {
				exitCode = 1
			}
		}
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List the lint rules that would run with the current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		if flagNoColor {
			color.NoColor = true
		}
		cfg, _, err := config.Load(flagConfig)
		if err != nil {
			return err
		}
		id := color.New(color.Bold)
		name := color.New(color.FgCyan)

		type ruleInfo struct{ id, name, desc string }
		var infos []ruleInfo

		for _, r := range []ruleInfo{
			{linter.SyntaxRuleID, linter.SyntaxRuleName, "structural validity: braces, section headers, meta grammar, required sections"},
			{linter.DirectiveRuleID, linter.DirectiveRuleName, "suppression directives that are malformed or name unknown rules"},
			{linter.WorkspaceDupRuleID, linter.WorkspaceDupRuleName, "cross-file check: rule names must be unique across the lint target"},
		} {
			if !cfg.IsDisabled(r.id, r.name) {
				infos = append(infos, r)
			}
		}

		for _, r := range rules.All() {
			if cfg.IsDisabled(r.ID(), r.Name()) {
				continue
			}
			infos = append(infos, ruleInfo{r.ID(), r.Name(), r.Description()})
		}

		sort.Slice(infos, func(i, j int) bool { return infos[i].id < infos[j].id })

		for _, ri := range infos {
			fmt.Printf("%s  %s  %s\n", id.Sprint(ri.id), name.Sprint(ri.name), ri.desc)
		}
		return nil
	},
}
