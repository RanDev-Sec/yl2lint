package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"yl2lint/internal/config"
	"yl2lint/internal/linter"
	"yl2lint/internal/linter/rules"
	"yl2lint/internal/printer"
	"yl2lint/internal/runner"
)

var (
	flagFix         bool
	flagInteractive bool
)

func init() {
	lintCmd.Flags().BoolVar(&flagFix, "fix", false,
		"automatically inject missing required meta keys (from .yl2lint.yaml) with TODO placeholders and write the file")
	lintCmd.Flags().BoolVar(&flagInteractive, "interactive", false,
		"like --fix, but ask before adding each missing meta field")
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

	sum := printer.Print(os.Stdout, results)
	if sum.Errors > 0 || sum.ReadFailures > 0 {
		os.Exit(1)
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

		fmt.Printf("%s  %s  %s\n", id.Sprint(linter.SyntaxRuleID), name.Sprint("syntax"),
			"structural validation performed by the parser (brackets, section headers, meta grammar)")
		for _, r := range linter.NewEngine(cfg, rules.All()).Rules() {
			fmt.Printf("%s  %s  %s\n", id.Sprint(r.ID()), name.Sprint(r.Name()), r.Description())
		}
		return nil
	},
}