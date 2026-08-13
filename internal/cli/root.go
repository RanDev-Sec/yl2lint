// Package cli wires the cobra command tree together.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"yl2lint/internal/config"
)

var (
	flagConfig  string
	flagNoColor bool
	flagWorkers int
)

var rootCmd = &cobra.Command{
	Use:   "yl2lint",
	Short: "A static-analysis linter for Google SecOps YARA-L 2.0 detection rules",
	Long: `yl2lint parses YARA-L 2.0 detection rules into an AST and runs a set of
lint rules over them: syntax validation (YL001), required meta keys driven by
.yl2lint.yaml (YL002), and event-variable lifecycle checks (YL003).`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the CLI. Exit codes: 0 clean (or warnings/info only),
// 1 lint errors found, 2 usage or I/O failure.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "yl2lint:", err)
		os.Exit(2)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagConfig, "config", "c", "",
		"path to a config file (default: ./"+config.DefaultFileName+" if present)")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false,
		"disable colored output")
	rootCmd.PersistentFlags().IntVarP(&flagWorkers, "workers", "w", 0,
		"number of concurrent lint workers (default: number of CPUs)")

	rootCmd.AddCommand(lintCmd)
	rootCmd.AddCommand(rulesCmd)
}
