package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"yl2lint/internal/config"
	"yl2lint/internal/format"
)

var flagForce bool

var createCmd = &cobra.Command{
	Use:   "create <filename.yaral>",
	Short: "Scaffold a new YARA-L 2.0 rule file with the meta fields required by .yl2lint.yaml",
	Args:  cobra.ExactArgs(1),
	RunE:  runCreate,
}

func init() {
	createCmd.Flags().BoolVarP(&flagForce, "force", "f", false, "overwrite the file if it already exists")
	rootCmd.AddCommand(createCmd)
}

func runCreate(cmd *cobra.Command, args []string) error {
	path := args[0]
	if !strings.EqualFold(filepath.Ext(path), ".yaral") {
		path += ".yaral"
	}
	if _, err := os.Stat(path); err == nil && !flagForce {
		return fmt.Errorf("%s already exists (use --force to overwrite)", path)
	}

	// The required meta fields come from the same policy YL002 enforces, so a
	// freshly scaffolded rule always lints clean on YL002 (modulo TODOs).
	cfg, cfgFile, err := config.Load(flagConfig)
	if err != nil {
		return err
	}

	src := scaffold(ruleNameFromPath(path), cfg.Meta.RequiredKeys)

	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		return err
	}

	faint := color.New(color.Faint)
	if cfgFile != "" {
		faint.Fprintf(os.Stdout, "config: %s\n", cfgFile)
	}
	fmt.Printf("created %s\n", path)
	return nil
}

// scaffold renders the boilerplate rule body.
func scaffold(name string, requiredKeys []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "rule %s {\n", name)

	b.WriteString("  meta:\n")
	if len(requiredKeys) == 0 {
		fmt.Fprintf(&b, "    description = %q\n", format.Placeholder)
	}
	for _, k := range requiredKeys {
		fmt.Fprintf(&b, "    %s = %q\n", k, format.Placeholder)
	}

	b.WriteString("\n  events:\n")
	b.WriteString("    // Base event filter: keep this to avoid unindexed full scans (YL007).\n")
	b.WriteString("    $e.metadata.event_type = \"TODO_EVENT_TYPE\"\n")
	b.WriteString("\n  condition:\n")
	b.WriteString("    $e\n")
	b.WriteString("}\n")
	return b.String()
}

// ruleNameFromPath derives a valid rule identifier from the file name.
func ruleNameFromPath(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	var b strings.Builder
	for i := 0; i < len(base); i++ {
		c := base[i]
		switch {
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	name := b.String()
	if name == "" || (name[0] >= '0' && name[0] <= '9') {
		name = "rule_" + name
	}
	return name
}