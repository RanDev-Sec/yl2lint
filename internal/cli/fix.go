package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/format"
	"yl2lint/internal/parser"
	"yl2lint/internal/runner"
)

// autofixMeta walks every target file, computes which required meta keys are
// missing per rule, and injects `key = "TODO"` placeholders — automatically
// under --fix, or after a per-field [Y/n] prompt under --interactive.
// Files are processed sequentially so prompts never interleave.
func autofixMeta(target string, cfg *config.Config) error {
	required := cfg.Meta.RequiredKeys
	if len(required) == 0 {
		return nil
	}

	paths, err := runner.Collect(target)
	if err != nil {
		return err
	}

	in := bufio.NewReader(os.Stdin)
	faint := color.New(color.Faint)

	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		file, _ := parser.Parse(src) // parser recovers; fix whatever tree exists

		var fixes []format.MetaFix
		for _, r := range file.Rules {
			missing := missingMetaKeys(r, required)
			if len(missing) == 0 {
				continue
			}
			if flagInteractive {
				var accepted []string
				for _, k := range missing {
					fmt.Printf("%s: rule %q: add missing field %q? [Y/n] ", path, displayRuleName(r), k)
					line, _ := in.ReadString('\n')
					switch strings.ToLower(strings.TrimSpace(line)) {
					case "", "y", "yes":
						accepted = append(accepted, k)
					}
				}
				missing = accepted
			}
			if len(missing) > 0 {
				fixes = append(fixes, format.MetaFix{Rule: r, Keys: missing})
			}
		}
		if len(fixes) == 0 {
			continue
		}

		out, changed := format.InjectMetaKeys(src, fixes)
		if !changed {
			continue
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
		faint.Fprintf(os.Stdout, "fixed: %s\n", path)
	}
	return nil
}

func missingMetaKeys(r *ast.YaraLRule, required []string) []string {
	have := map[string]bool{}
	if r.Meta != nil {
		for _, e := range r.Meta.Entries {
			have[e.Key] = true
		}
	}
	var missing []string
	for _, k := range required {
		if !have[k] {
			missing = append(missing, k)
		}
	}
	return missing
}

func displayRuleName(r *ast.YaraLRule) string {
	if r.Name == "" {
		return "<unnamed>"
	}
	return r.Name
}