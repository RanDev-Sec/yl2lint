// Package workspace runs cross-file checks that no single-file Rule can
// express. It receives every parsed file in the lint target and returns
// violations keyed by path, which the runner merges into per-file results
// (after passing them through the same inline-suppression filter).
package workspace

import (
	"fmt"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/linter"
)

// Check runs every workspace-level check. Files are expected in path order
// so "first definition wins" is deterministic.
func Check(files []*ast.File, cfg *config.Config) map[string][]linter.Violation {
	out := map[string][]linter.Violation{}
	dupRuleNames(files, cfg, out)
	return out
}

// dupRuleNames (YL014) flags rule names defined more than once across the
// lint target: Chronicle rule names must be unique, and duplicates usually
// mean a copy-paste that was never renamed.
func dupRuleNames(files []*ast.File, cfg *config.Config, out map[string][]linter.Violation) {
	if cfg.IsDisabled(linter.WorkspaceDupRuleID, linter.WorkspaceDupRuleName) {
		return
	}
	sev := linter.SeverityFor(cfg, linter.WorkspaceDupRuleID, linter.WorkspaceDupRuleName, linter.Error)

	type site struct {
		path string
		line int
	}
	first := map[string]site{}

	for _, f := range files {
		for _, r := range f.Rules {
			if r.Name == "" {
				continue // unnamed rules are already YL001 territory
			}
			if prev, dup := first[r.Name]; dup {
				out[f.Path] = append(out[f.Path], linter.Violation{
					RuleID:   linter.WorkspaceDupRuleID,
					RuleName: linter.WorkspaceDupRuleName,
					File:     f.Path,
					Pos:      r.NamePos,
					Severity: sev,
					Message: fmt.Sprintf("rule %q is already defined at %s:%d; rule names must be unique across the workspace",
						r.Name, prev.path, prev.line),
				})
				continue
			}
			first[r.Name] = site{path: f.Path, line: r.NamePos.Line}
		}
	}
}
