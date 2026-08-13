package rules

import (
	"fmt"
	"strings"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/linter"
)

// MetaRequiredKeys (YL002) enforces the dynamic meta policy: every key listed
// in the config's meta.required_keys must exist in each rule's meta block.
type MetaRequiredKeys struct{}

func (MetaRequiredKeys) ID() string   { return "YL002" }
func (MetaRequiredKeys) Name() string { return "meta-required-keys" }
func (MetaRequiredKeys) Description() string {
	return "meta block must contain every key listed under meta.required_keys in .yl2lint.yaml"
}

func (m MetaRequiredKeys) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	required := cfg.Meta.RequiredKeys
	if len(required) == 0 {
		return nil
	}
	sev := linter.SeverityFor(cfg, m.ID(), m.Name(), linter.Error)

	var vs []linter.Violation
	for _, r := range f.Rules {
		if r.Meta == nil {
			vs = append(vs, linter.Violation{
				RuleID: m.ID(), RuleName: m.Name(), Pos: r.Pos, Severity: sev,
				Message: fmt.Sprintf("rule %q has no meta section (policy requires keys: %s)",
					r.Name, strings.Join(required, ", ")),
			})
			continue
		}

		have := make(map[string]bool, len(r.Meta.Entries))
		for _, e := range r.Meta.Entries {
			have[e.Key] = true
		}
		for _, key := range required {
			if !have[key] {
				vs = append(vs, linter.Violation{
					RuleID: m.ID(), RuleName: m.Name(), Pos: r.Meta.Pos, Severity: sev,
					Message: fmt.Sprintf("rule %q: meta section is missing required key %q", r.Name, key),
				})
			}
		}
	}
	return vs
}
