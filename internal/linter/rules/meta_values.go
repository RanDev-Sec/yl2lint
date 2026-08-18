package rules

import (
	"fmt"
	"strings"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/linter"
)

// MetaValues (YL011) enforces enumerated values for meta keys, driven by
// meta.allowed_values in the config. By default the severity key must be one
// of INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL. Matching is
// case-insensitive.
type MetaValues struct{}

func (MetaValues) ID() string   { return "YL011" }
func (MetaValues) Name() string { return "meta-values" }
func (MetaValues) Description() string {
	return "meta keys listed under meta.allowed_values must use one of the configured values (default: severity enum)"
}

func (mv MetaValues) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	allowed := cfg.Meta.AllowedValues
	if len(allowed) == 0 {
		return nil
	}
	sev := linter.SeverityFor(cfg, mv.ID(), mv.Name(), linter.Error)

	var vs []linter.Violation
	for _, r := range f.Rules {
		if r.Meta == nil {
			continue // YL002 reports the missing block
		}
		for _, e := range r.Meta.Entries {
			values, ok := allowed[e.Key]
			if !ok || len(values) == 0 {
				continue
			}
			valid := false
			for _, v := range values {
				if strings.EqualFold(e.Value, v) {
					valid = true
					break
				}
			}
			if !valid {
				vs = append(vs, linter.Violation{
					RuleID: mv.ID(), RuleName: mv.Name(), Pos: e.Pos, Severity: sev,
					Message: fmt.Sprintf("meta key %q has value %q; allowed values: %s",
						e.Key, e.Value, strings.Join(values, ", ")),
				})
			}
		}
	}
	return vs
}
