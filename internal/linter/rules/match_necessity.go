package rules

import (
	"fmt"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/linter"
)

// MatchNecessity (YL009) flags mismatches between the match: section and how
// the rule actually uses events. A match: window on a rule
// with a single event variable is often only there to feed outcome
// aggregates, and should be refactored to a cheaper single-event rule.
type MatchNecessity struct{}

func (MatchNecessity) ID() string   { return "YL009" }
func (MatchNecessity) Name() string { return "match-necessity" }
func (MatchNecessity) Description() string {
	return "flag match: windows on single-event rules (refactor candidates)"
}

func (m MatchNecessity) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	sev := linter.SeverityFor(cfg, m.ID(), m.Name(), linter.Warning)

	var vs []linter.Violation
	warn := func(pos ast.Position, format string, args ...any) {
		vs = append(vs, linter.Violation{
			RuleID: m.ID(), RuleName: m.Name(), Pos: pos, Severity: sev,
			Message: fmt.Sprintf(format, args...),
		})
	}

	for _, r := range f.Rules {
		if r.Match != nil && len(sectionVarNames(r.Events)) == 1 {
			warn(r.Match.Pos,
				"rule %q uses a single event variable; if match: exists only to compute outcome values, refactor to a single-event rule by removing match: and the aggregate functions", r.Name)
		}
	}
	return vs
}
