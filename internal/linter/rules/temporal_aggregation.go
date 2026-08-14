package rules

import (
	"fmt"
	"time"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/lexer"
	"yl2lint/internal/linter"
)

// maxWindow is the recommended ceiling for match windows; Chronicle's hard
// limit varies by deployment, so exceeding 14d is reported as a warning.
const maxWindow = 14 * 24 * time.Hour

// aggregate functions whose event-variable arguments must be declared.
var aggFns = map[string]bool{
	"count": true, "count_distinct": true,
	"array": true, "array_distinct": true,
	"sum": true, "min": true, "max": true, "avg": true, "stddev": true,
}

// TemporalAndAggregation (YL005) validates the match window duration and
// checks that aggregation calls in outcome/condition only reference variables
// defined in events: or match:.
type TemporalAndAggregation struct{}

func (TemporalAndAggregation) ID() string   { return "YL005" }
func (TemporalAndAggregation) Name() string { return "temporal-aggregation" }
func (TemporalAndAggregation) Description() string {
	return "match windows must stay within Chronicle limits (warn > 14d); aggregation arguments must reference variables from events: or match:"
}

func (t TemporalAndAggregation) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	sev := linter.SeverityFor(cfg, t.ID(), t.Name(), linter.Warning)

	var vs []linter.Violation
	for _, r := range f.Rules {
		// 1. Temporal window: `match: $x over 15m`.
		if r.Match != nil {
			for _, st := range r.Match.Statements {
				for i, tok := range st.Tokens {
					if !(tok.Type == lexer.KEYWORD && tok.Literal == "over") || i+1 >= len(st.Tokens) {
						continue
					}
					n := st.Tokens[i+1]
					if n.Type != lexer.NUMBER {
						continue
					}
					d, ok := parseWindow(n.Literal)
					switch {
					case !ok:
						vs = append(vs, linter.Violation{
							RuleID: t.ID(), RuleName: t.Name(), Pos: ast.PositionOf(n), Severity: sev,
							Message: fmt.Sprintf("unrecognised match window %q (expected e.g. 30m, 4h, 7d)", n.Literal),
						})
					case d > maxWindow:
						vs = append(vs, linter.Violation{
							RuleID: t.ID(), RuleName: t.Name(), Pos: ast.PositionOf(n), Severity: sev,
							Message: fmt.Sprintf("match window %s exceeds the recommended 14d maximum; long windows are rejected or heavily throttled by Chronicle", n.Literal),
						})
					}
				}
			}
		}

		// 2. Aggregation arguments must exist in events: or match:.
		declared := sectionVarNames(r.Events)
		for name := range sectionVarNames(r.Match) {
			declared[name] = true
		}
		for _, sec := range []*ast.Section{r.Outcome, r.Condition} {
			for _, c := range extractCalls(sec) {
				if !aggFns[c.Name] {
					continue
				}
				for _, arg := range c.Args {
					for _, tok := range arg {
						if tok.Type != lexer.EVENTVAR && tok.Type != lexer.COUNTVAR {
							continue
						}
						if declared[tok.Literal[1:]] {
							continue
						}
						vs = append(vs, linter.Violation{
							RuleID: t.ID(), RuleName: t.Name(), Pos: ast.PositionOf(tok),
							Severity: linter.SeverityFor(cfg, t.ID(), t.Name(), linter.Error),
							Message: fmt.Sprintf("aggregation %s(...) references %s, which is not defined in events: or match:",
								c.Name, tok.Literal),
						})
					}
				}
			}
		}
	}
	return vs
}