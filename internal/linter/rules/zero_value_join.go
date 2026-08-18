package rules

import (
	"fmt"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/lexer"
	"yl2lint/internal/linter"
)

// ZeroValueJoin (YL008) guards against the zero-value equality pitfall: when
// two UDM fields are both absent from a log they evaluate to "", so a join
// like $e1.field = $e2.field matches on "" = "" and floods with false
// positives. The rule requires a non-empty guard ($eN.field != "" or
// != null) on at least one side of every cross-variable field equality.
type ZeroValueJoin struct{}

func (ZeroValueJoin) ID() string   { return "YL008" }
func (ZeroValueJoin) Name() string { return "zero-value-join" }
func (ZeroValueJoin) Description() string {
	return "cross-event field joins ($e1.f = $e2.f) must have a non-empty guard (!= \"\") on at least one side"
}

func (z ZeroValueJoin) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	sev := linter.SeverityFor(cfg, z.ID(), z.Name(), linter.Warning)

	var vs []linter.Violation
	for _, r := range f.Rules {
		if r.Events == nil {
			continue
		}

		// Pass 1: collect guarded fields ($var.path != "" / != null).
		guarded := map[string]bool{}
		for _, st := range r.Events.Statements {
			toks := st.Tokens
			for _, ref := range fieldRefsIn(toks) {
				k := ref.End + 1
				if k+1 >= len(toks) {
					continue
				}
				if !(toks[k].Type == lexer.OPERATOR && toks[k].Literal == "!=") {
					continue
				}
				val := toks[k+1]
				empty := (val.Type == lexer.STRING && val.Literal == "") ||
					(val.Type == lexer.KEYWORD && val.Literal == "null")
				if empty {
					guarded[ref.VarName+"."+ref.Path] = true
				}
			}
		}

		// Pass 2: find cross-variable equalities and check the guards.
		for _, st := range r.Events.Statements {
			toks := st.Tokens
			refs := fieldRefsIn(toks)
			for _, a := range refs {
				k := a.End + 1
				if k >= len(toks) {
					continue
				}
				if !(toks[k].Type == lexer.OPERATOR && (toks[k].Literal == "=" || toks[k].Literal == "==")) {
					continue
				}
				var b *stmtFieldRef
				for i := range refs {
					if refs[i].Start == k+1 {
						b = &refs[i]
						break
					}
				}
				if b == nil || b.VarName == a.VarName {
					continue // literal comparison or same-event field compare
				}
				if guarded[a.VarName+"."+a.Path] || guarded[b.VarName+"."+b.Path] {
					continue
				}
				vs = append(vs, linter.Violation{
					RuleID: z.ID(), RuleName: z.Name(), Pos: ast.PositionOf(toks[k]), Severity: sev,
					Message: fmt.Sprintf(
						"join $%s.%s = $%s.%s also matches when both fields are empty; add a guard such as $%s.%s != \"\"",
						a.VarName, a.Path, b.VarName, b.Path, a.VarName, a.Path),
				})
			}
		}
	}
	return vs
}
