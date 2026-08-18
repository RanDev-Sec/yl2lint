package rules

import (
	"fmt"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/lexer"
	"yl2lint/internal/linter"
	"yl2lint/internal/schema"
)

// RepeatedFields (YL010) enforces explicit handling of repeated UDM fields:
// comparing a repeated field (like principal.ip) requires an any/all
// quantifier, and applying any/all to a scalar field is a mistake. Field
// repeatedness comes from the schema dictionary, so unknown fields are left
// to YL004.
type RepeatedFields struct{}

func (RepeatedFields) ID() string   { return "YL010" }
func (RepeatedFields) Name() string { return "repeated-fields" }
func (RepeatedFields) Description() string {
	return "negated/ordering comparisons on repeated UDM fields need an explicit any/all quantifier; any/all must not be applied to scalar fields"
}

var cmpOps = map[string]bool{
	"=": true, "==": true, "!=": true, ">": true, "<": true, ">=": true, "<=": true,
}

// negCmpOps are the comparisons where implicit-any semantics on a repeated
// field are a trap: `$e.principal.ip != "x"` means "ANY element differs",
// which is almost always true and silently breaks exclusion logic.
var negCmpOps = map[string]bool{"!=": true, ">": true, "<": true, ">=": true, "<=": true}

func (rf RepeatedFields) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	sev := linter.SeverityFor(cfg, rf.ID(), rf.Name(), linter.Warning)

	var vs []linter.Violation
	warn := func(pos ast.Position, format string, args ...any) {
		vs = append(vs, linter.Violation{
			RuleID: rf.ID(), RuleName: rf.Name(), Pos: pos, Severity: sev,
			Message: fmt.Sprintf(format, args...),
		})
	}

	for _, r := range f.Rules {
		for _, sec := range []*ast.Section{r.Events, r.Condition} {
			if sec == nil {
				continue
			}
			for _, st := range sec.Statements {
				toks := st.Tokens
				for _, ref := range fieldRefsIn(toks) {
					k := ref.End + 1
					var op string
					if k < len(toks) && toks[k].Type == lexer.OPERATOR && cmpOps[toks[k].Literal] {
						op = toks[k].Literal
					}
					inKw := k < len(toks) && toks[k].Type == lexer.KEYWORD && toks[k].Literal == "in"
					if op == "" && !inKw {
						continue
					}

					quantified := ref.Start > 0 &&
						toks[ref.Start-1].Type == lexer.KEYWORD &&
						(toks[ref.Start-1].Literal == "any" || toks[ref.Start-1].Literal == "all")

					fld, known := schema.Lookup(ref.Path)
					if !known {
						continue // YL004's job
					}

					switch {
					// Positive equality / `in` on a repeated field is the
					// documented implicit-any idiom: not a finding. Indexed
					// access ($e.security_result[1].x) is explicit element
					// selection: also not a finding.
					case fld.Repeated && !quantified && !ref.Indexed && negCmpOps[op]:
						warn(ref.Pos,
							"$%s.%s is a repeated field; `%s` without a quantifier means ANY element satisfies it, which is almost always true — use `all $%s.%s %s ...` to exclude every element",
							ref.VarName, ref.Path, op, ref.VarName, ref.Path, op)
					case !fld.Repeated && quantified:
						warn(ast.PositionOf(toks[ref.Start-1]),
							"%s applied to $%s.%s, which is a scalar field; any/all only apply to repeated fields",
							toks[ref.Start-1].Literal, ref.VarName, ref.Path)
					}
				}
			}
		}
	}
	return vs
}
