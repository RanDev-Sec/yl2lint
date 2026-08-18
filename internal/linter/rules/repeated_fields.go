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
	return "repeated UDM fields must be compared with any/all; any/all must not be applied to scalar fields"
}

var cmpOps = map[string]bool{
	"=": true, "==": true, "!=": true, ">": true, "<": true, ">=": true, "<=": true,
}

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
					// Only consider refs that are directly compared.
					k := ref.End + 1
					compared := k < len(toks) &&
						((toks[k].Type == lexer.OPERATOR && cmpOps[toks[k].Literal]) ||
							(toks[k].Type == lexer.KEYWORD && toks[k].Literal == "in"))
					if !compared {
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
					case fld.Repeated && !quantified:
						warn(ref.Pos,
							"$%s.%s is a repeated field; compare it with an explicit quantifier, e.g. `any $%s.%s ...` or `all $%s.%s ...`",
							ref.VarName, ref.Path, ref.VarName, ref.Path, ref.VarName, ref.Path)
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
