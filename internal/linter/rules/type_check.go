package rules

import (
	"fmt"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/lexer"
	"yl2lint/internal/linter"
	"yl2lint/internal/schema"
)

// TypeCheck (YL012) performs lightweight type checking using the schema
// dictionary's per-field types: literals compared against a field must match
// the field's type, numeric functions must not receive string-typed fields,
// and timestamp functions must receive timestamp fields. Fields unknown to
// the schema are skipped (YL004's job), and no inference is attempted
// through outcome variables.
type TypeCheck struct{}

func (TypeCheck) ID() string   { return "YL012" }
func (TypeCheck) Name() string { return "type-check" }
func (TypeCheck) Description() string {
	return "literals and function arguments must match the schema-declared type of the UDM field they touch"
}

var numericArgFns = map[string]bool{
	"math.abs": true, "math.round": true,
}

var timestampArgFns = map[string]bool{
	"timestamp.get_day_of_week": true,
	"timestamp.get_hour":        true,
	"timestamp.get_date":        true,
}

func (tc TypeCheck) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	sev := linter.SeverityFor(cfg, tc.ID(), tc.Name(), linter.Warning)

	var vs []linter.Violation
	warn := func(pos ast.Position, format string, args ...any) {
		vs = append(vs, linter.Violation{
			RuleID: tc.ID(), RuleName: tc.Name(), Pos: pos, Severity: sev,
			Message: fmt.Sprintf(format, args...),
		})
	}

	for _, r := range f.Rules {
		for _, sec := range []*ast.Section{r.Events, r.Match, r.Outcome, r.Condition} {
			if sec == nil {
				continue
			}
			for _, st := range sec.Statements {
				toks := st.Tokens

				// 1. Field <op> literal comparisons.
				for _, ref := range fieldRefsIn(toks) {
					k := ref.End + 1
					if k+1 >= len(toks) {
						continue
					}
					if !(toks[k].Type == lexer.OPERATOR && cmpOps[toks[k].Literal]) {
						continue
					}
					ftype, known := schema.TypeOf(ref.Path)
					if !known || ftype == "" {
						continue
					}
					if msg := literalMismatch(ftype, toks[k+1]); msg != "" {
						warn(ast.PositionOf(toks[k+1]),
							"$%s.%s has type %s; %s", ref.VarName, ref.Path, ftype, msg)
					}
				}

				// 2. Typed function arguments.
				for _, c := range callsIn(toks) {
					if len(c.Args) == 0 {
						continue
					}
					ref, ok := soleFieldRef(c.Args[0])
					if !ok {
						continue
					}
					ftype, known := schema.TypeOf(ref.Path)
					if !known || ftype == "" {
						continue
					}
					switch {
					case numericArgFns[c.Name] && (ftype == "string" || ftype == "enum" || ftype == "bool"):
						warn(c.Pos, "%s: argument $%s.%s has type %s, expected a numeric field",
							c.Name, ref.VarName, ref.Path, ftype)
					case timestampArgFns[c.Name] && ftype != "timestamp":
						warn(c.Pos, "%s: argument $%s.%s has type %s, expected a timestamp field",
							c.Name, ref.VarName, ref.Path, ftype)
					}
				}
			}
		}
	}
	return vs
}

// literalMismatch reports why a literal token is incompatible with a field
// type, or "" when compatible (or when no judgement is safe).
func literalMismatch(ftype string, lit lexer.Token) string {
	switch lit.Type {
	case lexer.STRING:
		if ftype == "int" || ftype == "timestamp" || ftype == "bool" {
			return fmt.Sprintf("comparing it with string literal %q will not match numerically", lit.Literal)
		}
	case lexer.NUMBER:
		// Enums carry ordinals in Chronicle, so `metadata.event_type >= 16000` is idiomatic range matching.
		if ftype == "string" {
			return fmt.Sprintf("comparing it with numeric literal %s; use a quoted string", lit.Literal)
		}
	case lexer.REGEX:
		if ftype != "string" && ftype != "enum" {
			return "regex matching only applies to string fields"
		}
	case lexer.KEYWORD:
		if (lit.Literal == "true" || lit.Literal == "false") && ftype != "bool" {
			return fmt.Sprintf("comparing it with boolean literal %s", lit.Literal)
		}
	}
	return ""
}
