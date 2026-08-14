package rules

import (
	"fmt"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/linter"
	"yl2lint/internal/schema"
)

// UDMSchema (YL004) validates every `$var.path.to.field` access against the
// embedded UDM field dictionary, catching typos and unknown/deprecated fields.
type UDMSchema struct{}

func (UDMSchema) ID() string   { return "YL004" }
func (UDMSchema) Name() string { return "udm-schema" }
func (UDMSchema) Description() string {
	return "event field paths must exist in the UDM schema dictionary (typo / unknown-field detection)"
}

func (u UDMSchema) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	sev := linter.SeverityFor(cfg, u.ID(), u.Name(), linter.Warning)

	var vs []linter.Violation
	for _, r := range f.Rules {
		for _, sec := range []*ast.Section{r.Events, r.Match, r.Outcome, r.Condition} {
			for _, fr := range extractFieldPaths(sec) {
				if schema.Valid(fr.Path) {
					continue
				}
				msg := fmt.Sprintf("unknown UDM field %q on $%s", fr.Path, fr.VarName)
				if near := schema.Nearest(fr.Path); near != "" {
					msg += fmt.Sprintf("; did you mean %q?", near)
				}
				vs = append(vs, linter.Violation{
					RuleID: u.ID(), RuleName: u.Name(), Pos: fr.Pos, Severity: sev, Message: msg,
				})
			}
		}
	}
	return vs
}