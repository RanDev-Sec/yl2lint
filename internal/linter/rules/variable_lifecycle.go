package rules

import (
	"fmt"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/linter"
)

// VariableLifecycle (YL003) enforces two invariants:
//
//  1. Every event variable declared in the events block must be evaluated in
//     at least one of match, condition, or outcome.
//  2. Every variable referenced in match, condition, or outcome must have
//     been defined in the events block — with one carve-out: outcome
//     variables ($x = ... in outcome) are definitions in their own right and
//     may be referenced from outcome or condition.
//
// Count references (#var) evaluate the event variable of the same name.
type VariableLifecycle struct{}

func (VariableLifecycle) ID() string   { return "YL003" }
func (VariableLifecycle) Name() string { return "variable-lifecycle" }
func (VariableLifecycle) Description() string {
	return "event variables must be declared in events and evaluated in match, condition, or outcome"
}

func (vl VariableLifecycle) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	sev := linter.SeverityFor(cfg, vl.ID(), vl.Name(), linter.Error)

	var vs []linter.Violation
	for _, r := range f.Rules {
		vs = append(vs, vl.checkRule(r, sev)...)
	}
	return vs
}

func (vl VariableLifecycle) checkRule(r *ast.YaraLRule, sev linter.Severity) []linter.Violation {
	// Declarations: any $var / #var occurrence inside events.
	declared := map[string]bool{}
	if r.Events != nil {
		for _, ref := range r.Events.Variables {
			declared[ref.Name] = true
		}
	}

	// Outcome-variable definitions ($risk_score = ...) are a separate
	// namespace: they are not event variables and may legitimately be read
	// from outcome or condition.
	outcomeDefs := map[string]bool{}
	if r.Outcome != nil {
		for _, ref := range r.Outcome.Variables {
			if ref.IsDefinition {
				outcomeDefs[ref.Name] = true
			}
		}
	}

	evalSections := []*ast.Section{r.Match, r.Condition, r.Outcome}

	// Uses: every non-definition reference in match / condition / outcome.
	used := map[string]bool{}
	for _, sec := range evalSections {
		if sec == nil {
			continue
		}
		for _, ref := range sec.Variables {
			if !ref.IsDefinition {
				used[ref.Name] = true
			}
		}
	}

	var vs []linter.Violation

	// Check 1: declared in events but never evaluated anywhere.
	if r.Events != nil {
		reported := map[string]bool{}
		for _, ref := range r.Events.Variables {
			if used[ref.Name] || reported[ref.Name] {
				continue
			}
			reported[ref.Name] = true
			vs = append(vs, linter.Violation{
				RuleID: vl.ID(), RuleName: vl.Name(), Pos: ref.Pos, Severity: sev,
				Message: fmt.Sprintf(
					"event variable $%s is declared in the events block but never evaluated in match, condition, or outcome",
					ref.Name),
			})
		}
	}

	// Check 2: used but never defined. Reported once per variable per
	// section, at its first occurrence.
	for _, sec := range evalSections {
		if sec == nil {
			continue
		}
		reported := map[string]bool{}
		for _, ref := range sec.Variables {
			if ref.IsDefinition || declared[ref.Name] || outcomeDefs[ref.Name] || reported[ref.Name] {
				continue
			}
			reported[ref.Name] = true
			vs = append(vs, linter.Violation{
				RuleID: vl.ID(), RuleName: vl.Name(), Pos: ref.Pos, Severity: sev,
				Message: fmt.Sprintf(
					"variable %s is used in the %s block but never defined in the events block",
					ref.Text, sec.Name),
			})
		}
	}
	return vs
}
