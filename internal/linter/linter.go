// Package linter defines the Rule strategy interface, the Violation type,
// and the engine that runs parser output + registered rules over a file.
package linter

import (
	"sort"
	"strings"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/parser"
)

// Severity ranks how serious a violation is.
type Severity int

const (
	Info Severity = iota
	Warning
	Error
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Warning:
		return "warning"
	default:
		return "error"
	}
}

// ParseSeverity converts a config string into a Severity.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, true
	case "warn", "warning":
		return Warning, true
	case "error":
		return Error, true
	}
	return Error, false
}

// SeverityFor resolves a rule's effective severity: the config override if
// present and valid, otherwise the rule's default.
func SeverityFor(cfg *config.Config, id, name string, def Severity) Severity {
	if cfg == nil {
		return def
	}
	if raw, ok := cfg.SeverityOverride(id, name); ok {
		if sev, valid := ParseSeverity(raw); valid {
			return sev
		}
	}
	return def
}

// Violation is a single finding reported by a rule (or the parser).
type Violation struct {
	RuleID   string // e.g. "YL002"
	RuleName string // e.g. "meta-required-keys"
	File     string
	Pos      ast.Position
	Severity Severity
	Message  string
}

// Rule is the strategy interface every lint check implements. Rules are
// isolated modules: they receive the parsed AST plus config and return
// violations, with no knowledge of files, concurrency, or output.
type Rule interface {
	ID() string
	Name() string
	Description() string
	Check(f *ast.File, cfg *config.Config) []Violation
}

// SyntaxRuleID / SyntaxRuleName identify violations synthesised from parser
// errors. Syntax checking runs on parser output rather than the AST, so it
// lives in the engine instead of a Rule implementation.
const (
	SyntaxRuleID   = "YL001"
	SyntaxRuleName = "syntax"
)

// Engine runs registered rules over parsed files.
type Engine struct {
	cfg   *config.Config
	rules []Rule
}

// NewEngine builds an engine from a config and a rule set, dropping any rule
// disabled in the config.
func NewEngine(cfg *config.Config, ruleSet []Rule) *Engine {
	e := &Engine{cfg: cfg}
	for _, r := range ruleSet {
		if !cfg.IsDisabled(r.ID(), r.Name()) {
			e.rules = append(e.rules, r)
		}
	}
	return e
}

// Rules returns the active (non-disabled) rules.
func (e *Engine) Rules() []Rule { return e.rules }

// LintSource parses src and returns every violation for it, sorted by
// position. Parse errors become YL001 violations; AST rules then run on
// whatever tree was recovered, so one syntax slip still yields meta and
// lifecycle findings for the rest of the file.
func (e *Engine) LintSource(path string, src []byte) []Violation {
	file, parseErrs := parser.Parse(src)
	file.Path = path

	var vs []Violation
	if !e.cfg.IsDisabled(SyntaxRuleID, SyntaxRuleName) {
		sev := SeverityFor(e.cfg, SyntaxRuleID, SyntaxRuleName, Error)
		for _, pe := range parseErrs {
			vs = append(vs, Violation{
				RuleID:   SyntaxRuleID,
				RuleName: SyntaxRuleName,
				File:     path,
				Pos:      ast.Position{Line: pe.Line, Column: pe.Column},
				Severity: sev,
				Message:  pe.Msg,
			})
		}
	}

	for _, r := range e.rules {
		for _, v := range r.Check(file, e.cfg) {
			v.File = path
			vs = append(vs, v)
		}
	}

	// Honour inline `yl2lint-disable` suppression comments.
	if sup := buildSuppressions(file); len(sup) > 0 {
		kept := vs[:0]
		for _, v := range vs {
			if !sup.covers(v) {
				kept = append(kept, v)
			}
		}
		vs = kept
	}

	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].Pos.Line != vs[j].Pos.Line {
			return vs[i].Pos.Line < vs[j].Pos.Line
		}
		if vs[i].Pos.Column != vs[j].Pos.Column {
			return vs[i].Pos.Column < vs[j].Pos.Column
		}
		return vs[i].RuleID < vs[j].RuleID
	})
	return vs
}