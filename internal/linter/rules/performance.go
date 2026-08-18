package rules

import (
	"fmt"
	"regexp/syntax"
	"strings"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/lexer"
	"yl2lint/internal/linter"
)

// PerformanceAntiPattern (YL007) warns about detection patterns that force
// expensive scans: regexes matching anything, rules without a
// base event filter, and expensive filters ordered before the base filter.
type PerformanceAntiPattern struct{}

func (PerformanceAntiPattern) ID() string   { return "YL007" }
func (PerformanceAntiPattern) Name() string { return "performance" }
func (PerformanceAntiPattern) Description() string {
	return "warn on regexes that match everything, rules without base event filtering (metadata.event_type or metadata.log_type), and expensive filters placed before the base filter"
}

func (p PerformanceAntiPattern) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	sev := linter.SeverityFor(cfg, p.ID(), p.Name(), linter.Warning)

	var vs []linter.Violation
	warn := func(pos ast.Position, format string, args ...any) {
		vs = append(vs, linter.Violation{
			RuleID: p.ID(), RuleName: p.Name(), Pos: pos, Severity: sev,
			Message: fmt.Sprintf(format, args...),
		})
	}

	for _, r := range f.Rules {
		// 1. Trivial regexes anywhere in the rule that match everything.
		for _, sec := range []*ast.Section{r.Events, r.Match, r.Outcome, r.Condition} {
			if sec == nil {
				continue
			}
			for _, st := range sec.Statements {
				for _, tok := range st.Tokens {
					if tok.Type == lexer.REGEX && wildcardOnly(tok.Literal) {
						warn(ast.PositionOf(tok),
							"regex /%s/ matches any value and filters nothing; remove the comparison or use a real pattern", tok.Literal)
					}
				}
				for _, c := range callsIn(st.Tokens) {
					if (c.Name != "re.regex" && c.Name != "re.capture") || len(c.Args) < 2 {
						continue
					}
					a := c.Args[1]
					if len(a) == 1 && a[0].Type == lexer.STRING {
						if pat := unquotePattern(a[0].Literal); wildcardOnly(pat) {
							warn(ast.PositionOf(a[0]),
								"regex %q matches any value and filters nothing; remove the comparison or use a real pattern", pat)
						}
					}
				}
			}
		}

		// 2. Base event filtering: presence and position.
		if r.Events == nil {
			continue
		}
		baseIdx := -1
		for i, st := range r.Events.Statements {
			if stmtHasBaseFilter(st) {
				baseIdx = i
				break
			}
		}
		if baseIdx == -1 {
			warn(r.Events.Pos,
				"rule %q never filters on metadata.event_type or metadata.log_type in events:; without a base event filter the rule forces an unindexed scan of all log types", r.Name)
			continue
		}
		for i := 0; i < baseIdx; i++ {
			if pos, kind, ok := expensiveFilterAt(r.Events.Statements[i]); ok {
				warn(pos,
					"%s appears before the metadata.event_type or metadata.log_type equality filter; put strict equality filters first so cheap filters prune events before expensive ones run", kind)
			}
		}
	}
	return vs
}

// stmtHasBaseFilter reports whether a statement is a strict-equality filter
// on metadata.event_type or metadata.log_type.
func stmtHasBaseFilter(st ast.Statement) bool {
	found := false
	for _, ref := range fieldRefsIn(st.Tokens) {
		if strings.HasPrefix(ref.Path, "metadata.event_type") || ref.Path == "metadata.log_type" {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	for _, t := range st.Tokens {
		if t.Type == lexer.OPERATOR && (t.Literal == "=" || t.Literal == "==") {
			return true
		}
	}
	return false
}

// expensiveFilterAt reports whether a statement contains a comparatively
// expensive operation: a regex match or a reference-list lookup.
func expensiveFilterAt(st ast.Statement) (ast.Position, string, bool) {
	for _, t := range st.Tokens {
		switch t.Type {
		case lexer.REGEX:
			return ast.PositionOf(t), "regex comparison", true
		case lexer.PLACEHOLDER:
			return ast.PositionOf(t), "reference list lookup", true
		}
	}
	for _, c := range callsIn(st.Tokens) {
		if c.Name == "re.regex" || c.Name == "re.capture" {
			return c.Pos, c.Name + "(...) call", true
		}
	}
	return ast.Position{}, "", false
}

// wildcardOnly reports whether a pattern matches essentially any input —
// /.*/, /^.*$/, /.+$/ and equivalents — meaning the comparison filters
// nothing and is either a no-op or a logic error. Leading .* on a real
// pattern is NOT flagged: YARA-L `= /regex/` is a full-string match, so
// /.*foo.*/ is the required substring idiom.
func wildcardOnly(pat string) bool {
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return false // YL006 reports invalid patterns
	}
	return trivial(re)
}

func trivial(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginText, syntax.OpBeginLine, syntax.OpEndText, syntax.OpEndLine, syntax.OpEmptyMatch:
		return true
	case syntax.OpCapture:
		return trivial(re.Sub[0])
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if !trivial(s) {
				return false
			}
		}
		return true
	case syntax.OpStar, syntax.OpPlus:
		return isAnyChar(re.Sub[0])
	}
	return false
}

func isAnyChar(re *syntax.Regexp) bool {
	return re.Op == syntax.OpAnyChar || re.Op == syntax.OpAnyCharNotNL
}
