// internal/linter/rules/performance.go
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

// baseFilterFields are the indexed metadata fields whose equality narrows the
// scan cheaply. Any one of them counts as base event filtering.
var baseFilterFields = map[string]bool{
	"metadata.event_type":            true,
	"metadata.log_type":              true,
	"metadata.product_name":          true,
	"metadata.vendor_name":           true,
	"metadata.product_event_type":    true,
	"metadata.base_labels.log_types": true,
}

// PerformanceAntiPattern (YL007) warns about detection patterns that force
// expensive scans: regexes matching anything, rules without a
// base event filter, and expensive filters ordered before the base filter.
type PerformanceAntiPattern struct{}

func (PerformanceAntiPattern) ID() string   { return "YL007" }
func (PerformanceAntiPattern) Name() string { return "performance" }
func (PerformanceAntiPattern) Description() string {
	return "warn on regexes that match everything, rules without base event filtering, expensive filters placed before the base filter, and OR saturation"
}

func (p PerformanceAntiPattern) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	// Informational by default: every finding here is a cost/efficiency
	// signal, not a correctness one, and broad-scan rules are sometimes
	// deliberate. Teams can raise it via severities in .yl2lint.yaml.
	sev := linter.SeverityFor(cfg, p.ID(), p.Name(), linter.Info)

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
				"rule %q never filters on an indexed metadata filter (event_type, log_type, product_name, ...) in events:; without a base event filter the rule forces an unindexed scan of all log types", r.Name)
			continue
		}
		for i := 0; i < baseIdx; i++ {
			if pos, kind, ok := expensiveFilterAt(r.Events.Statements[i]); ok {
				warn(pos,
					"%s appears before an indexed metadata filter (event_type, log_type, product_name, ...); put strict equality filters first so cheap filters prune events before expensive ones run", kind)
			}
		}

		// 3. OR saturation. A rule built almost entirely from OR alternatives
		// (IOC lists, LOLBAS name dumps) cannot be pruned by any single
		// filter: every alternative is evaluated against every candidate
		// event. Reference lists (%list) are the indexed alternative.
		maxTerms := cfg.Performance.MaxOrTerms
		if maxTerms == 0 {
			maxTerms = 12
		}
		maxRatio := cfg.Performance.MaxOrRatio
		if maxRatio == 0 {
			maxRatio = 0.8
		}
		if maxTerms > 0 && r.Events != nil && len(r.Events.Statements) > 0 {
			orHeavy, total := 0, 0
			for _, st := range r.Events.Statements {
				n := topLevelOrTerms(st.Tokens)
				total++
				if n >= 2 {
					orHeavy++
				}
				if n > maxTerms {
					warn(st.Pos,
						"statement has %d OR alternatives; none can be indexed away, so every alternative is evaluated against every event — consider a reference list (in %%list) or a single regex alternation",
						n)
				}
			}
			if total >= 3 && float64(orHeavy)/float64(total) >= maxRatio {
				warn(r.Events.Pos,
					"rule %q is built almost entirely from OR alternatives (%d of %d statements); there is no selective filter to prune the scan — add a base event filter or move the alternatives into a reference list",
					r.Name, orHeavy, total)
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
		if baseFilterFields[ref.Path] || strings.HasPrefix(ref.Path, "metadata.event_type") {
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

// topLevelOrTerms counts alternatives joined by `or` at the outermost
// parenthesis depth of a statement: `a or b or c` is 3, `a and (b or c)` is 1.
// A statement wrapped entirely in one paren pair is unwrapped first, since
// `(a or b or c)` is the common way these are written.
func topLevelOrTerms(toks []lexer.Token) int {
	toks = unwrapParens(toks)
	depth, ors := 0, 0
	for _, t := range toks {
		switch t.Type {
		case lexer.LPAREN, lexer.LBRACKET:
			depth++
		case lexer.RPAREN, lexer.RBRACKET:
			depth--
		case lexer.KEYWORD:
			if depth == 0 && t.Literal == "or" {
				ors++
			}
		}
	}
	if ors == 0 {
		return 1
	}
	return ors + 1
}

// unwrapParens strips one fully enclosing parenthesis pair.
func unwrapParens(toks []lexer.Token) []lexer.Token {
	for len(toks) >= 2 && toks[0].Type == lexer.LPAREN && toks[len(toks)-1].Type == lexer.RPAREN {
		depth := 0
		enclosing := true
		for i, t := range toks {
			switch t.Type {
			case lexer.LPAREN:
				depth++
			case lexer.RPAREN:
				depth--
			}
			if depth == 0 && i < len(toks)-1 {
				enclosing = false
				break
			}
		}
		if !enclosing {
			return toks
		}
		toks = toks[1 : len(toks)-1]
	}
	return toks
}
