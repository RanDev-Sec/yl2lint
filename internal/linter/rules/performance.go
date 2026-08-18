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
// expensive scans: regexes opening with a broad wildcard, rules without a
// base event filter, and expensive filters ordered before the base filter.
type PerformanceAntiPattern struct{}

func (PerformanceAntiPattern) ID() string   { return "YL007" }
func (PerformanceAntiPattern) Name() string { return "performance" }
func (PerformanceAntiPattern) Description() string {
	return "warn on leading-wildcard regexes, rules without base event filtering (metadata.event_type), and expensive filters placed before the base filter"
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
		// 1. Leading-wildcard regexes anywhere in the rule.
		for _, sec := range []*ast.Section{r.Events, r.Match, r.Outcome, r.Condition} {
			if sec == nil {
				continue
			}
			for _, st := range sec.Statements {
				for _, tok := range st.Tokens {
					if tok.Type == lexer.REGEX && broadWildcardPrefix(tok.Literal) {
						warn(ast.PositionOf(tok),
							"regex /%s/ starts with a broad wildcard; anchor it or start with a literal prefix", tok.Literal)
					}
				}
				for _, c := range callsIn(st.Tokens) {
					if (c.Name != "re.regex" && c.Name != "re.capture") || len(c.Args) < 2 {
						continue
					}
					a := c.Args[1]
					if len(a) == 1 && a[0].Type == lexer.STRING {
						if pat := unquotePattern(a[0].Literal); broadWildcardPrefix(pat) {
							warn(ast.PositionOf(a[0]),
								"regex %q starts with a broad wildcard; anchor it or start with a literal prefix", pat)
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
				"rule %q never filters on metadata.event_type in events:; without a base event filter the rule forces an unindexed scan of all log types", r.Name)
			continue
		}
		for i := 0; i < baseIdx; i++ {
			if pos, kind, ok := expensiveFilterAt(r.Events.Statements[i]); ok {
				warn(pos,
					"%s appears before the metadata.event_type equality filter; put strict equality filters first so cheap filters prune events before expensive ones run", kind)
			}
		}
	}
	return vs
}

// stmtHasBaseFilter reports whether a statement is a strict-equality filter
// on metadata.event_type.
func stmtHasBaseFilter(st ast.Statement) bool {
	found := false
	for _, ref := range fieldRefsIn(st.Tokens) {
		if strings.HasPrefix(ref.Path, "metadata.event_type") {
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

// broadWildcardPrefix reports whether a pattern effectively begins with an
// unbounded any-character repetition (.* or .+), by walking Go's parsed
// regex AST. Flag groups, non-capturing groups, and anchors are handled by
// the parser, not string manipulation. Patterns that fail to parse return
// false; YL006 reports those.
func broadWildcardPrefix(pat string) bool {
	re, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return false
	}
	return startsBroad(re)
}

func startsBroad(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			switch sub.Op {
			case syntax.OpBeginText, syntax.OpBeginLine, syntax.OpEmptyMatch:
				continue
			}
			return startsBroad(sub)
		}
		return false
	case syntax.OpCapture:
		return startsBroad(re.Sub[0])
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if startsBroad(sub) {
				return true
			}
		}
		return false
	case syntax.OpStar, syntax.OpPlus:
		return isAnyChar(re.Sub[0])
	case syntax.OpRepeat:
		return re.Max == -1 && isAnyChar(re.Sub[0]) // .{2,} etc.
	}
	return false
}

func isAnyChar(re *syntax.Regexp) bool {
	return re.Op == syntax.OpAnyChar || re.Op == syntax.OpAnyCharNotNL
}
