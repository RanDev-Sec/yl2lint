package rules

// Note: Add function for reviewing rules that have too many OR functions for example, or too many regexes, or too many events, etc. This is a performance anti-pattern and should be flagged as a warning.

import (
	"fmt"
	"strings"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/lexer"
	"yl2lint/internal/linter"
)

// PerformanceAntiPattern (YL007) warns about detection patterns that force
// expensive scans: regexes opening with a broad wildcard, and rules whose
// events: section never filters on metadata.event_type.
type PerformanceAntiPattern struct{}

func (PerformanceAntiPattern) ID() string   { return "YL007" }
func (PerformanceAntiPattern) Name() string { return "performance" }
func (PerformanceAntiPattern) Description() string {
	return "warn on leading-wildcard regexes and on rules without base event filtering (metadata.event_type)"
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
		sections := []*ast.Section{r.Events, r.Match, r.Outcome, r.Condition}

		// 1. Leading-wildcard regexes: /.../ literals and re.regex string args.
		for _, sec := range sections {
			if sec == nil {
				continue
			}
			for _, st := range sec.Statements {
				for _, tok := range st.Tokens {
					if tok.Type == lexer.REGEX && broadWildcardPrefix(tok.Literal) {
						warn(ast.PositionOf(tok),
							"regex /%s/ starts with a broad wildcard; anchor it or start with a literal prefix to avoid scanning every value", tok.Literal)
					}
				}
			}
			for _, c := range extractCalls(sec) {
				if c.Name != "re.regex" || len(c.Args) < 2 {
					continue
				}
				a := c.Args[1]
				if len(a) == 1 && a[0].Type == lexer.STRING {
					if pat := unquotePattern(a[0].Literal); broadWildcardPrefix(pat) {
						warn(ast.PositionOf(a[0]),
							"regex %q starts with a broad wildcard; anchor it or start with a literal prefix to avoid scanning every value", pat)
					}
				}
			}
		}

		// 2. Missing base event filtering.
		if r.Events != nil {
			filtered := false
			for _, fr := range extractFieldPaths(r.Events) {
				if strings.HasPrefix(fr.Path, "metadata.event_type") {
					filtered = true
					break
				}
			}
			if !filtered {
				warn(r.Events.Pos,
					"rule %q never filters on metadata.event_type in events:; without a base event filter the rule forces an unindexed scan of all log types", r.Name)
			}
		}
	}
	return vs
}

// broadWildcardPrefix reports whether a pattern effectively begins with .* or
// .+, ignoring inline flag groups like (?i) and a leading ^ anchor.
func broadWildcardPrefix(pat string) bool {
	pat = strings.TrimSpace(pat)
	for strings.HasPrefix(pat, "(?") {
		end := strings.Index(pat, ")")
		if end < 0 {
			break
		}
		pat = pat[end+1:]
	}
	pat = strings.TrimPrefix(pat, "^")
	return strings.HasPrefix(pat, ".*") || strings.HasPrefix(pat, ".+")
}