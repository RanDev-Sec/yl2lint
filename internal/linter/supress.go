// Inline suppression: a comment `# yl2lint-disable: <rule>` (or the
// //-comment form) suppresses violations of the named rule(s) for the node it
// precedes. Preceding a statement suppresses that line; preceding a section
// header suppresses the whole section; preceding a `rule` keyword suppresses
// the whole rule. A trailing comment on a code line suppresses that line.
// Rules may be named by ID or name, comma-separated; an empty list means all.
package linter

import (
	"fmt"
	"sort"
	"strings"
	"yl2lint/internal/ast"
	"yl2lint/internal/lexer"
)

const disableDirective = "yl2lint-disable"

type lineSpan struct{ from, to int }

// suppressions maps a lowercase rule ID/name (or "*") to suppressed spans.
type suppressions map[string][]lineSpan

func (s suppressions) covers(v Violation) bool {
	for _, key := range []string{"*", strings.ToLower(v.RuleID), strings.ToLower(v.RuleName)} {
		for _, sp := range s[key] {
			if v.Pos.Line >= sp.from && v.Pos.Line <= sp.to {
				return true
			}
		}
	}
	return false
}

func buildSuppressions(f *ast.File) suppressions {
	if f == nil || len(f.Comments) == 0 {
		return nil
	}
	anchors := collectAnchors(f)
	out := suppressions{}
	for _, c := range f.Comments {
		names, ok := parseDisable(c.Text)
		if !ok {
			continue
		}
		sp, ok := targetSpan(anchors, c)
		if !ok {
			continue
		}
		for _, n := range names {
			out[n] = append(out[n], sp)
		}
	}
	return out
}

// parseDisable extracts the rule list from a directive comment body.
// "yl2lint-disable: udm-schema, YL006" → ["udm-schema", "yl006"].
// "yl2lint-disable" alone disables every rule for the target node.
func parseDisable(text string) ([]string, bool) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, disableDirective) {
		return nil, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(text, disableDirective))
	rest = strings.TrimSpace(strings.TrimPrefix(rest, ":"))
	if rest == "" {
		return []string{"*"}, true
	}
	var names []string
	for _, part := range strings.Split(rest, ",") {
		if p := strings.ToLower(strings.TrimSpace(part)); p != "" {
			names = append(names, p)
		}
	}
	if len(names) == 0 {
		names = []string{"*"}
	}
	return names, true
}

// anchor associates a source line that begins an AST node with the span of
// lines that node covers.
type anchor struct {
	line int
	span lineSpan
}

func collectAnchors(f *ast.File) []anchor {
	var as []anchor
	add := func(line int, sp lineSpan) {
		if line > 0 {
			as = append(as, anchor{line: line, span: sp})
		}
	}

	for _, r := range f.Rules {
		ruleEnd := r.Pos.Line
		grow := func(l int) {
			if l > ruleEnd {
				ruleEnd = l
			}
		}

		secs := []*ast.Section{r.Events, r.Match, r.Outcome, r.Condition, r.Options}

		if r.Meta != nil {
			grow(r.Meta.Pos.Line)
			metaEnd := r.Meta.Pos.Line
			for _, e := range r.Meta.Entries {
				grow(e.Pos.Line)
				if e.Pos.Line > metaEnd {
					metaEnd = e.Pos.Line
				}
				add(e.Pos.Line, lineSpan{e.Pos.Line, e.Pos.Line})
			}
			add(r.Meta.Pos.Line, lineSpan{r.Meta.Pos.Line, metaEnd})
		}
		for _, s := range secs {
			if s == nil {
				continue
			}
			grow(s.Pos.Line)
			secEnd := s.Pos.Line
			for _, st := range s.Statements {
				grow(st.Pos.Line)
				last := st.Pos.Line
				if n := len(st.Tokens); n > 0 {
					last = st.Tokens[n-1].Line
				}
				grow(last)
				if last > secEnd {
					secEnd = last
				}
				add(st.Pos.Line, lineSpan{st.Pos.Line, st.Pos.Line})
			}
			add(s.Pos.Line, lineSpan{s.Pos.Line, secEnd})
		}
		add(r.Pos.Line, lineSpan{r.Pos.Line, ruleEnd})
	}

	// Sort by line; at equal lines put the widest span first, so a comment
	// before a section header maps to the section (block), not a statement.
	sort.Slice(as, func(i, j int) bool {
		if as[i].line != as[j].line {
			return as[i].line < as[j].line
		}
		return (as[i].span.to - as[i].span.from) > (as[j].span.to - as[j].span.from)
	})
	return as
}

// targetSpan resolves which lines a directive comment suppresses.
func targetSpan(as []anchor, c lexer.Comment) (lineSpan, bool) {
	// Trailing comment sharing a line with code → suppress that line only.
	for _, a := range as {
		if a.line == c.Line {
			return lineSpan{c.Line, c.Line}, true
		}
	}
	// Otherwise the first node that starts after the comment ends.
	for _, a := range as {
		if a.line > c.EndLine {
			return a.span, true
		}
	}
	return lineSpan{}, false
}

// knownRuleKeys returns every lowercase ID and name a directive may
// legitimately reference, including disabled rules and the engine-level
// pseudo-rules.
func (e *Engine) knownRuleKeys() map[string]bool {
	known := map[string]bool{
		strings.ToLower(SyntaxRuleID):         true,
		strings.ToLower(SyntaxRuleName):       true,
		strings.ToLower(DirectiveRuleID):      true,
		strings.ToLower(DirectiveRuleName):    true,
		strings.ToLower(WorkspaceDupRuleID):   true,
		strings.ToLower(WorkspaceDupRuleName): true,
	}
	for _, r := range e.all {
		known[strings.ToLower(r.ID())] = true
		known[strings.ToLower(r.Name())] = true
	}
	return known
}

// directiveDiagnostics reports info-level findings for comments that look
// like suppression directives but will not do what the author intended:
// misspelled directives and references to rules that do not exist. Silent
// directive loss is the worst failure mode, so it is surfaced explicitly.
func directiveDiagnostics(f *ast.File, known map[string]bool) []Violation {
	var vs []Violation
	report := func(c lexer.Comment, format string, args ...any) {
		vs = append(vs, Violation{
			RuleID: DirectiveRuleID, RuleName: DirectiveRuleName,
			Pos:      ast.Position{Line: c.Line, Column: c.Column},
			Severity: Info,
			Message:  fmt.Sprintf(format, args...),
		})
	}

	for _, c := range f.Comments {
		text := strings.TrimSpace(c.Text)
		names, ok := parseDisable(text)
		if !ok {
			// "yl2lint disable", "yl2lint-disble", etc.: intended but broken.
			if strings.HasPrefix(strings.ToLower(text), "yl2lint") {
				report(c, "comment %q looks like a suppression directive but is malformed; use `yl2lint-disable: <rule>[, <rule>...]`", text)
			}
			continue
		}
		for _, n := range names {
			if n == "*" || known[n] {
				continue
			}
			report(c, "suppression directive references unknown rule %q; it will have no effect", n)
		}
	}
	return vs
}
