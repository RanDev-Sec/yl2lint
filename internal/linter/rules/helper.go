package rules

import (
	"strconv"
	"time"

	"yl2lint/internal/ast"
	"yl2lint/internal/lexer"
)

// fieldRef is one `$var.a.b.c` occurrence: variable plus dotted UDM path.
type fieldRef struct {
	VarName string
	Path    string
	Pos     ast.Position
}

// extractFieldPaths scans a section's raw token statements for event-variable
// field accesses.
func extractFieldPaths(sec *ast.Section) []fieldRef {
	if sec == nil {
		return nil
	}
	var refs []fieldRef
	for _, st := range sec.Statements {
		toks := st.Tokens
		for i := 0; i < len(toks); i++ {
			if toks[i].Type != lexer.EVENTVAR {
				continue
			}
			if i+2 >= len(toks) || toks[i+1].Type != lexer.DOT || toks[i+2].Type != lexer.IDENT {
				continue
			}
			path := toks[i+2].Literal
			j := i + 3
			for j+1 < len(toks) && toks[j].Type == lexer.DOT && toks[j+1].Type == lexer.IDENT {
				path += "." + toks[j+1].Literal
				j += 2
			}
			refs = append(refs, fieldRef{
				VarName: toks[i].Literal[1:],
				Path:    path,
				Pos:     ast.PositionOf(toks[i+2]),
			})
			i = j - 1
		}
	}
	return refs
}

// call is one function invocation found in a statement, e.g. re.regex(...).
// Multi-line calls are not reassembled (statements are per-line), matching
// the shallow-AST tradeoff documented in the parser.
type call struct {
	Name string
	Pos  ast.Position
	Args [][]lexer.Token
}

// extractCalls finds `name(...)` and `ns.name(...)` invocations in a section.
func extractCalls(sec *ast.Section) []call {
	if sec == nil {
		return nil
	}
	var out []call
	for _, st := range sec.Statements {
		toks := st.Tokens
		for i := 0; i < len(toks); i++ {
			if toks[i].Type != lexer.IDENT && toks[i].Type != lexer.KEYWORD {
				continue
			}
			name := toks[i].Literal
			pos := ast.PositionOf(toks[i])
			j := i + 1
			for j+1 < len(toks) && toks[j].Type == lexer.DOT && toks[j+1].Type == lexer.IDENT {
				name += "." + toks[j+1].Literal
				j += 2
			}
			if j >= len(toks) || toks[j].Type != lexer.LPAREN {
				continue
			}
			args, end := splitArgs(toks, j)
			out = append(out, call{Name: name, Pos: pos, Args: args})
			i = end
		}
	}
	return out
}

// splitArgs collects arguments between the LPAREN at open and its matching
// RPAREN, splitting on top-level commas. Returns the args and the index of
// the closing paren (or the last consumed token).
func splitArgs(toks []lexer.Token, open int) ([][]lexer.Token, int) {
	var args [][]lexer.Token
	var cur []lexer.Token
	depth := 1
	i := open + 1
	for ; i < len(toks); i++ {
		t := toks[i]
		switch t.Type {
		case lexer.LPAREN, lexer.LBRACKET:
			depth++
		case lexer.RPAREN, lexer.RBRACKET:
			depth--
			if depth == 0 {
				if len(cur) > 0 {
					args = append(args, cur)
				}
				return args, i
			}
		case lexer.COMMA:
			if depth == 1 {
				args = append(args, cur)
				cur = nil
				continue
			}
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		args = append(args, cur)
	}
	return args, i - 1
}

// sectionVarNames returns the set of event-variable names in a section.
func sectionVarNames(sec *ast.Section) map[string]bool {
	names := map[string]bool{}
	if sec == nil {
		return names
	}
	for _, v := range sec.Variables {
		names[v.Name] = true
	}
	return names
}

// unquotePattern resolves the escapes of a double-quoted string literal; raw
// (backtick) strings, whose content contains no processable escapes, fall
// through unchanged.
func unquotePattern(lit string) string {
	if s, err := strconv.Unquote(`"` + lit + `"`); err == nil {
		return s
	}
	return lit
}

// parseWindow converts a match-window duration literal (30s, 15m, 24h, 14d)
// into a time.Duration.
func parseWindow(lit string) (time.Duration, bool) {
	if lit == "" {
		return 0, false
	}
	i := 0
	for i < len(lit) && lit[i] >= '0' && lit[i] <= '9' {
		i++
	}
	if i == 0 || i == len(lit) {
		return 0, false
	}
	n, err := strconv.Atoi(lit[:i])
	if err != nil {
		return 0, false
	}
	switch lit[i:] {
	case "s":
		return time.Duration(n) * time.Second, true
	case "m":
		return time.Duration(n) * time.Minute, true
	case "h":
		return time.Duration(n) * time.Hour, true
	case "d":
		return time.Duration(n) * 24 * time.Hour, true
	}
	return 0, false
}