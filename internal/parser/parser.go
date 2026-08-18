// Package parser builds the AST for YARA-L 2.0 rules from the lexer's token
// stream. It is a hand-written recursive-descent parser that collects errors
// instead of aborting, so a single malformed file still yields as many
// diagnostics as possible.
package parser

import (
	"fmt"
	"slices"

	"yl2lint/internal/ast"
	"yl2lint/internal/lexer"
)

// knownSections are the canonical YARA-L 2.0 rule section headers.
var knownSections = []string{"meta", "events", "match", "outcome", "condition", "options"}

// maxHeaderEditDistance controls how tolerant the fuzzy header matcher is.
// `conditon` → `condition` is distance 1; `evnts` → `events` is distance 1.
const maxHeaderEditDistance = 2

// ParseError is a syntax problem found while lexing or parsing.
type ParseError struct {
	Line   int
	Column int
	Msg    string
}

// Parser walks a token slice.
type Parser struct {
	toks []lexer.Token
	pos  int
	errs []ParseError
}

// Parse lexes and parses src, returning the AST alongside every syntax error
// encountered. The AST is always non-nil; badly broken input simply produces
// a sparser tree plus more errors.
func Parse(src []byte) (*ast.File, []ParseError) {
	toks, comments, lexErrs := lexer.TokenizeWithComments(src)
	p := &Parser{toks: toks}
	for _, e := range lexErrs {
		p.errs = append(p.errs, ParseError{Line: e.Line, Column: e.Column, Msg: e.Msg})
	}

	file := &ast.File{Comments: comments}
	for !p.atEOF() {
		if r := p.parseRule(); r != nil {
			file.Rules = append(file.Rules, r)
		}
	}
	return file, p.errs
}

// --- rule level -----------------------------------------------------------

func (p *Parser) parseRule() *ast.YaraLRule {
	t := p.cur()
	if !(t.Type == lexer.KEYWORD && t.Literal == "rule") {
		p.errorAt(t, "expected 'rule' keyword at top level, found %s", describe(t))
		p.advance() // always make progress
		return nil
	}
	r := &ast.YaraLRule{Pos: ast.PositionOf(t)}
	p.advance()

	if nt := p.cur(); nt.Type == lexer.IDENT {
		r.Name = nt.Literal
		r.NamePos = ast.PositionOf(nt)
		p.advance()
	} else {
		p.errorAt(nt, "expected rule name after 'rule' keyword, found %s", describe(nt))
	}

	open := p.cur()
	hadBody := open.Type == lexer.LBRACE
	if hadBody {
		p.advance()
	} else {
		p.errorAt(open, "expected '{' to open the body of rule %s, found %s", displayName(r), describe(open))
	}

	p.parseRuleBody(r)

	// The YARA-L 2.0 language reference lists `events:` and `condition:` as
	// required sections of every detection rule; a rule without them will be
	// rejected by Google SecOps. (The meta section is also expected, but its
	// absence is reported by the YL002 policy rule to avoid double-reporting.)
	// Skip the check when the body never opened — the '{' error is enough.
	if hadBody {
		if r.Events == nil {
			p.errorPos(r.Pos, "rule %s is missing the required \"events:\" section", displayName(r))
		}
		if r.Condition == nil {
			p.errorPos(r.Pos, "rule %s is missing the required \"condition:\" section", displayName(r))
		}
	}
	return r
}

func (p *Parser) parseRuleBody(r *ast.YaraLRule) {
	for {
		t := p.cur()
		switch {
		case t.Type == lexer.EOF:
			p.errorPos(r.Pos, "unclosed rule %s: missing '}' before end of file", displayName(r))
			return
		case t.Type == lexer.RBRACE:
			p.advance()
			return
		case t.Type == lexer.IDENT && p.peek(1).Type == lexer.COLON:
			p.parseSection(r)
		case t.Type == lexer.IDENT && isKnownSection(t.Literal):
			// A known header missing its colon, e.g. `events` on its own line.
			p.errorAt(t, "expected ':' after section header %q", t.Literal)
			p.advance() // consume header name; body collection follows
			p.buildSection(r, t.Literal, t.Literal, ast.PositionOf(t), p.collectSectionBody())
		default:
			p.errorAt(t, "expected a section header (e.g. \"events:\") inside the rule body, found %s", describe(t))
			p.skipToRecovery()
		}
	}
}

func (p *Parser) parseSection(r *ast.YaraLRule) {
	hdr := p.cur()
	raw := hdr.Literal
	hdrPos := ast.PositionOf(hdr)

	canonical, known := canonicalHeader(raw)
	switch {
	case !known:
		p.errorAt(hdr, "unknown section header %q", raw+":")
	case canonical != raw:
		p.errorAt(hdr, "unknown section header %q; did you mean %q?", raw+":", canonical+":")
	}

	p.advance() // header ident
	p.advance() // colon
	body := p.collectSectionBody()
	p.buildSection(r, canonical, raw, hdrPos, body)
}

// collectSectionBody gathers tokens until the next section header, the rule's
// closing brace, or EOF. A "next header" is an IDENT that starts its source
// line and is immediately followed by a colon — the line-start requirement
// keeps stray colons inside expressions from splitting a section.
func (p *Parser) collectSectionBody() []lexer.Token {
	var body []lexer.Token
	depth := 0
	for {
		t := p.cur()
		if t.Type == lexer.EOF {
			return body
		}
		if t.Type == lexer.RBRACE {
			if depth == 0 {
				return body
			}
			depth--
		}
		if t.Type == lexer.LBRACE {
			depth++
		}
		if depth == 0 && t.Type == lexer.IDENT && p.peek(1).Type == lexer.COLON && p.startsLine() {
			return body
		}
		body = append(body, t)
		p.advance()
	}
}

// skipToRecovery discards tokens after an unexpected-token error until a
// plausible resynchronisation point, avoiding one error per stray token.
func (p *Parser) skipToRecovery() {
	p.advance()
	for {
		t := p.cur()
		if t.Type == lexer.EOF || t.Type == lexer.RBRACE {
			return
		}
		if t.Type == lexer.IDENT && p.peek(1).Type == lexer.COLON && p.startsLine() {
			return
		}
		p.advance()
	}
}

// --- section construction -------------------------------------------------

func (p *Parser) buildSection(r *ast.YaraLRule, canonical, raw string, hdrPos ast.Position, body []lexer.Token) {
	r.Headers = append(r.Headers, ast.SectionHeader{Name: raw, Pos: hdrPos})
	if canonical == "" {
		return // unknown section: header error already reported, body ignored
	}

	if canonical == "meta" {
		if r.Meta != nil {
			p.errorPos(hdrPos, "duplicate section \"meta:\" in rule %s", displayName(r))
			return
		}
		r.Meta = p.parseMeta(hdrPos, body)
		return
	}

	sec := &ast.Section{Name: canonical, Pos: hdrPos, Statements: groupStatements(body)}
	sec.Variables = extractVariables(canonical, sec.Statements)

	assign := func(dst **ast.Section) {
		if *dst != nil {
			p.errorPos(hdrPos, "duplicate section %q in rule %s", canonical+":", displayName(r))
			return
		}
		*dst = sec
	}
	switch canonical {
	case "events":
		assign(&r.Events)
	case "match":
		assign(&r.Match)
	case "outcome":
		assign(&r.Outcome)
	case "condition":
		assign(&r.Condition)
	case "options":
		assign(&r.Options)
	}
}

// parseMeta enforces the `key = "value"` line grammar of the meta block.
func (p *Parser) parseMeta(hdrPos ast.Position, body []lexer.Token) *ast.MetaSection {
	sec := &ast.MetaSection{Pos: hdrPos}
	for _, line := range splitLines(body) {
		if len(line) == 0 {
			continue
		}
		key := line[0]
		wellFormed := (key.Type == lexer.IDENT || key.Type == lexer.KEYWORD) &&
			len(line) >= 3 &&
			line[1].Type == lexer.OPERATOR && line[1].Literal == "=" &&
			line[2].Type == lexer.STRING
		if !wellFormed {
			p.errorAt(key, "malformed meta entry: expected `key = \"value\"`")
			continue
		}
		if len(line) > 3 {
			p.errorAt(line[3], "unexpected tokens after meta value for key %q", key.Literal)
		}
		sec.Entries = append(sec.Entries, ast.MetaEntry{
			Key:   key.Literal,
			Value: line[2].Literal,
			Pos:   ast.PositionOf(key),
		})
	}
	return sec
}

// groupStatements splits a section body into per-line statements. Multi-line
// expressions end up as several statements, which is harmless for the current
// rules: the variable index spans the whole section regardless.
func groupStatements(body []lexer.Token) []ast.Statement {
	var stmts []ast.Statement
	for _, line := range splitLines(body) {
		if len(line) == 0 {
			continue
		}
		stmts = append(stmts, ast.Statement{Pos: ast.PositionOf(line[0]), Tokens: line})
	}
	return stmts
}

// splitLines groups a section body into logical statements rather than
// physical lines. A statement continues across a line break while any
// parenthesis or bracket is still open, or when the break sits next to a
// token that cannot end or begin a statement: a trailing comma, operator,
// dot, or binary keyword, or a leading one. This is what lets YL006 and the
// field extractors see a re.regex(...) call or an if(...) outcome split over
// several lines as a single statement.
func splitLines(body []lexer.Token) [][]lexer.Token {
	var lines [][]lexer.Token
	var cur []lexer.Token
	depth := 0
	lastLine := -1
	for _, t := range body {
		if len(cur) > 0 && t.Line != lastLine && depth == 0 && !joins(cur[len(cur)-1], t) {
			lines = append(lines, cur)
			cur = nil
		}
		lastLine = t.Line
		cur = append(cur, t)
		switch t.Type {
		case lexer.LPAREN, lexer.LBRACKET:
			depth++
		case lexer.RPAREN, lexer.RBRACKET:
			if depth > 0 {
				depth--
			}
		}
	}
	if len(cur) > 0 {
		lines = append(lines, cur)
	}
	return lines
}

// joins reports whether a line break between prev and next is a continuation
// of the same logical statement.
func joins(prev, next lexer.Token) bool {
	switch prev.Type {
	case lexer.COMMA, lexer.DOT, lexer.OPERATOR:
		return true
	case lexer.KEYWORD:
		switch prev.Literal {
		case "and", "or", "not", "in", "over", "before", "after", "if", "else":
			return true
		}
	}
	switch next.Type {
	case lexer.COMMA, lexer.DOT, lexer.OPERATOR, lexer.RPAREN, lexer.RBRACKET:
		return true
	case lexer.KEYWORD:
		switch next.Literal {
		case "and", "or", "in", "over", "nocase", "before", "after", "else":
			return true
		}
	}
	return false
}

// extractVariables builds the flattened variable index for a section. In the
// events and outcome sections, `$var` at the start of a statement followed by `=` is a
// variable definition rather than a use of an event variable.
func extractVariables(section string, stmts []ast.Statement) []ast.VariableRef {
	var refs []ast.VariableRef
	for _, st := range stmts {
		for i, t := range st.Tokens {
			if t.Type != lexer.EVENTVAR && t.Type != lexer.COUNTVAR {
				continue
			}
			kind := ast.EventVar
			if t.Type == lexer.COUNTVAR {
				kind = ast.CountVar
			}

			isDef := false
			if kind == ast.EventVar {
				// LHS assignment: `$x = ...` at statement start. In outcome
				// these are outcome variables; in events they are computed
				// placeholders ($sev = re.regex(...)).
				lhs := (section == "outcome" || section == "events") &&
					i == 0 && len(st.Tokens) > 1 &&
					st.Tokens[1].Type == lexer.OPERATOR && st.Tokens[1].Literal == "="

				// RHS binding: `<field ref> = $x` in events, where $x is bare
				// (not followed by a dot) — the placeholder-binding pattern.
				// A dotted RHS ($e2.field) is a cross-event join, not a binding.
				bare := i+1 >= len(st.Tokens) || st.Tokens[i+1].Type != lexer.DOT
				rhs := section == "events" && bare && i > 0 &&
					st.Tokens[i-1].Type == lexer.OPERATOR && st.Tokens[i-1].Literal == "="

				isDef = lhs || rhs
			}

			refs = append(refs, ast.VariableRef{
				Name:         t.Literal[1:],
				Text:         t.Literal,
				Kind:         kind,
				Pos:          ast.PositionOf(t),
				IsDefinition: isDef,
			})
		}
	}
	return refs
}

// --- header matching ------------------------------------------------------

func isKnownSection(name string) bool {
	return slices.Contains(knownSections, name)
}

// canonicalHeader resolves a raw header name to its canonical section.
// Exact matches pass through; near-misses (edit distance ≤ 2) resolve to the
// closest known header so parsing — and downstream rules — can continue.
func canonicalHeader(name string) (string, bool) {
	if isKnownSection(name) {
		return name, true
	}
	best, bestDist := "", maxHeaderEditDistance+1
	for _, s := range knownSections {
		if d := levenshtein(name, s); d < bestDist {
			best, bestDist = s, d
		}
	}
	if bestDist <= maxHeaderEditDistance {
		return best, true
	}
	return "", false
}

// --- token cursor ---------------------------------------------------------

func (p *Parser) cur() lexer.Token {
	if p.pos >= len(p.toks) {
		return p.toks[len(p.toks)-1] // trailing EOF
	}
	return p.toks[p.pos]
}

func (p *Parser) peek(n int) lexer.Token {
	if p.pos+n >= len(p.toks) {
		return p.toks[len(p.toks)-1]
	}
	return p.toks[p.pos+n]
}

func (p *Parser) startsLine() bool {
	if p.pos == 0 {
		return true
	}
	return p.toks[p.pos].Line > p.toks[p.pos-1].Line
}

func (p *Parser) advance() {
	if p.pos < len(p.toks)-1 {
		p.pos++
	} else {
		p.pos = len(p.toks) // sit past the EOF token
	}
}

func (p *Parser) atEOF() bool { return p.cur().Type == lexer.EOF }

// --- error helpers --------------------------------------------------------

func (p *Parser) errorAt(t lexer.Token, format string, args ...any) {
	p.errs = append(p.errs, ParseError{Line: t.Line, Column: t.Column, Msg: fmt.Sprintf(format, args...)})
}

func (p *Parser) errorPos(pos ast.Position, format string, args ...any) {
	p.errs = append(p.errs, ParseError{Line: pos.Line, Column: pos.Column, Msg: fmt.Sprintf(format, args...)})
}

func describe(t lexer.Token) string {
	switch t.Type {
	case lexer.EOF:
		return "end of file"
	case lexer.STRING:
		return fmt.Sprintf("string %q", t.Literal)
	default:
		return fmt.Sprintf("%q", t.Literal)
	}
}

func displayName(r *ast.YaraLRule) string {
	if r.Name == "" {
		return "<unnamed>"
	}
	return fmt.Sprintf("%q", r.Name)
}
