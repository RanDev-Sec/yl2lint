// Package lexer turns YARA-L 2.0 source into a stream of positioned tokens.
// It is a hand-written byte scanner — no regular expressions are involved.
package lexer

import (
	"bytes"
	"fmt"
	"strings"
)

// Lexer scans a byte slice into Tokens.
type Lexer struct {
	src  []byte
	pos  int
	line int
	col  int
	errs []Error

	comments []Comment // captured side-channel, see Comment

	// prevType/prevLit track the last emitted token so `/` can be
	// disambiguated: after `=`, `!=`, `(`, `,` or a keyword it opens a regex
	// literal (`$u.userid = /adm.n/ nocase`); anywhere else it is division.
	prevType TokenType
	prevLit  string
}

// New returns a Lexer positioned at the start of src.
func New(src []byte) *Lexer {
	return &Lexer{src: src, line: 1, col: 1}
}

// Errors returns lexical errors accumulated so far.
func (l *Lexer) Errors() []Error { return l.errs }

func TokenizeWithComments(src []byte) ([]Token, []Comment, []Error) {
	l := New(src)
	var toks []Token
	for {
		t := l.Next()
		toks = append(toks, t)
		if t.Type == EOF {
			break
		}
	}
	return toks, l.comments, l.errs
}

// Tokenize scans src to completion. The returned slice always ends with an
// EOF token. Comments are consumed and never emitted as tokens.
func Tokenize(src []byte) ([]Token, []Error) {
	toks, _, errs := TokenizeWithComments(src)
	return toks, errs
}

// Next returns the next token.
func (l *Lexer) Next() Token {
	l.skipSpaceAndComments()

	startLine, startCol := l.line, l.col
	if l.pos >= len(l.src) {
		return Token{Type: EOF, Line: startLine, Column: startCol}
	}

	c := l.src[l.pos]
	switch {
	case c == '$' || c == '#' || c == '%':
		return l.lexVariable(c, startLine, startCol)
	case isIdentStart(c):
		return l.lexIdent(startLine, startCol)
	case isDigit(c):
		return l.lexNumber(startLine, startCol)
	case c == '"':
		return l.lexQuotedString(startLine, startCol)
	case c == '`':
		return l.lexRawString(startLine, startCol)
	case c == '/':
		if l.regexAllowed() {
			return l.lexRegex(startLine, startCol)
		}
		l.advance()
		return l.emit(Token{Type: OPERATOR, Literal: "/", Line: startLine, Column: startCol})
	}

	single := func(tt TokenType) Token {
		l.advance()
		return l.emit(Token{Type: tt, Literal: string(c), Line: startLine, Column: startCol})
	}

	switch c {
	case ':':
		return single(COLON)
	case '{':
		return single(LBRACE)
	case '}':
		return single(RBRACE)
	case '(':
		return single(LPAREN)
	case ')':
		return single(RPAREN)
	case '[':
		return single(LBRACKET)
	case ']':
		return single(RBRACKET)
	case ',':
		return single(COMMA)
	case '.':
		return single(DOT)
	case '+', '-', '*':
		return single(OPERATOR)
	case '=', '!', '>', '<':
		l.advance()
		lit := string(c)
		if l.pos < len(l.src) && l.src[l.pos] == '=' { // != >= <= == (== tolerated)
			lit += "="
			l.advance()
		}
		return l.emit(Token{Type: OPERATOR, Literal: lit, Line: startLine, Column: startCol})
	}

	// Anything else is illegal; report it once and keep scanning so the
	// parser can still recover the overall structure.
	l.errorf(startLine, startCol, "unexpected character %q", string(c))
	l.advance()
	return l.emit(Token{Type: ILLEGAL, Literal: string(c), Line: startLine, Column: startCol})
}

// --- scanners -------------------------------------------------------------

func (l *Lexer) lexVariable(sigil byte, line, col int) Token {
	l.advance() // consume sigil
	start := l.pos
	for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) {
		l.advance()
	}
	name := string(l.src[start:l.pos])
	if name == "" {
		l.errorf(line, col, "expected an identifier after %q", string(sigil))
		return l.emit(Token{Type: ILLEGAL, Literal: string(sigil), Line: line, Column: col})
	}
	tt := EVENTVAR
	switch sigil {
	case '#':
		tt = COUNTVAR
	case '%':
		tt = PLACEHOLDER
	}
	return l.emit(Token{Type: tt, Literal: string(sigil) + name, Line: line, Column: col})
}

func (l *Lexer) lexIdent(line, col int) Token {
	start := l.pos
	for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) {
		l.advance()
	}
	lit := string(l.src[start:l.pos])
	tt := IDENT
	if keywords[lit] {
		tt = KEYWORD
	}
	return l.emit(Token{Type: tt, Literal: lit, Line: line, Column: col})
}

// lexNumber accepts integers, simple decimals (1.5) and duration literals
// used by `match ... over` windows (15m, 24h, 7d).
func (l *Lexer) lexNumber(line, col int) Token {
	start := l.pos
	for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
		l.advance()
	}
	if l.pos+1 < len(l.src) && l.src[l.pos] == '.' && isDigit(l.src[l.pos+1]) {
		l.advance() // '.'
		for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
			l.advance()
		}
	}
	for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) { // duration suffix
		l.advance()
	}
	return l.emit(Token{Type: NUMBER, Literal: string(l.src[start:l.pos]), Line: line, Column: col})
}

func (l *Lexer) lexQuotedString(line, col int) Token {
	l.advance() // opening quote
	start := l.pos
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '\\' && l.pos+1 < len(l.src) {
			l.advance()
			l.advance()
			continue
		}
		if c == '\n' {
			l.errorf(line, col, "unterminated string literal")
			return l.emit(Token{Type: STRING, Literal: string(l.src[start:l.pos]), Line: line, Column: col})
		}
		if c == '"' {
			lit := string(l.src[start:l.pos])
			l.advance() // closing quote
			return l.emit(Token{Type: STRING, Literal: lit, Line: line, Column: col})
		}
		l.advance()
	}
	l.errorf(line, col, "unterminated string literal (reached end of file)")
	return l.emit(Token{Type: STRING, Literal: string(l.src[start:l.pos]), Line: line, Column: col})
}

// lexRawString scans a backtick-delimited raw string (used for regex patterns
// in re.regex(...) calls). No escapes are processed.
func (l *Lexer) lexRawString(line, col int) Token {
	l.advance() // opening backtick
	start := l.pos
	for l.pos < len(l.src) {
		if l.src[l.pos] == '`' {
			lit := string(l.src[start:l.pos])
			l.advance()
			return l.emit(Token{Type: STRING, Literal: lit, Line: line, Column: col})
		}
		l.advance()
	}
	l.errorf(line, col, "unterminated raw string literal (reached end of file)")
	return l.emit(Token{Type: STRING, Literal: string(l.src[start:l.pos]), Line: line, Column: col})
}

// lexRegex scans a /.../ literal. It must be consumed as one token: regex
// quantifiers such as {2,4} would otherwise corrupt the parser's brace
// matching for the rule body.
func (l *Lexer) lexRegex(line, col int) Token {
	l.advance() // opening slash
	start := l.pos
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '\\' && l.pos+1 < len(l.src) {
			l.advance()
			l.advance()
			continue
		}
		if c == '\n' {
			l.errorf(line, col, "unterminated regular expression literal")
			return l.emit(Token{Type: REGEX, Literal: string(l.src[start:l.pos]), Line: line, Column: col})
		}
		if c == '/' {
			lit := string(l.src[start:l.pos])
			l.advance()
			return l.emit(Token{Type: REGEX, Literal: lit, Line: line, Column: col})
		}
		l.advance()
	}
	l.errorf(line, col, "unterminated regular expression literal (reached end of file)")
	return l.emit(Token{Type: REGEX, Literal: string(l.src[start:l.pos]), Line: line, Column: col})
}

// --- helpers --------------------------------------------------------------

func (l *Lexer) regexAllowed() bool {
	if l.prevType == OPERATOR {
		return l.prevLit == "=" || l.prevLit == "!=" || l.prevLit == "=="
	}
	return l.prevType == LPAREN || l.prevType == COMMA || l.prevType == KEYWORD
}

func (l *Lexer) skipSpaceAndComments() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			l.advance()

		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			l.captureLineComment(2)

		// `#` opens a count variable (#login) when followed by an identifier;
		// followed by whitespace or end-of-line it is a line comment. The
		// literal prefix `#yl2lint` is always a comment, so a directive typed
		// without a space (#yl2lint-disable: ...) cannot silently become a
		// count variable named "yl2lint".
		case c == '#' && (l.pos+1 >= len(l.src) ||
			l.src[l.pos+1] == ' ' || l.src[l.pos+1] == '\t' ||
			l.src[l.pos+1] == '\r' || l.src[l.pos+1] == '\n' ||
			bytes.HasPrefix(l.src[l.pos:], []byte("#yl2lint"))):
			l.captureLineComment(1)

		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*':
			line, col := l.line, l.col
			start := l.pos
			l.advance()
			l.advance()
			closed := false
			for l.pos < len(l.src) {
				if l.src[l.pos] == '*' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
					l.advance()
					l.advance()
					closed = true
					break
				}
				l.advance()
			}
			if !closed {
				l.errorf(line, col, "unterminated block comment")
			}
			text := string(l.src[start+2 : l.pos])
			if closed {
				text = strings.TrimSuffix(text, "*/")
			}
			l.comments = append(l.comments, Comment{
				Text: strings.TrimSpace(text), Line: line, Column: col, EndLine: l.line,
			})
		default:
			return
		}
	}
}

// captureLineComment consumes a line comment whose marker is markerLen bytes
// long ("//" or "#") and records it.
func (l *Lexer) captureLineComment(markerLen int) {
	line, col := l.line, l.col
	start := l.pos
	for l.pos < len(l.src) && l.src[l.pos] != '\n' {
		l.advance()
	}
	text := strings.TrimSpace(string(l.src[start+markerLen : l.pos]))
	l.comments = append(l.comments, Comment{Text: text, Line: line, Column: col, EndLine: line})
}

func (l *Lexer) advance() {
	if l.pos >= len(l.src) {
		return
	}
	if l.src[l.pos] == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	l.pos++
}

func (l *Lexer) emit(t Token) Token {
	l.prevType = t.Type
	l.prevLit = t.Literal
	return t
}

func (l *Lexer) errorf(line, col int, format string, args ...any) {
	l.errs = append(l.errs, Error{Line: line, Column: col, Msg: fmt.Sprintf(format, args...)})
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool { return isIdentStart(c) || isDigit(c) }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
