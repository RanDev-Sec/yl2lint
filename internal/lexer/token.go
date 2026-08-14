package lexer

import "fmt"

// TokenType identifies the lexical class of a token.
type TokenType int

const (
	ILLEGAL TokenType = iota
	EOF
	IDENT       // metadata, principal, userid, max
	KEYWORD     // rule, and, or, not, over, nocase, if, ...
	EVENTVAR    // $login
	COUNTVAR    // #login   (count-of reference in condition)
	PLACEHOLDER // %suspicious_ips (reference list)
	STRING      // "USER_LOGIN"  or  `raw string`
	REGEX       // /adm.n/
	NUMBER      // 3, 1.5, 15m
	COLON       // :
	LBRACE      // {
	RBRACE      // }
	LPAREN      // (
	RPAREN      // )
	LBRACKET    // [
	RBRACKET    // ]
	COMMA       // ,
	DOT         // .
	OPERATOR    // = != > < >= <= + - * / !
)

var tokenNames = map[TokenType]string{
	ILLEGAL:     "ILLEGAL",
	EOF:         "EOF",
	IDENT:       "IDENT",
	KEYWORD:     "KEYWORD",
	EVENTVAR:    "EVENTVAR",
	COUNTVAR:    "COUNTVAR",
	PLACEHOLDER: "PLACEHOLDER",
	STRING:      "STRING",
	REGEX:       "REGEX",
	NUMBER:      "NUMBER",
	COLON:       "COLON",
	LBRACE:      "LBRACE",
	RBRACE:      "RBRACE",
	LPAREN:      "LPAREN",
	RPAREN:      "RPAREN",
	LBRACKET:    "LBRACKET",
	RBRACKET:    "RBRACKET",
	COMMA:       "COMMA",
	DOT:         "DOT",
	OPERATOR:    "OPERATOR",
}

func (t TokenType) String() string {
	if n, ok := tokenNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TokenType(%d)", int(t))
}

// Token is a single lexical unit with its 1-based source position.
type Token struct {
	Type    TokenType
	Literal string // for STRING/REGEX: the content without delimiters; for variables: includes the sigil ($e, #e, %list)
	Line    int
	Column  int
}

// Error is a lexical error (unterminated string, stray character, ...).
type Error struct {
	Line   int
	Column int
	Msg    string
}

// keywords that are reserved words rather than plain identifiers.
// Section names (meta, events, ...) are deliberately NOT keywords: they are
// ordinary identifiers that the parser promotes to headers when followed by
// a colon at the start of a line, so field paths like `security_result` or a
// UDM field literally named `match` cannot confuse the lexer.
var keywords = map[string]bool{
	"rule": true, "and": true, "or": true, "not": true,
	"over": true, "nocase": true, "in": true, "if": true, "else": true,
	"all": true, "any": true, "before": true, "after": true,
	"null": true, "true": true, "false": true,
	// `in regex` / `in cidr` reference-list comparison operators.
	"regex": true, "cidr": true,
}

// Comment is a source comment captured while scanning. Comments never enter
// the token stream; they are collected on the side so the linter can honour
// inline suppression directives such as `// yl2lint-disable: udm-schema`.
type Comment struct {
	Text    string // content without the //, /* */ or # markers, trimmed
	Line    int    // line the comment starts on
	Column  int
	EndLine int // last line covered (block comments may span lines)
}