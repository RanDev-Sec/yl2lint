// Package ast defines the syntax tree produced by the parser and consumed by
// every lint rule. The tree is deliberately shallow: rigid top-level structure
// (rule → sections), raw token statements below that, plus a flattened
// variable index per section so lifecycle checks are simple set operations.
package ast

import "yl2lint/internal/lexer"

// Position is a 1-based source location. It is embedded in every node so
// violations always report an exact line and column.
type Position struct {
	Line   int
	Column int
}

// PositionOf converts a lexer token's location into a Position.
func PositionOf(t lexer.Token) Position {
	return Position{Line: t.Line, Column: t.Column}
}

// File is one parsed .yaral file. YARA-L files usually hold a single rule but
// multiple rules per file are supported.
type File struct {
	Path  string
	Rules []*YaraLRule
}

// YaraLRule is one `rule name { ... }` block.
type YaraLRule struct {
	Name    string
	NamePos Position
	Pos     Position // position of the `rule` keyword

	Meta      *MetaSection
	Events    *Section
	Match     *Section
	Outcome   *Section
	Condition *Section
	Options   *Section

	// Headers records every section header encountered, in source order and
	// with its raw (possibly misspelled) name — useful for ordering and
	// duplicate checks.
	Headers []SectionHeader
}

// SectionHeader is one `name:` header inside a rule body.
type SectionHeader struct {
	Name string // raw text as written, e.g. "conditon"
	Pos  Position
}

// MetaSection is the parsed `meta:` block.
type MetaSection struct {
	Pos     Position
	Entries []MetaEntry
}

// MetaEntry is one `key = "value"` line in the meta block.
type MetaEntry struct {
	Key   string
	Value string
	Pos   Position
}

// Section is any non-meta block (events, match, outcome, condition, options).
type Section struct {
	Name       string // canonical name: "events", "condition", ...
	Pos        Position
	Statements []Statement
	Variables  []VariableRef // flattened index of every $var/#var occurrence
}

// Statement is one logical line of a section, kept as raw tokens so future
// expression-level rules can be built without reparsing files.
type Statement struct {
	Pos    Position
	Tokens []lexer.Token
}

// VarKind distinguishes `$name` references from `#name` count references.
type VarKind int

const (
	EventVar VarKind = iota // $name
	CountVar                // #name
)

// VariableRef is a single occurrence of a variable inside a section.
type VariableRef struct {
	Name string // without sigil: "login"
	Text string // as written: "$login" / "#login"
	Kind VarKind
	Pos  Position

	// IsDefinition is true for the left-hand side of an assignment in the
	// outcome section ($risk_score = ...). Such outcome variables are
	// definitions, not uses of event variables, and must be excluded from
	// the "used but never declared in events" check.
	IsDefinition bool
}
