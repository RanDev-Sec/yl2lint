// Package format contains write-side utilities: minimally invasive source
// edits driven by AST positions, so user formatting and comments survive.
package format

import (
	"fmt"
	"sort"
	"strings"

	"yl2lint/internal/ast"
)

// Placeholder is the value injected for a missing meta key.
const Placeholder = "TODO"

// MetaFix requests that Keys be added to the meta block of Rule.
type MetaFix struct {
	Rule *ast.YaraLRule
	Keys []string
}

// InjectMetaKeys returns src with each fix's missing meta keys inserted as
// `key = "TODO"` lines. Rules without a meta: section get one created right
// after the rule's opening brace. The second return value reports whether any
// change was made.
func InjectMetaKeys(src []byte, fixes []MetaFix) ([]byte, bool) {
	lines := strings.Split(string(src), "\n")

	type edit struct {
		afterIdx int // 0-based line index to insert after
		add      []string
	}
	var edits []edit

	for _, fx := range fixes {
		if fx.Rule == nil || len(fx.Keys) == 0 {
			continue
		}
		r := fx.Rule

		if r.Meta != nil {
			// Insert after the last existing entry (or after the header).
			afterIdx := r.Meta.Pos.Line - 1
			indent := indentOf(safeLine(lines, afterIdx)) + "  "
			if n := len(r.Meta.Entries); n > 0 {
				afterIdx = r.Meta.Entries[n-1].Pos.Line - 1
				indent = indentOf(safeLine(lines, afterIdx))
			}
			var add []string
			for _, k := range fx.Keys {
				add = append(add, fmt.Sprintf("%s%s = %q", indent, k, Placeholder))
			}
			edits = append(edits, edit{afterIdx: afterIdx, add: add})
			continue
		}

		// No meta section: create one after the line holding the rule's '{'.
		braceIdx := -1
		for i := r.Pos.Line - 1; i < len(lines); i++ {
			if strings.Contains(lines[i], "{") {
				braceIdx = i
				break
			}
		}
		if braceIdx < 0 {
			continue // rule body never opened; nothing safe to do
		}
		secIndent := indentOf(safeLine(lines, r.Pos.Line-1)) + "  "
		entryIndent := secIndent + "  "
		add := []string{secIndent + "meta:"}
		for _, k := range fx.Keys {
			add = append(add, fmt.Sprintf("%s%s = %q", entryIndent, k, Placeholder))
		}
		add = append(add, "") // blank line before the next section
		edits = append(edits, edit{afterIdx: braceIdx, add: add})
	}

	if len(edits) == 0 {
		return src, false
	}

	// Apply bottom-up so earlier insertions don't shift later indices.
	sort.Slice(edits, func(i, j int) bool { return edits[i].afterIdx > edits[j].afterIdx })
	for _, e := range edits {
		at := e.afterIdx + 1
		if at > len(lines) {
			at = len(lines)
		}
		lines = append(lines[:at], append(append([]string{}, e.add...), lines[at:]...)...)
	}
	return []byte(strings.Join(lines, "\n")), true
}

func safeLine(lines []string, idx int) string {
	if idx >= 0 && idx < len(lines) {
		return lines[idx]
	}
	return ""
}

func indentOf(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] != ' ' && line[i] != '\t' {
			return line[:i]
		}
	}
	return line
}