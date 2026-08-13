// Package rules holds the concrete lint-rule strategies. Each rule lives in
// its own file and implements linter.Rule; registration happens from the CLI
// via All(), keeping linter <- rules a one-way dependency.
package rules

import "yl2lint/internal/linter"

// All returns every built-in rule. Add new Day 2+ rules here.
func All() []linter.Rule {
	return []linter.Rule{
		MetaRequiredKeys{},
		VariableLifecycle{},
	}
}
