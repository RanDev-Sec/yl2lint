package rules

import (
	"fmt"
	"regexp"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/lexer"
	"yl2lint/internal/linter"
)

// defaultListNaming is the naming convention applied when the config does
// not override reference_lists.naming.
const defaultListNaming = `^[A-Za-z][A-Za-z0-9_]*$`

// ReferenceLists (YL013) validates %reference_list usage: names must match
// the configured naming convention, and when the config supplies a `known`
// allowlist, every referenced list must be in it.
type ReferenceLists struct{}

func (ReferenceLists) ID() string   { return "YL013" }
func (ReferenceLists) Name() string { return "reference-lists" }
func (ReferenceLists) Description() string {
	return "%reference_list names must match the configured naming convention and, when configured, the known-list allowlist"
}

func (rl ReferenceLists) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	sev := linter.SeverityFor(cfg, rl.ID(), rl.Name(), linter.Warning)

	pattern := cfg.ReferenceLists.Naming
	if pattern == "" {
		pattern = defaultListNaming
	}
	naming, reErr := regexp.Compile(pattern)

	known := map[string]bool{}
	for _, k := range cfg.ReferenceLists.Known {
		known[k] = true
	}

	var vs []linter.Violation
	warn := func(pos ast.Position, format string, args ...any) {
		vs = append(vs, linter.Violation{
			RuleID: rl.ID(), RuleName: rl.Name(), Pos: pos, Severity: sev,
			Message: fmt.Sprintf(format, args...),
		})
	}

	reportedBadPattern := false
	for _, r := range f.Rules {
		for _, sec := range []*ast.Section{r.Events, r.Match, r.Outcome, r.Condition} {
			if sec == nil {
				continue
			}
			for _, st := range sec.Statements {
				for _, t := range st.Tokens {
					if t.Type != lexer.PLACEHOLDER {
						continue
					}
					name := t.Literal[1:]
					switch {
					case reErr != nil:
						if !reportedBadPattern {
							warn(ast.PositionOf(t),
								"config reference_lists.naming %q is not a valid regex: %v; naming checks skipped", pattern, reErr)
							reportedBadPattern = true
						}
					case !naming.MatchString(name):
						warn(ast.PositionOf(t),
							"reference list %%%s does not match the naming convention %q", name, pattern)
					}
					if len(known) > 0 && !known[name] {
						warn(ast.PositionOf(t),
							"reference list %%%s is not in reference_lists.known; it may not exist in the workspace", name)
					}
				}
			}
		}
	}
	return vs
}
