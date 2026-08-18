package rules

import (
	"fmt"
	"net"
	"regexp"

	"yl2lint/internal/ast"
	"yl2lint/internal/config"
	"yl2lint/internal/lexer"
	"yl2lint/internal/linter"
)

type fnSig struct {
	min, max int // max == -1 means variadic
}

var fnSigs = map[string]fnSig{
	"re.regex":                  {2, 2},
	"re.capture":                {2, 2},
	"net.ip_in_range_cidr":      {2, 2},
	"strings.coalesce":          {2, -1},
	"strings.concat":            {2, -1},
	"strings.to_lower":          {1, 1},
	"strings.to_upper":          {1, 1},
	"math.abs":                  {1, 1},
	"math.round":                {1, 2},
	"arrays.contains":           {2, 2},
	"timestamp.get_day_of_week": {1, 2},
	"timestamp.get_hour":        {1, 2},
	"timestamp.get_date":        {1, 2},
	"timestamp.current_seconds": {0, 0},
}

// FunctionAndOperator (YL006) type-checks built-in YARA-L function calls:
// argument counts, literal argument types, RE2 validity of regex patterns
// (Go's regexp package is RE2, exactly like Chronicle), and CIDR validity.
type FunctionAndOperator struct{}

func (FunctionAndOperator) ID() string   { return "YL006" }
func (FunctionAndOperator) Name() string { return "function-signature" }
func (FunctionAndOperator) Description() string {
	return "built-in function calls must have valid argument counts/types; regex patterns must compile under RE2; CIDR literals must parse"
}

func (fn FunctionAndOperator) Check(f *ast.File, cfg *config.Config) []linter.Violation {
	sev := linter.SeverityFor(cfg, fn.ID(), fn.Name(), linter.Error)

	var vs []linter.Violation
	report := func(pos ast.Position, format string, args ...any) {
		vs = append(vs, linter.Violation{
			RuleID: fn.ID(), RuleName: fn.Name(), Pos: pos, Severity: sev,
			Message: fmt.Sprintf(format, args...),
		})
	}

	for _, r := range f.Rules {
		for _, sec := range []*ast.Section{r.Events, r.Match, r.Outcome, r.Condition} {
			for _, c := range extractCalls(sec) {
				sig, known := fnSigs[c.Name]
				if !known {
					continue
				}

				got := len(c.Args)
				switch {
				case sig.max == -1 && got < sig.min:
					report(c.Pos, "%s expects at least %d arguments, got %d", c.Name, sig.min, got)
					continue
				case sig.max != -1 && (got < sig.min || got > sig.max):
					if sig.min == sig.max {
						report(c.Pos, "%s expects exactly %d argument(s), got %d", c.Name, sig.min, got)
					} else {
						report(c.Pos, "%s expects %d to %d arguments, got %d", c.Name, sig.min, sig.max, got)
					}
					continue
				}

				switch c.Name {
				case "re.regex", "re.capture":
					checkPatternArg(c, 1, report)

				case "net.ip_in_range_cidr":
					cidr := c.Args[1]
					if len(cidr) == 1 && cidr[0].Type == lexer.STRING {
						if _, _, err := net.ParseCIDR(cidr[0].Literal); err != nil {
							report(ast.PositionOf(cidr[0]), "%s: invalid CIDR %q: %v", c.Name, cidr[0].Literal, err)
						}
					} else {
						report(c.Pos, "%s: second argument must be a string CIDR literal (e.g. \"10.0.0.0/8\")", c.Name)
					}

				case "math.abs", "math.round":
					arg := c.Args[0]
					if len(arg) == 1 && arg[0].Type == lexer.STRING {
						report(ast.PositionOf(arg[0]), "%s: first argument must be numeric, got a string literal", c.Name)
					}
				}
			}
		}
	}
	return vs
}

// checkPatternArg validates that argument idx of a call is a string-literal
// regex pattern that compiles under RE2.
func checkPatternArg(c call, idx int, report func(ast.Position, string, ...any)) {
	pat := c.Args[idx]
	switch {
	case len(pat) == 1 && pat[0].Type == lexer.STRING:
		p := unquotePattern(pat[0].Literal)
		if _, err := regexp.Compile(p); err != nil {
			report(ast.PositionOf(pat[0]), "%s: invalid RE2 pattern %q: %v", c.Name, p, err)
		}
	case len(pat) == 1 && pat[0].Type == lexer.REGEX:
		if _, err := regexp.Compile(pat[0].Literal); err != nil {
			report(ast.PositionOf(pat[0]), "%s: invalid RE2 pattern /%s/: %v", c.Name, pat[0].Literal, err)
		}
	default:
		report(c.Pos, "%s: argument %d must be a string literal regex pattern", c.Name, idx+1)
	}
}
