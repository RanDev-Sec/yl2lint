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
	"re.regex":             {2, 2},
	"net.ip_in_range_cidr": {2, 2},
	"strings.coalesce":     {2, -1},
	"math.abs":             {1, 1},
}

// FunctionAndOperator (YL006) type-checks built-in YARA-L function calls:
// argument counts, literal argument types, RE2 validity of re.regex patterns
// (Go's regexp package is RE2, exactly like Chronicle), and CIDR validity.
type FunctionAndOperator struct{}

func (FunctionAndOperator) ID() string   { return "YL006" }
func (FunctionAndOperator) Name() string { return "function-signature" }
func (FunctionAndOperator) Description() string {
	return "built-in function calls must have valid argument counts/types; re.regex patterns must compile under RE2; CIDR literals must parse"
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
					report(c.Pos, "%s expects exactly %d argument(s), got %d", c.Name, sig.min, got)
					continue
				}

				switch c.Name {
				case "re.regex":
					pat := c.Args[1]
					switch {
					case len(pat) == 1 && pat[0].Type == lexer.STRING:
						p := unquotePattern(pat[0].Literal)
						if _, err := regexp.Compile(p); err != nil {
							report(ast.PositionOf(pat[0]), "re.regex: invalid RE2 pattern %q: %v", p, err)
						}
					case len(pat) == 1 && pat[0].Type == lexer.REGEX:
						if _, err := regexp.Compile(pat[0].Literal); err != nil {
							report(ast.PositionOf(pat[0]), "re.regex: invalid RE2 pattern /%s/: %v", pat[0].Literal, err)
						}
					default:
						report(c.Pos, "re.regex: second argument must be a string literal regex pattern")
					}

				case "net.ip_in_range_cidr":
					cidr := c.Args[1]
					if len(cidr) == 1 && cidr[0].Type == lexer.STRING {
						if _, _, err := net.ParseCIDR(cidr[0].Literal); err != nil {
							report(ast.PositionOf(cidr[0]), "net.ip_in_range_cidr: invalid CIDR %q: %v", cidr[0].Literal, err)
						}
					} else {
						report(c.Pos, "net.ip_in_range_cidr: second argument must be a string CIDR literal (e.g. \"10.0.0.0/8\")")
					}

				case "math.abs":
					arg := c.Args[0]
					if len(arg) == 1 && arg[0].Type == lexer.STRING {
						report(ast.PositionOf(arg[0]), "math.abs: argument must be numeric, got a string literal")
					}
				}
			}
		}
	}
	return vs
}