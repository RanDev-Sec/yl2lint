# yl2lint

A static-analysis linter for Google SecOps (Chronicle) **YARA-L 2.0** detection rules, written in Go. It parses rules into a real AST with a hand-written lexer and recursive-descent parser (no regex scraping) and runs pluggable lint rules over the tree. It can also fix files and scaffold new ones.

## Build

```bash
go build -o yl2lint ./cmd/yl2lint
```

Requires Go 1.26+ (current stable toolchain). All dependencies are pinned to their latest releases: cobra v1.10.2, fatih/color v1.19.0, and go.yaml.in/yaml/v3 v3.0.5, the officially maintained successor to the archived gopkg.in/yaml.v3 (see *Dependency notes* below).

## Usage

```bash
# Lint one file
./yl2lint lint detections/failed_logins.yaral

# Recursively lint every *.yaral file in a directory (concurrent)
./yl2lint lint detections/

# Auto-inject missing required meta keys with "TODO" placeholders
./yl2lint lint --fix detections/

# Same, but ask [Y/n] before adding each field
./yl2lint lint --interactive detections/foo.yaral

# Scaffold a new rule pre-populated with the required meta keys
./yl2lint create detections/suspicious_login.yaral

# Options
./yl2lint lint -c ci/.yl2lint.yaml --no-color -w 16 detections/

# List the checks active under the current config
./yl2lint rules
```

Exit codes: `0` clean (or warnings/info only), `1` at least one error-severity finding or unreadable file, `2` usage or I/O failure.

## Commands and flags

| Command | Purpose |
|---------|---------|
| `lint <file \| dir>` | Parse and lint. With `--fix` or `--interactive`, missing required meta keys are injected as `key = "TODO"` before linting. Rules without a `meta:` section get one created after the opening brace. Edits are line splices, so formatting and comments are preserved. |
| `create <file.yaral>` | Write a boilerplate rule (meta, events, condition) with the meta keys from `.yl2lint.yaml` pre-filled. The rule name is derived from the filename. `--force` overwrites an existing file. |
| `rules` | List the checks that would run under the current config. |

Global flags: `-c, --config <path>`, `--no-color`, `-w, --workers <n>`.

## Checks

| ID | Name | What it enforces |
|----|------|------------------|
| YL001 | `syntax` | Structural validity: balanced `{ }`, recognised section headers (with *"did you mean `condition:`?"* suggestions for typos within edit distance 2), `key = "value"` grammar in `meta:`, unterminated strings/regexes, duplicate sections, unclosed rules, and presence of the required `events:` and `condition:` sections. |
| YL002 | `meta-required-keys` | Every rule's `meta:` block contains all keys listed in the config (`author`, `description`, `severity` by default). |
| YL003 | `variable-lifecycle` | Every event variable declared in `events:` is evaluated in `match:`, `condition:`, or `outcome:`; every variable used in those sections was defined in `events:`. Outcome variables (`$risk_score = ...`) are recognised as definitions, and `#var` count references evaluate the same-named event variable. |
| YL004 | `udm-schema` | Every `$var.path.to.field` access exists in the embedded UDM field dictionary (`internal/schema`). Unknown fields get a *"did you mean?"* suggestion. Warning by default because the embedded dictionary is a partial mock; extend `internal/schema/udm.go` before raising it to error. |
| YL005 | `temporal-aggregation` | `match ... over <window>` durations above 14 days produce a warning (Chronicle throttles or rejects long windows). Aggregation calls (`count`, `array`, `array_distinct`, `sum`, `min`, `max`, `avg`, ...) in `outcome:` or `condition:` must only reference variables defined in `events:` or `match:` (error). |
| YL006 | `function-signature` | Argument counts and types for built-ins: `re.regex` (2 args; the pattern must be a string literal that compiles under Go's RE2, the same engine Chronicle uses), `net.ip_in_range_cidr` (2 args; valid CIDR literal), `strings.coalesce` (2 or more args), `math.abs` (exactly 1, non-string). |
| YL007 | `performance` | Warns on regexes that effectively start with `.*` or `.+` (after stripping `(?i)` flags and `^`), in `/.../ ` literals or `re.regex` string arguments, and on rules whose `events:` section never filters on `metadata.event_type`, which forces an unindexed scan of all log types. |

Syntax errors don't halt analysis: the parser recovers (a misspelled `conditon:` is corrected internally to `condition:`), so YL002-YL007 still run over whatever tree was salvaged.

## Inline suppressions

A directive comment silences specific rules for the node it precedes. Rules can be named by ID or name, case-insensitive, comma-separated. Omitting the list suppresses all rules for the target. Both `//` comments and `#` followed by a space work (`#name` with no space is still a count variable).

```
// yl2lint-disable: udm-schema        next line is a statement: that line only
$e.principal.user.useridd = "root"

# yl2lint-disable: YL005, performance next line is a section header: whole section
match:
  $u over 30d

// yl2lint-disable                    next line starts a rule: entire rule
rule legacy_noisy_rule { ... }

$e.custom.field = "x"  // yl2lint-disable: udm-schema   trailing: that line only
```

## Configuration - `.yl2lint.yaml`

Looked up in the working directory, or passed explicitly with `--config`. Absent file means built-in defaults.

```yaml
meta:
  required_keys:        # drives YL002, lint --fix/--interactive, and create
    - author
    - description
    - severity

disabled_rules: []      # by name or ID, case-insensitive: [udm-schema, YL007]

severities: {}          # per-rule override: {performance: info}
```

`meta.required_keys` is read by three things, so the policy stays in one place: YL002 enforces it, `--fix`/`--interactive` repair against it, and `create` scaffolds from it.

## Architecture

```
cmd/yl2lint            main() -> cli.Execute()
internal/cli           cobra commands (lint, rules, create) + flags + autofix pass
internal/config        .yl2lint.yaml loading, defaults, disable/severity lookups
internal/lexer         hand-written byte scanner -> positioned tokens + comments
internal/parser        recursive descent -> AST; error recovery + fuzzy headers
internal/ast           File -> YaraLRule -> sections; variable index; comments
internal/linter        Rule interface, Violation, Severity, Engine, suppressions
internal/linter/rules  concrete strategies (YL002-YL007) + All() registry
internal/schema        embedded mock UDM field dictionary for YL004
internal/format        position-driven source edits (meta key injection)
internal/runner        target collection + bounded worker-pool concurrency
internal/printer       colored, aligned terminal output + summary
```

Design points worth knowing before extending it:

- **Strategy pattern with external registration.** `linter.Rule` is the strategy interface; concrete rules live in `internal/linter/rules` and are wired into the engine by the CLI via `rules.All()`. This keeps `linter <- rules` a one-way dependency (no import cycle) and makes adding a rule a single new file plus one line in `All()`.
- **Shallow AST, flattened variable index.** Top-level structure (rule to sections) is rigid; below that, statements are kept as raw token lines and each section carries `Variables []VariableRef`. Lifecycle checks become set comparisons instead of tree walks. Raw tokens are preserved, which is what the YL004-YL007 field-path and call extraction is built on. One tradeoff: statements are grouped per source line, so a function call split across lines is not signature-checked by YL006.
- **Comments are a side channel.** The lexer collects comments instead of discarding them; the parser attaches them to the AST and the engine turns `yl2lint-disable` directives into suppressed line spans. `#` followed by whitespace is a comment; `#name` remains a count variable.
- **Fixes are line splices, not re-serialisation.** `internal/format` inserts lines at positions taken from the AST, so `--fix` never reformats anything it did not touch.
- **Regex literals are single tokens.** `/adm.n{2,4}/` is consumed whole by the lexer (contextually, after `=`, `!=`, `(`, `,`, or a keyword) so quantifier braces can't corrupt the parser's brace matching.
- **Section headers aren't keywords.** `events` is an ordinary identifier promoted to a header only when it starts a line and is followed by `:`, so UDM field paths can't collide with section names.
- **Concurrency at the file level.** `runner.Run` feeds a jobs channel into `min(workers, files)` goroutines; results are gathered and sorted by path so output is deterministic regardless of completion order. The `--fix`/`--interactive` pass runs sequentially before it so prompts never interleave.

## Language reference adherence

The lexer/parser and rules follow the Google SecOps YARA-L 2.0 documentation:

- Section set and semantics per the [language syntax reference](https://docs.cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax): `meta`, `events`, `match`, `outcome`, `condition`, `options`; `events:` and `condition:` are required and their absence is a YL001 error.
- `#var` in `condition` is the count-of-distinct-events reference for the same-named event variable, and outcome variables defined in `outcome:` may be referenced from `condition:` (both per the syntax reference; YL003 models this).
- All documented comparison forms lex correctly, per the [overview examples](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview): regex literals with `nocase` (`$host = /.*HoSt.*/ nocase`), backtick raw strings in `re.regex(...)`, and `in cidr` / `in regex` reference-list operators (`$e.principal.ip in cidr %internal_ranges`).
- `re.regex` patterns are compiled with Go's `regexp` package, which implements RE2, the same engine Chronicle uses, so YL006 validity results match production behaviour.
- Composite detection rules use the same structure and syntax as multi-event rules, so they lint with no special handling.

## Test fixtures

`testdata/` contains five rules exercising the original checks: `good.yaral` (clean), `bad_meta.yaral` (YL002), `bad_syntax.yaral` (YL001, including the `conditon:` typo and a missing `}`), `bad_structure.yaral` (YL001 missing required `condition:` section), and `bad_vars.yaral` (YL003 in both directions). Fixtures for YL004-YL007 and the suppression directives are a good next addition.