# yl2lint

A static-analysis linter for Google SecOps (Chronicle) **YARA-L 2.0** detection rules, written in Go. It parses rules into a real AST with a hand-written lexer and recursive-descent parser — no regex scraping — and runs pluggable lint rules over the tree.

## Build

```bash
go build -o yl2lint ./cmd/yl2lint
```

Requires Go 1.26+ (current stable toolchain). All dependencies are pinned to their latest releases: cobra v1.10.2, fatih/color v1.19.0, and go.yaml.in/yaml/v3 v3.0.5 — the officially maintained successor to the archived gopkg.in/yaml.v3 (see *Dependency notes* below).

## Usage

```bash
# Lint one file
./yl2lint lint detections/failed_logins.yaral

# Recursively lint every *.yaral file in a directory (concurrent)
./yl2lint lint detections/

# Options
./yl2lint lint -c ci/.yl2lint.yaml --no-color -w 16 detections/

# List the checks active under the current config
./yl2lint rules
```

Exit codes: `0` clean (or warnings/info only), `1` at least one error-severity finding or unreadable file, `2` usage or I/O failure.

## Checks

| ID | Name | What it enforces |
|----|------|------------------|
| YL001 | `syntax` | Structural validity: balanced `{ }`, recognised section headers (with *"did you mean `condition:`?"* suggestions for typos within edit distance 2), `key = "value"` grammar in `meta:`, unterminated strings/regexes, duplicate sections, unclosed rules, and presence of the `events:` and `condition:` sections that the YARA-L 2.0 language reference lists as required. |
| YL002 | `meta-required-keys` | Every rule's `meta:` block contains all keys listed in the config (`author`, `description`, `severity` by default). |
| YL003 | `variable-lifecycle` | Every event variable declared in `events:` is evaluated in `match:`, `condition:`, or `outcome:`; every variable used in those sections was defined in `events:`. Outcome variables (`$risk_score = ...`) are recognised as definitions, and `#var` count references evaluate the same-named event variable. |

Syntax errors don't halt analysis: the parser recovers (a misspelled `conditon:` is corrected internally to `condition:`), so YL002/YL003 still run over whatever tree was salvaged.

## Configuration — `.yl2lint.yaml`

Looked up in the working directory, or passed explicitly with `--config`. Absent file → built-in defaults.

```yaml
meta:
  required_keys:        # YL002 policy
    - author
    - description
    - severity

disabled_rules: []      # by name or ID, case-insensitive: [variable-lifecycle, YL002]

severities: {}          # per-rule override: {meta-required-keys: warning}
```

## Architecture

```
cmd/yl2lint            main() → cli.Execute()
internal/cli           cobra commands (lint, rules) + flags
internal/config        .yl2lint.yaml loading, defaults, disable/severity lookups
internal/lexer         hand-written byte scanner → positioned tokens
internal/parser        recursive descent → AST; error recovery + fuzzy headers
internal/ast           File → YaraLRule → sections; per-section variable index
internal/linter        Rule interface, Violation, Severity, Engine
internal/linter/rules  concrete strategies (YL002, YL003) + All() registry
internal/runner        target collection + bounded worker-pool concurrency
internal/printer       colored, aligned terminal output + summary
```

Design points worth knowing before extending it:

- **Strategy pattern with external registration.** `linter.Rule` is the strategy interface; concrete rules live in `internal/linter/rules` and are wired into the engine by the CLI via `rules.All()`. This keeps `linter ← rules` a one-way dependency (no import cycle) and makes adding a Day 2 rule a single new file plus one line in `All()`.
- **Shallow AST, flattened variable index.** Top-level structure (rule → sections) is rigid; below that, statements are kept as raw token lines and each section carries `Variables []VariableRef`. Lifecycle checks become set comparisons instead of tree walks. Raw tokens are preserved so future expression-level rules need no reparse.
- **Regex literals are single tokens.** `/adm.n{2,4}/` is consumed whole by the lexer (contextually, after `=`, `!=`, `(`, `,`, or a keyword) so quantifier braces can't corrupt the parser's brace matching.
- **Section headers aren't keywords.** `events` is an ordinary identifier promoted to a header only when it starts a line and is followed by `:`, so UDM field paths can't collide with section names.
- **Concurrency at the file level.** `runner.Run` feeds a jobs channel into `min(workers, files)` goroutines; results are gathered and sorted by path so output is deterministic regardless of completion order.

## Language reference adherence

The lexer/parser and rules follow the Google SecOps YARA-L 2.0 documentation:

- Section set and semantics per the [language syntax reference](https://docs.cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax): `meta`, `events`, `match`, `outcome`, `condition`, `options`; `events:` and `condition:` are required and their absence is a YL001 error.
- `#var` in `condition` is the count-of-distinct-events reference for the same-named event variable, and outcome variables defined in `outcome:` may be referenced from `condition:` (both per the syntax reference; YL003 models this).
- All documented comparison forms lex correctly, per the [overview examples](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview): regex literals with `nocase` (`$host = /.*HoSt.*/ nocase`), backtick raw strings in `re.regex(...)`, and `in cidr` / `in regex` reference-list operators (`$e.principal.ip in cidr %internal_ranges`).
- Composite detection rules use the same structure and syntax as multi-event rules, so they lint with no special handling.

## Test fixtures

`testdata/` contains five rules exercising each check: `good.yaral` (clean), `bad_meta.yaral` (YL002), `bad_syntax.yaral` (YL001, including the `conditon:` typo and a missing `}`), `bad_structure.yaral` (YL001 missing required `condition:` section), and `bad_vars.yaral` (YL003 in both directions).
