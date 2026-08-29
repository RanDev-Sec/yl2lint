// Fixture tests: one .yaral file per rule under testdata/rules, each written
// to trigger exactly one check. Lives in package runner_test (external test
// package) so it can import both runner and rules without an import cycle.
package runner_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"yl2lint/internal/config"
	"yl2lint/internal/linter"
	"yl2lint/internal/linter/rules"
	"yl2lint/internal/runner"
)

const fixtureDir = "../../testdata/rules"

func engine(t *testing.T) *linter.Engine {
	t.Helper()
	return linter.NewEngine(config.Default(), rules.All())
}

// lintFile returns the sorted, deduplicated set of rule IDs a fixture
// produces, plus the raw violations for line-level assertions.
func lintFile(t *testing.T, name string) ([]string, []linter.Violation) {
	t.Helper()
	path := filepath.Join(fixtureDir, name)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	vs := engine(t).LintSource(path, src)

	seen := map[string]bool{}
	var ids []string
	for _, v := range vs {
		if !seen[v.RuleID] {
			seen[v.RuleID] = true
			ids = append(ids, v.RuleID)
		}
	}
	sort.Strings(ids)
	return ids, vs
}

func has(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestFixtureTriggersItsRule asserts every fixture produces the check it was
// written for. It deliberately does not assert an exact set: a fixture may
// incidentally trip an info-level check, and pinning the full set would make
// every new rule break every fixture.
func TestFixtureTriggersItsRule(t *testing.T) {
	cases := []struct {
		file string
		want string
	}{
		{"yl000_directive.yaral", "YL000"},
		{"yl001_syntax.yaral", "YL001"},
		{"yl002_meta_keys.yaral", "YL002"},
		{"yl003_lifecycle.yaral", "YL003"},
		{"yl004_udm_schema.yaral", "YL004"},
		{"yl005_temporal.yaral", "YL005"},
		{"yl006_functions.yaral", "YL006"},
		{"yl007_performance.yaral", "YL007"},
		{"yl008_zero_value_join.yaral", "YL008"},
		{"yl009_match_necessity.yaral", "YL009"},
		{"yl010_repeated_fields.yaral", "YL010"},
		{"yl011_meta_values.yaral", "YL011"},
		{"yl012_type_check.yaral", "YL012"},
		{"yl013_reference_lists.yaral", "YL013"},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			ids, vs := lintFile(t, tc.file)
			if !has(ids, tc.want) {
				t.Fatalf("want %s, got %v\n%s", tc.want, ids, dump(vs))
			}
		})
	}
}

// TestCleanFixtureIsSilent is the false-positive guard. Every idiom in
// clean.yaral is valid YARA-L that appears in real corpora: positive
// equality on a repeated field, a leading-.* regex (full-string match
// semantics), a multi-line call, an anchored quantifier.
func TestCleanFixtureIsSilent(t *testing.T) {
	ids, vs := lintFile(t, "clean.yaral")
	if len(ids) != 0 {
		t.Fatalf("clean fixture produced findings %v — likely a false positive\n%s", ids, dump(vs))
	}
}

// TestSuppressionSilencesFindings checks that directives at line and trailing
// scope actually drop the violations they name.
func TestSuppressionSilencesFindings(t *testing.T) {
	ids, vs := lintFile(t, "suppressed.yaral")
	for _, unwanted := range []string{"YL004", "YL010"} {
		if has(ids, unwanted) {
			t.Errorf("%s should have been suppressed\n%s", unwanted, dump(vs))
		}
	}
	if has(ids, "YL000") {
		t.Errorf("directives in suppressed.yaral are well formed; YL000 should not fire\n%s", dump(vs))
	}
}

// TestSeverityTiers pins the blocking/non-blocking split. Errors fail a
// build; warnings and info do not. Moving a rule across this line is a
// deliberate act and should require editing this test.
func TestSeverityTiers(t *testing.T) {
	errorRules := map[string]string{
		"yl001_syntax.yaral":      "YL001",
		"yl002_meta_keys.yaral":   "YL002",
		"yl006_functions.yaral":   "YL006",
		"yl011_meta_values.yaral": "YL011",
	}
	for file, id := range errorRules {
		_, vs := lintFile(t, file)
		found := false
		for _, v := range vs {
			if v.RuleID == id && v.Severity == linter.Error {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: %s should report at error severity", file, id)
		}
	}

	nonBlocking := map[string]string{
		"yl004_udm_schema.yaral":      "YL004",
		"yl007_performance.yaral":     "YL007",
		"yl008_zero_value_join.yaral": "YL008",
		"yl009_match_necessity.yaral": "YL009",
		"yl010_repeated_fields.yaral": "YL010",
		"yl012_type_check.yaral":      "YL012",
		"yl013_reference_lists.yaral": "YL013",
	}
	for file, id := range nonBlocking {
		_, vs := lintFile(t, file)
		for _, v := range vs {
			if v.RuleID == id && v.Severity == linter.Error {
				t.Errorf("%s: %s is a judgment call and must not block builds", file, id)
			}
		}
	}
}

// TestYL003Tiers pins the three-tier placeholder logic: a real event variable
// that is never evaluated is an error, a placeholder that is assigned and
// never read is only a warning.
func TestYL003Tiers(t *testing.T) {
	_, vs := lintFile(t, "yl003_lifecycle.yaral")
	var sawErr, sawWarn bool
	for _, v := range vs {
		if v.RuleID != "YL003" {
			continue
		}
		switch {
		case strings.Contains(v.Message, "$unused") && v.Severity == linter.Error:
			sawErr = true
		case strings.Contains(v.Message, "$dead") && v.Severity == linter.Warning:
			sawWarn = true
		}
	}
	if !sawErr {
		t.Errorf("$unused should be an error (never evaluated event variable)\n%s", dump(vs))
	}
	if !sawWarn {
		t.Errorf("$dead should be a warning (assigned placeholder, legal in Chronicle)\n%s", dump(vs))
	}
}

// TestYL014DuplicateRuleNames needs the workspace pass, so it runs the whole
// runner over a directory rather than linting one file.
func TestYL014DuplicateRuleNames(t *testing.T) {
	results, err := runner.Run(filepath.Join(fixtureDir, "dup"), engine(t), 2)
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	for _, res := range results {
		for _, v := range res.Violations {
			if v.RuleID != "YL014" {
				continue
			}
			hits++
			if filepath.Base(res.Path) != "b.yaral" {
				t.Errorf("duplicate reported against %s; the first definition wins", res.Path)
			}
		}
	}
	if hits != 1 {
		t.Fatalf("want exactly one YL014 finding, got %d", hits)
	}
}

// TestPositionsArePlausible guards the position invariant: every finding must
// point somewhere inside the file it came from.
func TestPositionsArePlausible(t *testing.T) {
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaral" {
			continue
		}
		src, err := os.ReadFile(filepath.Join(fixtureDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Count(string(src), "\n") + 1
		_, vs := lintFile(t, e.Name())
		for _, v := range vs {
			if v.Pos.Line < 1 || v.Pos.Line > lines {
				t.Errorf("%s: %s reports line %d, file has %d lines",
					e.Name(), v.RuleID, v.Pos.Line, lines)
			}
			if v.Pos.Column < 1 {
				t.Errorf("%s: %s reports column %d", e.Name(), v.RuleID, v.Pos.Column)
			}
		}
	}
}

func dump(vs []linter.Violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString("    ")
		b.WriteString(v.RuleID)
		b.WriteString(" ")
		b.WriteString(v.Severity.String())
		b.WriteString(" ")
		b.WriteString(v.Message)
		b.WriteString("\n")
	}
	return b.String()
}
