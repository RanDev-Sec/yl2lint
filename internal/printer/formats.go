// Alternative output formats for large rule corpora, where the default
// per-file listing runs to hundreds of lines. Each writer takes an io.Writer
// so output can be captured in tests instead of the process's stdout.
package printer

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/fatih/color"

	"yl2lint/internal/linter"
	"yl2lint/internal/runner"
)

// PrintSummary aggregates findings by rule and by file instead of listing
// every violation: the right view when triaging a repo rather than fixing
// one file.
func PrintSummary(w io.Writer, results []runner.Result) {
	type agg struct {
		id, name string
		count    int
		sev      linter.Severity
		files    map[string]bool
	}
	byRule := map[string]*agg{}
	fileCounts := map[string]int{}
	fileErrs := map[string]int{}
	total, errs := 0, 0

	for _, res := range results {
		for _, v := range res.Violations {
			a := byRule[v.RuleID]
			if a == nil {
				a = &agg{id: v.RuleID, name: v.RuleName, sev: v.Severity, files: map[string]bool{}}
				byRule[v.RuleID] = a
			}
			a.count++
			a.files[res.Path] = true
			if v.Severity == linter.Error {
				a.sev = linter.Error
				errs++
				fileErrs[res.Path]++
			}
			fileCounts[res.Path]++
			total++
		}
	}

	if total == 0 {
		color.New(color.FgGreen).Fprintln(w, "✔ no problems found")
		return
	}

	bold := color.New(color.Bold)
	bold.Fprintln(w, "By rule")
	aggs := make([]*agg, 0, len(byRule))
	for _, a := range byRule {
		aggs = append(aggs, a)
	}
	sort.Slice(aggs, func(i, j int) bool {
		if aggs[i].count != aggs[j].count {
			return aggs[i].count > aggs[j].count
		}
		return aggs[i].id < aggs[j].id
	})
	for _, a := range aggs {
		fmt.Fprintf(w, "  %-6s %-22s %5d in %3d file(s)  [%s]\n",
			a.id, a.name, a.count, len(a.files), a.sev)
	}

	// Files with errors first, then by finding count.
	type fileAgg struct {
		path       string
		n, errored int
	}
	files := make([]fileAgg, 0, len(fileCounts))
	for p, n := range fileCounts {
		files = append(files, fileAgg{path: p, n: n, errored: fileErrs[p]})
	}
	sort.Slice(files, func(i, j int) bool {
		if (files[i].errored > 0) != (files[j].errored > 0) {
			return files[i].errored > 0
		}
		if files[i].n != files[j].n {
			return files[i].n > files[j].n
		}
		return files[i].path < files[j].path
	})

	limit := 15
	if len(files) < limit {
		limit = len(files)
	}
	bold.Fprintf(w, "\nFiles needing attention (top %d of %d)\n", limit, len(files))
	for _, f := range files[:limit] {
		marker := " "
		if f.errored > 0 {
			marker = "!"
		}
		fmt.Fprintf(w, "  %s %-58s %3d\n", marker, filepath.Base(f.path), f.n)
	}

	fmt.Fprintln(w)
	printTotals(w, total, errs)
}

// PrintCompact emits one grep-friendly line per finding:
// path:line:col  severity  RULE  message
func PrintCompact(w io.Writer, results []runner.Result) {
	total, errs := 0, 0
	for _, res := range results {
		if res.Err != nil {
			fmt.Fprintf(w, "%s  error  IO  %v\n", res.Path, res.Err)
			errs++
			continue
		}
		for _, v := range res.Violations {
			fmt.Fprintf(w, "%s:%d:%d  %s  %s  %s\n",
				res.Path, v.Pos.Line, v.Pos.Column, v.Severity, v.RuleID, v.Message)
			total++
			if v.Severity == linter.Error {
				errs++
			}
		}
	}
	printTotals(w, total, errs)
}

// PrintJSON writes machine-readable output for CI dashboards.
func PrintJSON(w io.Writer, results []runner.Result) error {
	type jsonViolation struct {
		Rule     string `json:"rule"`
		RuleName string `json:"rule_name"`
		Severity string `json:"severity"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
		Message  string `json:"message"`
	}
	type jsonFile struct {
		Path       string          `json:"path"`
		Error      string          `json:"error,omitempty"`
		Violations []jsonViolation `json:"violations"`
	}

	out := make([]jsonFile, 0, len(results))
	for _, res := range results {
		jf := jsonFile{Path: res.Path, Violations: []jsonViolation{}}
		if res.Err != nil {
			jf.Error = res.Err.Error()
		}
		for _, v := range res.Violations {
			jf.Violations = append(jf.Violations, jsonViolation{
				Rule: v.RuleID, RuleName: v.RuleName, Severity: v.Severity.String(),
				Line: v.Pos.Line, Column: v.Pos.Column, Message: v.Message,
			})
		}
		out = append(out, jf)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func printTotals(w io.Writer, total, errs int) {
	if total == 0 {
		color.New(color.FgGreen).Fprintln(w, "✔ no problems found")
		return
	}
	color.New(color.FgRed).Fprintf(w, "✖ %d problem(s), %d error(s)\n", total, errs)
}
