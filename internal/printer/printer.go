// Package printer renders lint results with colored, aligned terminal output.
package printer

import (
	"fmt"
	"io"

	"github.com/fatih/color"

	"yl2lint/internal/linter"
	"yl2lint/internal/runner"
)

var (
	pathStyle = color.New(color.Bold, color.Underline)
	posStyle  = color.New(color.Faint)
	idStyle   = color.New(color.Faint)
	errStyle  = color.New(color.FgRed, color.Bold)
	warnStyle = color.New(color.FgYellow, color.Bold)
	infoStyle = color.New(color.FgCyan, color.Bold)
	okStyle   = color.New(color.FgGreen, color.Bold)
)

// Summary aggregates counts across all linted files.
type Summary struct {
	Files        int
	Errors       int
	Warnings     int
	Infos        int
	ReadFailures int
}

// Total returns the number of violations across all severities.
func (s Summary) Total() int { return s.Errors + s.Warnings + s.Infos }

// Print writes all results to w and returns the summary.
func Print(w io.Writer, results []runner.Result) Summary {
	sum := Summary{Files: len(results)}

	for _, res := range results {
		if res.Err != nil {
			sum.ReadFailures++
			fmt.Fprintf(w, "%s\n  %s  %v\n\n",
				pathStyle.Sprint(res.Path), errStyle.Sprint("error"), res.Err)
			continue
		}
		if len(res.Violations) == 0 {
			continue
		}

		fmt.Fprintln(w, pathStyle.Sprint(res.Path))

		posWidth := 0
		for _, v := range res.Violations {
			if l := len(posString(v)); l > posWidth {
				posWidth = l
			}
		}
		for _, v := range res.Violations {
			switch v.Severity {
			case linter.Error:
				sum.Errors++
			case linter.Warning:
				sum.Warnings++
			default:
				sum.Infos++
			}
			// Pad BEFORE colouring: ANSI escape bytes would break %-Ns widths.
			fmt.Fprintf(w, "  %s  %s  %s  %s\n",
				posStyle.Sprint(pad(posString(v), posWidth)),
				severityStyle(v.Severity).Sprint(pad(v.Severity.String(), 7)),
				idStyle.Sprint(v.RuleID),
				v.Message)
		}
		fmt.Fprintln(w)
	}

	printSummaryLine(w, sum)
	return sum
}

func printSummaryLine(w io.Writer, s Summary) {
	if s.Total() == 0 && s.ReadFailures == 0 {
		fmt.Fprintf(w, "%s no problems found (%d %s linted)\n",
			okStyle.Sprint("✔"), s.Files, plural(s.Files, "file", "files"))
		return
	}
	fmt.Fprintf(w, "%s %d %s (%d %s, %d %s, %d info) in %d %s\n",
		errStyle.Sprint("✖"),
		s.Total(), plural(s.Total(), "problem", "problems"),
		s.Errors, plural(s.Errors, "error", "errors"),
		s.Warnings, plural(s.Warnings, "warning", "warnings"),
		s.Infos,
		s.Files, plural(s.Files, "file", "files"))
	if s.ReadFailures > 0 {
		fmt.Fprintf(w, "%s %d %s could not be read\n",
			errStyle.Sprint("✖"), s.ReadFailures, plural(s.ReadFailures, "file", "files"))
	}
}

func severityStyle(s linter.Severity) *color.Color {
	switch s {
	case linter.Error:
		return errStyle
	case linter.Warning:
		return warnStyle
	default:
		return infoStyle
	}
}

func posString(v linter.Violation) string {
	return fmt.Sprintf("%d:%d", v.Pos.Line, v.Pos.Column)
}

func pad(s string, width int) string {
	for len(s) < width {
		s += " "
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
