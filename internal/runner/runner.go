// Package runner discovers .yaral targets and lints them concurrently with a
// bounded worker pool.
package runner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"yl2lint/internal/ast"
	"yl2lint/internal/linter"
	"yl2lint/internal/parser"
	"yl2lint/internal/workspace"
)

// Result is the outcome of linting one file.
type Result struct {
	Path       string
	Violations []linter.Violation
	Err        error // read failure; Violations is empty when set
}

// Collect resolves a CLI target into the list of files to lint. A file path
// is linted as-is; a directory is walked recursively for *.yaral files.
func Collect(target string) ([]string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{target}, nil
	}

	var paths []string
	err = filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".yaral") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}

// parsedFile is the pass-1 output for one target file.
type parsedFile struct {
	path    string
	file    *ast.File
	errs    []parser.ParseError
	readErr error
}

// Run lints every file under target in two passes. Pass 1 reads and parses
// all files concurrently. Between the passes, workspace checks run over the
// complete set of ASTs (they need the global view). Pass 2 runs the per-file
// rules concurrently and merges in the workspace findings, filtered through
// each file's inline suppressions. Results come back sorted by path.
func Run(target string, eng *linter.Engine, workers int) ([]Result, error) {
	paths, err := Collect(target)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no .yaral files found under %s", target)
	}
	sort.Strings(paths) // deterministic "first definition" for workspace checks
	if workers < 1 {
		workers = 1
	}
	if workers > len(paths) {
		workers = len(paths)
	}

	// Pass 1: read + parse. Index-addressed slices need no result channel.
	parsedFiles := make([]parsedFile, len(paths))
	runIndexed(len(paths), workers, func(i int) {
		path := paths[i]
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			parsedFiles[i] = parsedFile{path: path, readErr: readErr}
			return
		}
		file, errs := parser.Parse(src)
		file.Path = path
		parsedFiles[i] = parsedFile{path: path, file: file, errs: errs}
	})

	// Workspace checks over every successfully parsed file.
	var files []*ast.File
	for _, pf := range parsedFiles {
		if pf.readErr == nil {
			files = append(files, pf.file)
		}
	}
	wsViolations := workspace.Check(files, eng.Config())

	// Pass 2: per-file rules + merge.
	results := make([]Result, len(paths))
	runIndexed(len(paths), workers, func(i int) {
		pf := parsedFiles[i]
		if pf.readErr != nil {
			results[i] = Result{Path: pf.path, Err: pf.readErr}
			return
		}
		vs := eng.LintParsed(pf.path, pf.file, pf.errs)
		if extra := wsViolations[pf.path]; len(extra) > 0 {
			extra = linter.ApplySuppressions(pf.file, extra)
			vs = append(vs, extra...)
			linter.SortViolations(vs)
		}
		results[i] = Result{Path: pf.path, Violations: vs}
	})

	return results, nil
}

// runIndexed executes fn(i) for i in [0, n) across up to `workers`
// goroutines. Each index is owned by exactly one goroutine, so writes to
// index-addressed slices need no further synchronisation.
func runIndexed(n, workers int, fn func(i int)) {
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}
