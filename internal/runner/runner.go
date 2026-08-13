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

	"yl2lint/internal/linter"
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

// Run lints every file under target using up to `workers` goroutines and
// returns per-file results sorted by path (concurrent completion order is
// nondeterministic; sorting keeps output stable).
func Run(target string, eng *linter.Engine, workers int) ([]Result, error) {
	paths, err := Collect(target)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no .yaral files found under %s", target)
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(paths) {
		workers = len(paths)
	}

	jobs := make(chan string)
	out := make(chan Result, len(paths))

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				src, readErr := os.ReadFile(path)
				if readErr != nil {
					out <- Result{Path: path, Err: readErr}
					continue
				}
				out <- Result{Path: path, Violations: eng.LintSource(path, src)}
			}
		}()
	}

	go func() {
		for _, p := range paths {
			jobs <- p
		}
		close(jobs)
		wg.Wait()
		close(out)
	}()

	results := make([]Result, 0, len(paths))
	for r := range out {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Path < results[j].Path })
	return results, nil
}
