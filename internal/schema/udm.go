// Package schema holds the UDM field dictionary used by the udm-schema lint
// rule (and, later, type and repeated-field checks). The dictionary is data,
// not code: the embedded udm_fields.yaml ships a baseline, and users can
// extend or replace it via the `schema:` block in .yl2lint.yaml. Regenerate
// the embedded file from a CSV export of Google's UDM field list with:
//
//go:generate go run ./gen -csv udm_fields.csv -out udm_fields.yaml
package schema

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

//go:embed udm_fields.yaml
var embeddedFields []byte

// Field is one UDM field path with its metadata.
type Field struct {
	Path     string `yaml:"path"`
	Type     string `yaml:"type"`     // string, int, bool, timestamp, enum
	Repeated bool   `yaml:"repeated"` // repeated (array) field, or child of one
}

type fileFormat struct {
	Fields   []Field  `yaml:"fields"`
	Prefixes []string `yaml:"prefixes"` // path families with free-form suffixes
}

var (
	mu       sync.RWMutex
	fields   map[string]Field
	prefixes []string
)

func init() {
	if err := load(embeddedFields, true); err != nil {
		panic("schema: embedded udm_fields.yaml is invalid: " + err.Error())
	}
}

func load(data []byte, replace bool) error {
	var ff fileFormat
	if err := yaml.Unmarshal(data, &ff); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if replace || fields == nil {
		fields = make(map[string]Field, len(ff.Fields))
		prefixes = nil
	}
	for _, f := range ff.Fields {
		fields[f.Path] = f
	}
	prefixes = append(prefixes, ff.Prefixes...)
	return nil
}

// LoadExtra merges a user-supplied dictionary file into the embedded one, or
// substitutes it entirely when replace is true. Call once at startup, before
// concurrent linting begins.
func LoadExtra(path string, replace bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("loading schema %s: %w", path, err)
	}
	if err := load(data, replace); err != nil {
		return fmt.Errorf("parsing schema %s: %w", path, err)
	}
	return nil
}

// Valid reports whether path is a known UDM field path.
func Valid(path string) bool {
	mu.RLock()
	defer mu.RUnlock()
	if _, ok := fields[path]; ok {
		return true
	}

	// Timestamp fields expose .seconds and .nanos sub-fields
	// (metadata.event_timestamp.seconds is a valid access).
	for _, suf := range []string{".seconds", ".nanos"} {
		if parent, ok := strings.CutSuffix(path, suf); ok {
			if f, known := fields[parent]; known && f.Type == "timestamp" {
				return true
			}
		}
	}

	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+".") {
			return true
		}
	}
	return false
}

// Lookup returns the full field record for a path.
func Lookup(path string) (Field, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := fields[path]
	return f, ok
}

// TypeOf returns a field's declared type ("" when unknown).
func TypeOf(path string) (string, bool) {
	f, ok := Lookup(path)
	return f.Type, ok
}

// IsRepeated reports whether a known field is repeated.
func IsRepeated(path string) bool {
	f, ok := Lookup(path)
	return ok && f.Repeated
}

// Nearest returns the closest known field path (edit distance <= 3) as a
// "did you mean" suggestion, or "" when nothing is close. Ties break
// lexicographically so output is deterministic.
func Nearest(path string) string {
	mu.RLock()
	defer mu.RUnlock()
	best, bestDist := "", 4
	for p := range fields {
		d := levenshtein(path, p)
		if d < bestDist || (d == bestDist && best != "" && p < best) {
			best, bestDist = p, d
		}
	}
	return best
}

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = minInt(minInt(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
