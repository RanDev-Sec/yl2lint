// Command gen converts a CSV export of the UDM field list into the
// udm_fields.yaml consumed by the schema package. Offline by design: export
// the field list from Google's documentation, then run `go generate`.
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

type field struct {
	Path     string `yaml:"path"`
	Type     string `yaml:"type"`
	Repeated bool   `yaml:"repeated,omitempty"`
}

type out struct {
	Prefixes []string `yaml:"prefixes"`
	Fields   []field  `yaml:"fields"`
}

func main() {
	csvPath := flag.String("csv", "udm_fields.csv", "input CSV: path,type,repeated")
	outPath := flag.String("out", "udm_fields.yaml", "output YAML")
	flag.Parse()

	f, err := os.Open(*csvPath)
	if err != nil {
		fatal(err)
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		fatal(err)
	}

	doc := out{Prefixes: []string{"additional.fields", "about.labels", "metadata.tags"}}
	for i, row := range rows {
		if i == 0 && strings.EqualFold(row[0], "path") {
			continue // header row
		}
		if len(row) < 2 {
			fatal(fmt.Errorf("row %d: want at least path,type", i+1))
		}
		fld := field{Path: strings.TrimSpace(row[0]), Type: strings.TrimSpace(row[1])}
		if len(row) > 2 {
			fld.Repeated = strings.EqualFold(strings.TrimSpace(row[2]), "true")
		}
		doc.Fields = append(doc.Fields, fld)
	}

	data, err := yaml.Marshal(doc)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*outPath, data, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %d fields to %s\n", len(doc.Fields), *outPath)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen:", err)
	os.Exit(1)
}
