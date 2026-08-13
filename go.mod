module yl2lint

go 1.26

require (
	github.com/fatih/color v1.19.0
	github.com/spf13/cobra v1.10.2
	go.yaml.in/yaml/v3 v3.0.5
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/sys v0.42.0 // indirect
)

// Workarounds for network-restricted build environments; both are inert and
// removable on a normal network (delete them and third_party/, then run
// `go mod tidy`).
//
// go.yaml.in/yaml/v3 is the officially maintained successor to the archived
// gopkg.in/yaml.v3, published by the YAML org. The local copy under
// third_party/yaml is the unmodified v3.0.5 release (tests and their
// test-only dependency stripped from its go.mod).
replace go.yaml.in/yaml/v3 => ./third_party/yaml

// Canonical GitHub mirror of the same module.
replace golang.org/x/sys => github.com/golang/sys v0.47.0
