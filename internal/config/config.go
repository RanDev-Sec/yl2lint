// Package config loads the .yl2lint.yaml policy file that customises linting
// behaviour (required meta keys, disabled rules, severity overrides).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DefaultFileName is the config file looked up in the working directory when
// no explicit --config path is supplied.
const DefaultFileName = ".yl2lint.yaml"

// Config is the root of the .yl2lint.yaml document.
type Config struct {
	// Meta configures the meta-required-keys (YL002) policy.
	Meta MetaConfig `yaml:"meta"`

	// DisabledRules lists rule names or IDs to skip entirely,
	// e.g. ["variable-lifecycle"] or ["YL003"]. Case-insensitive.
	DisabledRules []string `yaml:"disabled_rules"`

	// Severities overrides the default severity per rule name or ID,
	// e.g. {meta-required-keys: warning}. Valid values: info, warning, error.
	Severities map[string]string `yaml:"severities"`
}

// MetaConfig holds the policy for a rule's meta section.
type MetaConfig struct {
	// RequiredKeys must all be present in every rule's meta block.
	RequiredKeys []string `yaml:"required_keys"`
}

// Default returns the configuration used when no .yl2lint.yaml exists.
func Default() *Config {
	return &Config{
		Meta: MetaConfig{
			RequiredKeys: []string{"author", "description", "severity"},
		},
	}
}

// Load reads the configuration.
//
//   - If explicitPath is non-empty, that file must exist and parse.
//   - Otherwise DefaultFileName is looked up in the working directory; if it
//     does not exist, Default() is returned silently.
//
// The second return value is the path of the file actually loaded ("" when
// defaults were used).
func Load(explicitPath string) (*Config, string, error) {
	path := explicitPath
	if path == "" {
		path = DefaultFileName
		if _, err := os.Stat(path); err != nil {
			return Default(), "", nil // no config file: defaults, not an error
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("reading config %s: %w", path, err)
	}

	// Decode on top of the defaults so an absent key keeps its default value,
	// while an explicitly empty key (e.g. `required_keys: []`) overrides it.
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // typos in the config file should fail loudly
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Default(), path, nil // empty file
		}
		return nil, "", fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, path, nil
}

// IsDisabled reports whether a rule (matched by name or ID, case-insensitively)
// has been switched off in the config.
func (c *Config) IsDisabled(id, name string) bool {
	for _, d := range c.DisabledRules {
		if strings.EqualFold(d, id) || strings.EqualFold(d, name) {
			return true
		}
	}
	return false
}

// SeverityOverride returns the configured severity string for a rule, if any.
func (c *Config) SeverityOverride(id, name string) (string, bool) {
	for key, val := range c.Severities {
		if strings.EqualFold(key, id) || strings.EqualFold(key, name) {
			return val, true
		}
	}
	return "", false
}
