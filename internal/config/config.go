package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/rules"
)

// Config holds the global doit configuration.
type Config struct {
	Tiers TierConfig                     `yaml:"tiers"`
	Audit AuditConfig                    `yaml:"audit"`
	Rules map[string]rules.CapRuleConfig `yaml:"rules"`
}

// TierConfig controls which safety tiers are enabled.
type TierConfig struct {
	Read      bool `yaml:"read"`
	Build     bool `yaml:"build"`
	Write     bool `yaml:"write"`
	Dangerous bool `yaml:"dangerous"`
}

// AuditConfig controls audit log settings.
type AuditConfig struct {
	Path      string `yaml:"path"`
	MaxSizeMB int    `yaml:"max_size_mb"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		Tiers: TierConfig{
			Read:      true,
			Build:     true,
			Write:     true,
			Dangerous: false,
		},
		Audit: AuditConfig{
			Path:      filepath.Join(home, ".local", "share", "doit", "audit.jsonl"),
			MaxSizeMB: 100,
		},
	}
}

// Load reads the config from the standard location (~/.config/doit/config.yaml).
// If the file doesn't exist, returns the default config.
func Load() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return DefaultConfig(), nil
	}

	path := filepath.Join(home, ".config", "doit", "config.yaml")
	return LoadFrom(path)
}

// LoadFrom reads the config from the given path.
func LoadFrom(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Expand ~ in audit path.
	if cfg.Audit.Path != "" && cfg.Audit.Path[0] == '~' {
		home, _ := os.UserHomeDir()
		cfg.Audit.Path = filepath.Join(home, cfg.Audit.Path[1:])
	}

	return cfg, nil
}

// DefaultRules returns the default argument-level rules.
func DefaultRules() map[string]rules.CapRuleConfig {
	return map[string]rules.CapRuleConfig{
		"make": {
			RejectFlags: []string{"-j"},
		},
		"git": {
			Subcommands: map[string]rules.SubRuleConfig{
				"push":  {RejectFlags: []string{"--force", "-f", "--force-with-lease"}},
				"reset": {RejectFlags: []string{"--hard"}},
			},
		},
	}
}

// ApplyRules creates a RuleSet from the config and sets it on the registry.
// Hardcoded safety rules are always included. Programmatic default rules
// (like git checkout .) are added as config rules so they can be bypassed
// with --retry.
func (c *Config) ApplyRules(reg *cap.Registry) {
	rs := rules.NewRuleSet(rules.Hardcoded()...)
	cfgRules := c.Rules
	if cfgRules == nil {
		cfgRules = DefaultRules()
	}
	for name, capRule := range cfgRules {
		for _, fn := range rules.CompileCapRule(name, capRule) {
			rs.AddConfig(fn)
		}
	}
	// Programmatic default rules that can't be expressed in YAML config.
	rs.AddConfig(rules.CheckGitCheckoutAll)
	reg.SetRules(rs)
}

// ApplyTiers sets the registry tier permissions from the config.
func (c *Config) ApplyTiers(reg *cap.Registry) {
	reg.SetTier(cap.TierRead, c.Tiers.Read)
	reg.SetTier(cap.TierBuild, c.Tiers.Build)
	reg.SetTier(cap.TierWrite, c.Tiers.Write)
	reg.SetTier(cap.TierDangerous, c.Tiers.Dangerous)
}

// ConfigPath returns the standard config file path.
func ConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "doit", "config.yaml")
}
