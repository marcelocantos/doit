package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/rules"
)

// Config holds the global doit configuration.
type Config struct {
	Tiers  TierConfig                     `yaml:"tiers"`
	Audit  AuditConfig                    `yaml:"audit"`
	Rules  map[string]rules.CapRuleConfig `yaml:"rules"`
	Daemon DaemonConfig                   `yaml:"daemon"`
	Policy PolicyConfig                   `yaml:"policy"`
}

// PolicyConfig controls the policy engine.
type PolicyConfig struct {
	Level1Enabled bool   `yaml:"level1_enabled"`
	Level2Enabled bool   `yaml:"level2_enabled"`
	Level2Path    string `yaml:"level2_path,omitempty"`
	Level3Enabled bool   `yaml:"level3_enabled"`
	Level3Model   string `yaml:"level3_model,omitempty"`
	Level3Timeout string `yaml:"level3_timeout,omitempty"`
}

// DefaultLevel3Timeout is used when no level3_timeout is configured.
const DefaultLevel3Timeout = 60 * time.Second

// Level3TimeoutDuration parses the configured Level 3 timeout or returns the default.
func (p *PolicyConfig) Level3TimeoutDuration() time.Duration {
	if p.Level3Timeout != "" {
		dur, err := time.ParseDuration(p.Level3Timeout)
		if err == nil {
			return dur
		}
	}
	return DefaultLevel3Timeout
}

// DaemonConfig controls daemon behavior.
type DaemonConfig struct {
	// Enabled: nil = auto (try daemon, fall back to in-process),
	// true = require daemon, false = always in-process.
	Enabled     *bool  `yaml:"enabled"`
	IdleTimeout string `yaml:"idle_timeout"`
}

// DefaultIdleTimeout is used when no idle_timeout is configured.
const DefaultIdleTimeout = 5 * time.Minute

// IdleTimeoutDuration parses the configured idle timeout or returns the default.
func (d *DaemonConfig) IdleTimeoutDuration() time.Duration {
	if d.IdleTimeout != "" {
		dur, err := time.ParseDuration(d.IdleTimeout)
		if err == nil {
			return dur
		}
	}
	return DefaultIdleTimeout
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
		Policy: PolicyConfig{
			Level1Enabled: true,
			Level2Enabled: true,
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

// ProjectConfigPath returns the config file path for a project root.
func ProjectConfigPath(projectRoot string) string {
	return filepath.Join(projectRoot, ".doit", "config.yaml")
}

// LoadProject loads a project-level config from the given project root.
// Returns nil (not an error) if no .doit/config.yaml exists.
func LoadProject(projectRoot string) (*Config, error) {
	path := ProjectConfigPath(projectRoot)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read project config: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse project config %s: %w", path, err)
	}
	return cfg, nil
}

// MergeProject overlays project config onto the global config using
// tighten-only semantics: the project can add rules and disable tiers
// but cannot remove global rules or enable globally-disabled tiers.
func (c *Config) MergeProject(proj *Config) {
	if proj == nil {
		return
	}

	// Tiers: project can only disable (tighten), never enable.
	if c.Tiers.Read && !proj.Tiers.Read {
		c.Tiers.Read = false
	}
	if c.Tiers.Build && !proj.Tiers.Build {
		c.Tiers.Build = false
	}
	if c.Tiers.Write && !proj.Tiers.Write {
		c.Tiers.Write = false
	}
	if c.Tiers.Dangerous && !proj.Tiers.Dangerous {
		c.Tiers.Dangerous = false
	}

	// Rules: merge project rules into global. Project rules add to
	// (never replace) global rules.
	if len(proj.Rules) > 0 {
		if c.Rules == nil {
			c.Rules = DefaultRules()
		}
		for name, projRule := range proj.Rules {
			existing, ok := c.Rules[name]
			if !ok {
				c.Rules[name] = projRule
				continue
			}
			// Merge reject flags (deduplicated).
			existing.RejectFlags = mergeFlags(existing.RejectFlags, projRule.RejectFlags)
			// Merge subcommand rules.
			if len(projRule.Subcommands) > 0 {
				if existing.Subcommands == nil {
					existing.Subcommands = make(map[string]rules.SubRuleConfig)
				}
				for sub, subRule := range projRule.Subcommands {
					if es, ok := existing.Subcommands[sub]; ok {
						es.RejectFlags = mergeFlags(es.RejectFlags, subRule.RejectFlags)
						existing.Subcommands[sub] = es
					} else {
						existing.Subcommands[sub] = subRule
					}
				}
			}
			c.Rules[name] = existing
		}
	}
}

// mergeFlags appends new flags to existing, skipping duplicates.
func mergeFlags(existing, new []string) []string {
	seen := make(map[string]bool, len(existing))
	for _, f := range existing {
		seen[f] = true
	}
	for _, f := range new {
		if !seen[f] {
			existing = append(existing, f)
			seen[f] = true
		}
	}
	return existing
}
