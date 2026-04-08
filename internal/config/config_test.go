// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/rules"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Tiers: read, build, write enabled; dangerous disabled.
	if !cfg.Tiers.Read {
		t.Error("expected Tiers.Read to be true")
	}
	if !cfg.Tiers.Build {
		t.Error("expected Tiers.Build to be true")
	}
	if !cfg.Tiers.Write {
		t.Error("expected Tiers.Write to be true")
	}
	if cfg.Tiers.Dangerous {
		t.Error("expected Tiers.Dangerous to be false")
	}

	// Audit defaults.
	home, _ := os.UserHomeDir()
	wantPath := filepath.Join(home, ".local", "share", "doit", "audit.jsonl")
	if cfg.Audit.Path != wantPath {
		t.Errorf("Audit.Path = %q, want %q", cfg.Audit.Path, wantPath)
	}
	if cfg.Audit.MaxSizeMB != 100 {
		t.Errorf("Audit.MaxSizeMB = %d, want 100", cfg.Audit.MaxSizeMB)
	}

	// Policy defaults.
	if !cfg.Policy.Level1Enabled {
		t.Error("expected Policy.Level1Enabled to be true")
	}
	if !cfg.Policy.Level2Enabled {
		t.Error("expected Policy.Level2Enabled to be true")
	}
	if cfg.Policy.Level3Enabled {
		t.Error("expected Policy.Level3Enabled to be false")
	}

	// Rules should be nil (defaults applied at ApplyRules time).
	if cfg.Rules != nil {
		t.Errorf("expected Rules to be nil, got %v", cfg.Rules)
	}
}

func TestLoadFromMissingFile(t *testing.T) {
	cfg, err := LoadFrom("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("LoadFrom missing file: unexpected error: %v", err)
	}

	// Should return default config.
	def := DefaultConfig()
	if cfg.Tiers != def.Tiers {
		t.Errorf("Tiers = %+v, want %+v", cfg.Tiers, def.Tiers)
	}
	if cfg.Audit != def.Audit {
		t.Errorf("Audit = %+v, want %+v", cfg.Audit, def.Audit)
	}
}

func TestLoadFromValidYAML(t *testing.T) {
	content := `
tiers:
  read: true
  build: false
  write: true
  dangerous: true
audit:
  path: /tmp/test-audit.jsonl
  max_size_mb: 50
policy:
  level3_enabled: true
  level3_model: gpt-4
  level3_timeout: 30s
`
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cfg, err := LoadFrom(f.Name())
	if err != nil {
		t.Fatalf("LoadFrom valid YAML: %v", err)
	}

	if cfg.Tiers.Build {
		t.Error("expected Tiers.Build to be false")
	}
	if !cfg.Tiers.Dangerous {
		t.Error("expected Tiers.Dangerous to be true")
	}
	if cfg.Audit.Path != "/tmp/test-audit.jsonl" {
		t.Errorf("Audit.Path = %q, want /tmp/test-audit.jsonl", cfg.Audit.Path)
	}
	if cfg.Audit.MaxSizeMB != 50 {
		t.Errorf("Audit.MaxSizeMB = %d, want 50", cfg.Audit.MaxSizeMB)
	}
	if !cfg.Policy.Level3Enabled {
		t.Error("expected Policy.Level3Enabled to be true")
	}
	if cfg.Policy.Level3Model != "gpt-4" {
		t.Errorf("Policy.Level3Model = %q, want gpt-4", cfg.Policy.Level3Model)
	}
}

func TestLoadFromInvalidYAML(t *testing.T) {
	content := `tiers: [[[invalid yaml`
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = LoadFrom(f.Name())
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadFromTildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	content := `
audit:
  path: ~/logs/audit.jsonl
`
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cfg, err := LoadFrom(f.Name())
	if err != nil {
		t.Fatalf("LoadFrom tilde config: %v", err)
	}

	want := filepath.Join(home, "logs/audit.jsonl")
	if cfg.Audit.Path != want {
		t.Errorf("Audit.Path = %q, want %q", cfg.Audit.Path, want)
	}
}

func TestLoadFromPartialConfig(t *testing.T) {
	content := `
tiers:
  dangerous: true
`
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cfg, err := LoadFrom(f.Name())
	if err != nil {
		t.Fatalf("LoadFrom partial config: %v", err)
	}

	// Dangerous should be overridden.
	if !cfg.Tiers.Dangerous {
		t.Error("expected Tiers.Dangerous to be true")
	}

	// Other tier defaults should be preserved (YAML unmarshals into
	// the DefaultConfig struct, but YAML zero-values for bools are
	// false, so unset fields become false, not the default true).
	// This is the actual behavior: YAML sets the whole Tiers struct.

	// Audit defaults should be preserved since not specified.
	def := DefaultConfig()
	if cfg.Audit != def.Audit {
		t.Errorf("Audit = %+v, want default %+v", cfg.Audit, def.Audit)
	}
	if cfg.Policy.Level1Enabled != def.Policy.Level1Enabled {
		t.Errorf("Policy.Level1Enabled = %v, want %v", cfg.Policy.Level1Enabled, def.Policy.Level1Enabled)
	}
}

func TestLevel3TimeoutDuration(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
		want    time.Duration
	}{
		{"valid duration", "30s", 30 * time.Second},
		{"valid minutes", "2m", 2 * time.Minute},
		{"invalid string", "not-a-duration", DefaultLevel3Timeout},
		{"empty string", "", DefaultLevel3Timeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PolicyConfig{Level3Timeout: tt.timeout}
			got := p.Level3TimeoutDuration()
			if got != tt.want {
				t.Errorf("Level3TimeoutDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultRules(t *testing.T) {
	r := DefaultRules()

	// Check make rules.
	makeRule, ok := r["make"]
	if !ok {
		t.Fatal("expected 'make' rule in DefaultRules")
	}
	found := false
	for _, f := range makeRule.RejectFlags {
		if f == "-j" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected make rule to reject -j flag")
	}

	// Check git rules.
	gitRule, ok := r["git"]
	if !ok {
		t.Fatal("expected 'git' rule in DefaultRules")
	}
	pushRule, ok := gitRule.Subcommands["push"]
	if !ok {
		t.Fatal("expected 'push' subcommand rule for git")
	}
	hasForce := false
	for _, f := range pushRule.RejectFlags {
		if f == "--force" {
			hasForce = true
			break
		}
	}
	if !hasForce {
		t.Error("expected git push rule to reject --force")
	}

	resetRule, ok := gitRule.Subcommands["reset"]
	if !ok {
		t.Fatal("expected 'reset' subcommand rule for git")
	}
	hasHard := false
	for _, f := range resetRule.RejectFlags {
		if f == "--hard" {
			hasHard = true
			break
		}
	}
	if !hasHard {
		t.Error("expected git reset rule to reject --hard")
	}
}

func TestApplyTiers(t *testing.T) {
	tests := []struct {
		name   string
		tiers  TierConfig
		checks map[cap.Tier]bool
	}{
		{
			name:  "all enabled",
			tiers: TierConfig{Read: true, Build: true, Write: true, Dangerous: true},
			checks: map[cap.Tier]bool{
				cap.TierRead:      true,
				cap.TierBuild:     true,
				cap.TierWrite:     true,
				cap.TierDangerous: true,
			},
		},
		{
			name:  "dangerous disabled",
			tiers: TierConfig{Read: true, Build: true, Write: true, Dangerous: false},
			checks: map[cap.Tier]bool{
				cap.TierRead:      true,
				cap.TierBuild:     true,
				cap.TierWrite:     true,
				cap.TierDangerous: false,
			},
		},
		{
			name:  "all disabled",
			tiers: TierConfig{},
			checks: map[cap.Tier]bool{
				cap.TierRead:      false,
				cap.TierBuild:     false,
				cap.TierWrite:     false,
				cap.TierDangerous: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := cap.NewRegistry()
			cfg := &Config{Tiers: tt.tiers}
			cfg.ApplyTiers(reg)

			for tier, wantEnabled := range tt.checks {
				err := reg.CheckTier(tier)
				if wantEnabled && err != nil {
					t.Errorf("tier %v: expected enabled, got error: %v", tier, err)
				}
				if !wantEnabled && err == nil {
					t.Errorf("tier %v: expected disabled, got nil error", tier)
				}
			}
		})
	}
}

func TestApplyRules(t *testing.T) {
	t.Run("default rules block make -j", func(t *testing.T) {
		reg := cap.NewRegistry()
		cfg := DefaultConfig()
		cfg.ApplyRules(reg)

		err := reg.CheckRules("make", []string{"-j4"}, false)
		if err == nil {
			t.Error("expected make -j4 to be blocked by default rules")
		}
	})

	t.Run("default rules block git push --force", func(t *testing.T) {
		reg := cap.NewRegistry()
		cfg := DefaultConfig()
		cfg.ApplyRules(reg)

		err := reg.CheckRules("git", []string{"push", "--force"}, false)
		if err == nil {
			t.Error("expected git push --force to be blocked by default rules")
		}
	})

	t.Run("default rules allow git push without force", func(t *testing.T) {
		reg := cap.NewRegistry()
		cfg := DefaultConfig()
		cfg.ApplyRules(reg)

		err := reg.CheckRules("git", []string{"push", "origin", "master"}, false)
		if err != nil {
			t.Errorf("expected git push (no force) to be allowed, got: %v", err)
		}
	})

	t.Run("hardcoded rules always enforced", func(t *testing.T) {
		reg := cap.NewRegistry()
		cfg := DefaultConfig()
		cfg.ApplyRules(reg)

		// Hardcoded: rm -rf / is always blocked, even with retry.
		err := reg.CheckRules("rm", []string{"-rf", "/"}, true)
		if err == nil {
			t.Error("expected rm -rf / to be blocked even with retry")
		}
	})

	t.Run("config rules bypassed with retry", func(t *testing.T) {
		reg := cap.NewRegistry()
		cfg := DefaultConfig()
		cfg.ApplyRules(reg)

		err := reg.CheckRules("make", []string{"-j4"}, true)
		if err != nil {
			t.Errorf("expected make -j4 with retry to be allowed, got: %v", err)
		}
	})

	t.Run("custom config rules override defaults", func(t *testing.T) {
		reg := cap.NewRegistry()
		cfg := DefaultConfig()
		cfg.Rules = map[string]rules.CapRuleConfig{
			"make": {RejectFlags: []string{"-B"}},
		}
		cfg.ApplyRules(reg)

		// Custom rule should block -B.
		err := reg.CheckRules("make", []string{"-B"}, false)
		if err == nil {
			t.Error("expected make -B to be blocked by custom rule")
		}

		// Default -j rule should NOT apply since custom rules replace defaults.
		err = reg.CheckRules("make", []string{"-j4"}, false)
		if err != nil {
			t.Errorf("expected make -j4 to be allowed when custom rules replace defaults, got: %v", err)
		}
	})

	t.Run("git checkout dot always added as config rule", func(t *testing.T) {
		reg := cap.NewRegistry()
		cfg := DefaultConfig()
		cfg.ApplyRules(reg)

		err := reg.CheckRules("git", []string{"checkout", "."}, false)
		if err == nil {
			t.Error("expected git checkout . to be blocked")
		}

		// Should be bypassable with retry (it's a config rule, not hardcoded).
		err = reg.CheckRules("git", []string{"checkout", "."}, true)
		if err != nil {
			t.Errorf("expected git checkout . with retry to be allowed, got: %v", err)
		}
	})
}

func TestProjectConfigPath(t *testing.T) {
	got := ProjectConfigPath("/home/user/myproject")
	want := filepath.Join("/home/user/myproject", ".doit", "config.yaml")
	if got != want {
		t.Errorf("ProjectConfigPath = %q, want %q", got, want)
	}
}

func TestLoadProjectMissing(t *testing.T) {
	cfg, err := LoadProject(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil config for missing project config")
	}
}

func TestLoadProjectValid(t *testing.T) {
	dir := t.TempDir()
	doitDir := filepath.Join(dir, ".doit")
	if err := os.MkdirAll(doitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := `
tiers:
  dangerous: false
rules:
  npm:
    reject_flags: ["--unsafe-perm"]
`
	if err := os.WriteFile(filepath.Join(doitDir, "config.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadProject(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Tiers.Dangerous {
		t.Error("expected Dangerous=false in project config")
	}
	if _, ok := cfg.Rules["npm"]; !ok {
		t.Error("expected npm rule in project config")
	}
}

func TestLoadProjectInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	doitDir := filepath.Join(dir, ".doit")
	if err := os.MkdirAll(doitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(doitDir, "config.yaml"), []byte(":::bad"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadProject(dir)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestMergeProjectNil(t *testing.T) {
	cfg := DefaultConfig()
	original := *cfg
	cfg.MergeProject(nil)
	if cfg.Tiers != original.Tiers {
		t.Error("MergeProject(nil) should not change tiers")
	}
}

func TestMergeProjectTightenOnly(t *testing.T) {
	t.Run("project disables tier", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Tiers.Write = true
		proj := &Config{Tiers: TierConfig{Read: true, Build: true, Write: false, Dangerous: false}}
		cfg.MergeProject(proj)
		if cfg.Tiers.Write {
			t.Error("expected Write disabled after project merge")
		}
	})

	t.Run("project cannot enable globally disabled tier", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Tiers.Dangerous = false
		proj := &Config{Tiers: TierConfig{Read: true, Build: true, Write: true, Dangerous: true}}
		cfg.MergeProject(proj)
		if cfg.Tiers.Dangerous {
			t.Error("project should not be able to enable globally disabled Dangerous tier")
		}
	})
}

func TestMergeProjectRules(t *testing.T) {
	t.Run("adds new capability rule", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Rules = map[string]rules.CapRuleConfig{
			"make": {RejectFlags: []string{"-j"}},
		}
		proj := &Config{
			Rules: map[string]rules.CapRuleConfig{
				"npm": {RejectFlags: []string{"--unsafe-perm"}},
			},
		}
		cfg.MergeProject(proj)
		if _, ok := cfg.Rules["npm"]; !ok {
			t.Error("expected npm rule after merge")
		}
		if _, ok := cfg.Rules["make"]; !ok {
			t.Error("expected make rule preserved after merge")
		}
	})

	t.Run("merges flags into existing capability", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Rules = map[string]rules.CapRuleConfig{
			"git": {
				Subcommands: map[string]rules.SubRuleConfig{
					"push": {RejectFlags: []string{"--force"}},
				},
			},
		}
		proj := &Config{
			Rules: map[string]rules.CapRuleConfig{
				"git": {
					Subcommands: map[string]rules.SubRuleConfig{
						"push":  {RejectFlags: []string{"--no-verify"}},
						"clean": {RejectFlags: []string{"-f"}},
					},
				},
			},
		}
		cfg.MergeProject(proj)
		gitRule := cfg.Rules["git"]
		pushFlags := gitRule.Subcommands["push"].RejectFlags
		if len(pushFlags) != 2 {
			t.Errorf("expected 2 push flags, got %d: %v", len(pushFlags), pushFlags)
		}
		if _, ok := gitRule.Subcommands["clean"]; !ok {
			t.Error("expected clean subcommand rule after merge")
		}
	})

	t.Run("deduplicates flags", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Rules = map[string]rules.CapRuleConfig{
			"make": {RejectFlags: []string{"-j"}},
		}
		proj := &Config{
			Rules: map[string]rules.CapRuleConfig{
				"make": {RejectFlags: []string{"-j", "-B"}},
			},
		}
		cfg.MergeProject(proj)
		flags := cfg.Rules["make"].RejectFlags
		if len(flags) != 2 {
			t.Errorf("expected 2 flags (deduplicated), got %d: %v", len(flags), flags)
		}
	})

	t.Run("project rules with nil global rules uses defaults", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Rules = nil
		proj := &Config{
			Rules: map[string]rules.CapRuleConfig{
				"npm": {RejectFlags: []string{"--unsafe-perm"}},
			},
		}
		cfg.MergeProject(proj)
		if _, ok := cfg.Rules["make"]; !ok {
			t.Error("expected default make rule when global rules were nil")
		}
		if _, ok := cfg.Rules["npm"]; !ok {
			t.Error("expected npm rule from project")
		}
	})
}
