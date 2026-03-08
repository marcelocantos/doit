// Copyright 2025 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/marcelocantos/doit/internal/rules"
)

// mockCap is a minimal Capability implementation for testing.
type mockCap struct {
	name string
	desc string
	tier Tier
}

func (m *mockCap) Name() string                          { return m.name }
func (m *mockCap) Description() string                   { return m.desc }
func (m *mockCap) Tier() Tier                            { return m.tier }
func (m *mockCap) Validate(args []string) error          { return nil }
func (m *mockCap) Run(_ context.Context, _ []string, _ io.Reader, _, _ io.Writer) error {
	return nil
}

func TestParseTier(t *testing.T) {
	tests := []struct {
		input   string
		want    Tier
		wantErr bool
	}{
		{"read", TierRead, false},
		{"build", TierBuild, false},
		{"write", TierWrite, false},
		{"dangerous", TierDangerous, false},
		{"", 0, true},
		{"unknown", 0, true},
		{"READ", 0, true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.input), func(t *testing.T) {
			got, err := ParseTier(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTier(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseTier(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTierString(t *testing.T) {
	tests := []struct {
		tier Tier
		want string
	}{
		{TierRead, "read"},
		{TierBuild, "build"},
		{TierWrite, "write"},
		{TierDangerous, "dangerous"},
		{Tier(999), "tier(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.tier.String(); got != tt.want {
				t.Errorf("Tier(%d).String() = %q, want %q", int(tt.tier), got, tt.want)
			}
		})
	}
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()

	// Read, Build, Write should be enabled.
	for _, tier := range []Tier{TierRead, TierBuild, TierWrite} {
		if err := r.CheckTier(tier); err != nil {
			t.Errorf("NewRegistry: tier %v should be enabled, got error: %v", tier, err)
		}
	}

	// Dangerous should be disabled.
	if err := r.CheckTier(TierDangerous); err == nil {
		t.Error("NewRegistry: TierDangerous should be disabled, got nil error")
	}
}

func TestRegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	c := &mockCap{name: "grep", desc: "search files", tier: TierRead}
	r.Register(c)

	// Successful lookup.
	got, err := r.Lookup("grep")
	if err != nil {
		t.Fatalf("Lookup(grep) unexpected error: %v", err)
	}
	if got.Name() != "grep" {
		t.Errorf("Lookup(grep).Name() = %q, want %q", got.Name(), "grep")
	}

	// Non-existent capability.
	_, err = r.Lookup("nonexistent")
	if err == nil {
		t.Error("Lookup(nonexistent) should return error, got nil")
	}
}

func TestCheckTier(t *testing.T) {
	r := NewRegistry()

	// Read is enabled by default.
	if err := r.CheckTier(TierRead); err != nil {
		t.Fatalf("CheckTier(Read) should succeed: %v", err)
	}

	// Dangerous is disabled by default.
	if err := r.CheckTier(TierDangerous); err == nil {
		t.Fatal("CheckTier(Dangerous) should fail when disabled")
	}

	// Enable Dangerous, should now succeed.
	r.SetTier(TierDangerous, true)
	if err := r.CheckTier(TierDangerous); err != nil {
		t.Fatalf("CheckTier(Dangerous) should succeed after enabling: %v", err)
	}

	// Disable Read, should now fail.
	r.SetTier(TierRead, false)
	if err := r.CheckTier(TierRead); err == nil {
		t.Fatal("CheckTier(Read) should fail after disabling")
	}
}

func TestRegistryAll(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockCap{name: "cat", tier: TierRead})
	r.Register(&mockCap{name: "awk", tier: TierRead})
	r.Register(&mockCap{name: "make", tier: TierBuild})

	all := r.All()
	if len(all) != 3 {
		t.Fatalf("All() returned %d capabilities, want 3", len(all))
	}

	want := []string{"awk", "cat", "make"}
	for i, c := range all {
		if c.Name() != want[i] {
			t.Errorf("All()[%d].Name() = %q, want %q", i, c.Name(), want[i])
		}
	}
}

func TestCheckRules(t *testing.T) {
	r := NewRegistry()

	// Set up a rule set with a config rule that blocks "blocked-arg".
	rs := rules.NewRuleSet()
	rs.AddConfig(func(capName string, args []string) error {
		for _, a := range args {
			if a == "blocked-arg" {
				return fmt.Errorf("blocked by config rule")
			}
		}
		return nil
	})
	r.SetRules(rs)

	// No matching args: should pass.
	if err := r.CheckRules("test", []string{"safe"}, false); err != nil {
		t.Errorf("CheckRules with safe args should pass: %v", err)
	}

	// Matching args, retry=false: should fail.
	if err := r.CheckRules("test", []string{"blocked-arg"}, false); err == nil {
		t.Error("CheckRules with blocked arg and retry=false should fail")
	}

	// Matching args, retry=true: config rules bypassed, should pass.
	if err := r.CheckRules("test", []string{"blocked-arg"}, true); err != nil {
		t.Errorf("CheckRules with retry=true should bypass config rules: %v", err)
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()

	// Registry round-trip.
	reg := NewRegistry()
	ctx = NewContext(ctx, reg)
	gotReg, ok := RegistryFromContext(ctx)
	if !ok {
		t.Fatal("RegistryFromContext returned ok=false")
	}
	if gotReg != reg {
		t.Error("RegistryFromContext returned different registry")
	}

	// Registry missing from bare context.
	_, ok = RegistryFromContext(context.Background())
	if ok {
		t.Error("RegistryFromContext on bare context should return ok=false")
	}

	// Cwd round-trip.
	ctx = NewCwdContext(ctx, "/tmp/work")
	if got := CwdFromContext(ctx); got != "/tmp/work" {
		t.Errorf("CwdFromContext = %q, want %q", got, "/tmp/work")
	}

	// Cwd missing from bare context.
	if got := CwdFromContext(context.Background()); got != "" {
		t.Errorf("CwdFromContext on bare context = %q, want empty", got)
	}

	// Env round-trip.
	env := map[string]string{"HOME": "/home/test", "PATH": "/usr/bin"}
	ctx = NewEnvContext(ctx, env)
	gotEnv := EnvFromContext(ctx)
	if gotEnv == nil {
		t.Fatal("EnvFromContext returned nil")
	}
	if gotEnv["HOME"] != "/home/test" {
		t.Errorf("EnvFromContext[HOME] = %q, want %q", gotEnv["HOME"], "/home/test")
	}
	if gotEnv["PATH"] != "/usr/bin" {
		t.Errorf("EnvFromContext[PATH] = %q, want %q", gotEnv["PATH"], "/usr/bin")
	}

	// Env missing from bare context.
	if got := EnvFromContext(context.Background()); got != nil {
		t.Errorf("EnvFromContext on bare context = %v, want nil", got)
	}
}
