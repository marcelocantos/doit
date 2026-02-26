package rules

import "testing"

func TestCompileCapRuleRejectFlags(t *testing.T) {
	cfg := CapRuleConfig{
		RejectFlags: []string{"-j"},
	}
	fns := CompileCapRule("make", cfg)
	if len(fns) != 1 {
		t.Fatalf("expected 1 check func, got %d", len(fns))
	}

	tests := []struct {
		name    string
		cap     string
		args    []string
		wantErr bool
	}{
		{"j flag blocked", "make", []string{"-j", "all"}, true},
		{"j4 blocked", "make", []string{"-j4", "all"}, true},
		{"j8 blocked", "make", []string{"-j8", "all"}, true},
		{"no j flag", "make", []string{"all"}, false},
		{"different cap", "grep", []string{"-j"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fns[0](tt.cap, tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("reject_flags check(%q, %v) error = %v, wantErr %v",
					tt.cap, tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestCompileCapRuleSubcommands(t *testing.T) {
	cfg := CapRuleConfig{
		Subcommands: map[string]SubRuleConfig{
			"push": {RejectFlags: []string{"--force", "-f"}},
			"reset": {RejectFlags: []string{"--hard"}},
		},
	}
	fns := CompileCapRule("git", cfg)
	if len(fns) != 2 {
		t.Fatalf("expected 2 check funcs, got %d", len(fns))
	}

	// Build a RuleSet so we test all compiled rules together.
	rs := NewRuleSet()
	for _, fn := range fns {
		rs.AddConfig(fn)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"push force blocked", []string{"push", "--force"}, true},
		{"push -f blocked", []string{"push", "-f"}, true},
		{"push normal", []string{"push", "origin", "master"}, false},
		{"reset hard blocked", []string{"reset", "--hard"}, true},
		{"reset soft ok", []string{"reset", "--soft"}, false},
		{"pull force ok", []string{"pull", "--force"}, false},
		{"commit ok", []string{"commit", "-m", "msg"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rs.Check("git", tt.args, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("subcommand check(%v) error = %v, wantErr %v",
					tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestCompileCapRuleMixed(t *testing.T) {
	cfg := CapRuleConfig{
		RejectFlags: []string{"-v"},
		Subcommands: map[string]SubRuleConfig{
			"push": {RejectFlags: []string{"--force"}},
		},
	}
	fns := CompileCapRule("git", cfg)

	rs := NewRuleSet()
	for _, fn := range fns {
		rs.AddConfig(fn)
	}

	// Top-level -v should be rejected on any git invocation.
	if err := rs.Check("git", []string{"status", "-v"}, false); err == nil {
		t.Error("expected top-level reject_flags to block -v")
	}

	// Subcommand-level --force only on push.
	if err := rs.Check("git", []string{"push", "--force"}, false); err == nil {
		t.Error("expected subcommand rule to block push --force")
	}
	if err := rs.Check("git", []string{"pull", "--force"}, false); err != nil {
		t.Errorf("expected pull --force to pass, got %v", err)
	}
}
