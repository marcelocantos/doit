// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/rules"
)

func defaultLevel1() *Level1 {
	return NewLevel1(map[string]rules.CapRuleConfig{
		"make": {
			RejectFlags: []string{"-j"},
		},
		"git": {
			Subcommands: map[string]rules.SubRuleConfig{
				"push":  {RejectFlags: []string{"--force", "-f", "--force-with-lease"}},
				"reset": {RejectFlags: []string{"--hard"}},
			},
		},
	})
}

func TestDenyRmCatastrophic(t *testing.T) {
	l1 := defaultLevel1()
	tests := []struct {
		name     string
		segments []Segment
		wantDeny bool
	}{
		{
			"rm -rf /",
			[]Segment{{CapName: "rm", Args: []string{"-rf", "/"}, Tier: cap.TierDangerous}},
			true,
		},
		{
			"rm -rf .",
			[]Segment{{CapName: "rm", Args: []string{"-rf", "."}, Tier: cap.TierDangerous}},
			true,
		},
		{
			"rm -rf ..",
			[]Segment{{CapName: "rm", Args: []string{"-rf", ".."}, Tier: cap.TierDangerous}},
			true,
		},
		{
			"rm -rf ~",
			[]Segment{{CapName: "rm", Args: []string{"-rf", "~"}, Tier: cap.TierDangerous}},
			true,
		},
		{
			"rm -rf ~/",
			[]Segment{{CapName: "rm", Args: []string{"-rf", "~/"}, Tier: cap.TierDangerous}},
			true,
		},
		{
			"rm -r /",
			[]Segment{{CapName: "rm", Args: []string{"-r", "/"}, Tier: cap.TierDangerous}},
			true,
		},
		{
			"rm -R /",
			[]Segment{{CapName: "rm", Args: []string{"-R", "/"}, Tier: cap.TierDangerous}},
			true,
		},
		{
			"rm -rf /tmp/safe",
			[]Segment{{CapName: "rm", Args: []string{"-rf", "/tmp/safe"}, Tier: cap.TierDangerous}},
			false,
		},
		{
			"rm file.txt (no recursive flag)",
			[]Segment{{CapName: "rm", Args: []string{"file.txt"}, Tier: cap.TierDangerous}},
			false,
		},
		{
			"grep -rf / (not rm)",
			[]Segment{{CapName: "grep", Args: []string{"-rf", "/"}, Tier: cap.TierRead}},
			false,
		},
		{
			"rm -fr /",
			[]Segment{{CapName: "rm", Args: []string{"-fr", "/"}, Tier: cap.TierDangerous}},
			true,
		},
		{
			"rm -rf //",
			[]Segment{{CapName: "rm", Args: []string{"-rf", "//"}, Tier: cap.TierDangerous}},
			true,
		},
		{
			"rm -rf in pipeline",
			[]Segment{
				{CapName: "grep", Args: []string{"foo"}, Tier: cap.TierRead},
				{CapName: "rm", Args: []string{"-rf", "/"}, Tier: cap.TierDangerous},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{Segments: tt.segments})
			if tt.wantDeny {
				if result.Decision != Deny || result.RuleID != "deny-rm-catastrophic" {
					t.Errorf("got decision=%v rule=%q, want deny by deny-rm-catastrophic",
						result.Decision, result.RuleID)
				}
			} else if result.Decision == Deny && result.RuleID == "deny-rm-catastrophic" {
				t.Errorf("unexpected deny by deny-rm-catastrophic")
			}
		})
	}
}

func TestDenyRmCatastrophicNotBypassable(t *testing.T) {
	l1 := defaultLevel1()
	result := l1.Evaluate(&Request{
		Segments: []Segment{{CapName: "rm", Args: []string{"-rf", "/"}, Tier: cap.TierDangerous}},
		Retry:    true,
	})
	if result.Decision != Deny {
		t.Errorf("got decision=%v, want deny (hardcoded rules cannot be bypassed)", result.Decision)
	}
}

func TestDenyMakeFlags(t *testing.T) {
	l1 := defaultLevel1()
	tests := []struct {
		name     string
		args     []string
		wantDeny bool
	}{
		{"make -j4", []string{"-j4"}, true},
		{"make -j", []string{"-j"}, true},
		{"make clean", []string{"clean"}, false},
		{"make (no args)", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{
				Segments: []Segment{{CapName: "make", Args: tt.args, Tier: cap.TierBuild}},
			})
			if tt.wantDeny {
				if result.Decision != Deny {
					t.Errorf("got decision=%v, want deny", result.Decision)
				}
			} else if result.Decision == Deny {
				t.Errorf("unexpected deny: %s", result.Reason)
			}
		})
	}
}

func TestDenyGitPushFlags(t *testing.T) {
	l1 := defaultLevel1()
	tests := []struct {
		name     string
		args     []string
		wantDeny bool
	}{
		{"git push --force", []string{"push", "--force"}, true},
		{"git push -f", []string{"push", "-f"}, true},
		{"git push --force-with-lease", []string{"push", "--force-with-lease"}, true},
		{"git push", []string{"push"}, false},
		{"git push origin master", []string{"push", "origin", "master"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{
				Segments: []Segment{{CapName: "git", Args: tt.args, Tier: cap.TierRead}},
			})
			if tt.wantDeny {
				if result.Decision != Deny {
					t.Errorf("got decision=%v, want deny", result.Decision)
				}
			} else if result.Decision == Deny {
				t.Errorf("unexpected deny: %s", result.Reason)
			}
		})
	}
}

func TestDenyGitResetHard(t *testing.T) {
	l1 := defaultLevel1()
	tests := []struct {
		name     string
		args     []string
		wantDeny bool
	}{
		{"git reset --hard", []string{"reset", "--hard"}, true},
		{"git reset --hard HEAD~1", []string{"reset", "--hard", "HEAD~1"}, true},
		{"git reset", []string{"reset"}, false},
		{"git reset --soft", []string{"reset", "--soft"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{
				Segments: []Segment{{CapName: "git", Args: tt.args, Tier: cap.TierRead}},
			})
			if tt.wantDeny {
				if result.Decision != Deny {
					t.Errorf("got decision=%v, want deny", result.Decision)
				}
			} else if result.Decision == Deny {
				t.Errorf("unexpected deny: %s", result.Reason)
			}
		})
	}
}

func TestDenyGitCheckoutAll(t *testing.T) {
	l1 := defaultLevel1()
	tests := []struct {
		name     string
		args     []string
		wantDeny bool
	}{
		{"git checkout .", []string{"checkout", "."}, true},
		{"git checkout -- .", []string{"checkout", "--", "."}, true},
		{"git checkout ./", []string{"checkout", "./"}, true},
		{"git checkout branch", []string{"checkout", "feature"}, false},
		{"git checkout -- file.go", []string{"checkout", "--", "file.go"}, false},
		{"git status", []string{"status"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{
				Segments: []Segment{{CapName: "git", Args: tt.args, Tier: cap.TierRead}},
			})
			if tt.wantDeny {
				if result.Decision != Deny || result.RuleID != "deny-git-checkout-all" {
					t.Errorf("got decision=%v rule=%q, want deny by deny-git-checkout-all",
						result.Decision, result.RuleID)
				}
			} else if result.Decision == Deny && result.RuleID == "deny-git-checkout-all" {
				t.Errorf("unexpected deny by deny-git-checkout-all")
			}
		})
	}
}

func TestAllowSafePipeline(t *testing.T) {
	l1 := defaultLevel1()
	tests := []struct {
		name      string
		segments  []Segment
		redirect  bool
		wantAllow bool
	}{
		{
			"single read-only",
			[]Segment{{CapName: "grep", Args: []string{"foo", "file"}, Tier: cap.TierRead}},
			false,
			true,
		},
		{
			"multi read-only pipeline",
			[]Segment{
				{CapName: "grep", Args: []string{"foo"}, Tier: cap.TierRead},
				{CapName: "sort", Tier: cap.TierRead},
				{CapName: "head", Tier: cap.TierRead},
			},
			false,
			true,
		},
		{
			"mixed tiers",
			[]Segment{
				{CapName: "grep", Args: []string{"foo"}, Tier: cap.TierRead},
				{CapName: "tee", Args: []string{"out.txt"}, Tier: cap.TierWrite},
			},
			false,
			false,
		},
		{
			"read-only with output redirect",
			[]Segment{{CapName: "grep", Args: []string{"foo"}, Tier: cap.TierRead}},
			true,
			false,
		},
		{
			"build tier",
			[]Segment{{CapName: "make", Tier: cap.TierBuild}},
			false,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{
				Segments:       tt.segments,
				HasRedirectOut: tt.redirect,
			})
			if tt.wantAllow {
				if result.Decision != Allow || result.RuleID != "allow-safe-pipeline" {
					t.Errorf("got decision=%v rule=%q, want allow by allow-safe-pipeline",
						result.Decision, result.RuleID)
				}
			} else if result.Decision == Allow && result.RuleID == "allow-safe-pipeline" {
				t.Errorf("unexpected allow by allow-safe-pipeline")
			}
		})
	}
}

func TestRetryBypassesConfigRules(t *testing.T) {
	l1 := defaultLevel1()

	tests := []struct {
		name     string
		segments []Segment
	}{
		{
			"make -j bypassed",
			[]Segment{{CapName: "make", Args: []string{"-j4"}, Tier: cap.TierBuild}},
		},
		{
			"git push --force bypassed",
			[]Segment{{CapName: "git", Args: []string{"push", "--force"}, Tier: cap.TierRead}},
		},
		{
			"git checkout . bypassed",
			[]Segment{{CapName: "git", Args: []string{"checkout", "."}, Tier: cap.TierRead}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{
				Segments: tt.segments,
				Retry:    true,
			})
			if result.Decision == Deny {
				t.Errorf("got deny, want non-deny (config rules should be bypassed with retry): %s", result.Reason)
			}
		})
	}
}

func TestEscalateWhenNoRuleMatches(t *testing.T) {
	l1 := defaultLevel1()
	result := l1.Evaluate(&Request{
		Segments: []Segment{{CapName: "make", Tier: cap.TierBuild}},
	})
	if result.Decision != Escalate {
		t.Errorf("got decision=%v, want escalate", result.Decision)
	}
	if result.Level != 1 {
		t.Errorf("got level=%d, want 1", result.Level)
	}
}

func TestDecisionString(t *testing.T) {
	tests := []struct {
		d    Decision
		want string
	}{
		{Allow, "allow"},
		{Deny, "deny"},
		{Escalate, "escalate"},
		{Decision(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.d.String(); got != tt.want {
			t.Errorf("Decision(%d).String() = %q, want %q", int(tt.d), got, tt.want)
		}
	}
}

func TestJustificationPassthrough(t *testing.T) {
	l1 := defaultLevel1()
	result := l1.Evaluate(&Request{
		Segments:      []Segment{{CapName: "grep", Args: []string{"foo"}, Tier: cap.TierRead}},
		Justification: "need to search for error patterns",
		SafetyArg:     "read-only grep, no side effects",
	})
	if result.Decision != Allow {
		t.Errorf("got decision=%v, want allow", result.Decision)
	}
	// Justification and SafetyArg are on the Request, not the Result.
	// They flow through to audit logging via the daemon.
}

func TestEmptySegments(t *testing.T) {
	l1 := defaultLevel1()
	result := l1.Evaluate(&Request{Segments: nil})
	if result.Decision != Escalate {
		t.Errorf("got decision=%v, want escalate for empty segments", result.Decision)
	}
}

func TestHasAnyFlag(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		flags []string
		want  bool
	}{
		{"exact match", []string{"-f"}, []string{"-f"}, true},
		{"no match", []string{"-v"}, []string{"-f"}, false},
		{"combined short", []string{"-rf"}, []string{"-r"}, true},
		{"value suffix", []string{"-j4"}, []string{"-j"}, true},
		{"long with equals", []string{"--force=yes"}, []string{"--force"}, true},
		{"long exact", []string{"--force"}, []string{"--force"}, true},
		{"non-flag arg", []string{"hello"}, []string{"-f"}, false},
		{"empty args", nil, []string{"-f"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasAnyFlag(tt.args, tt.flags...); got != tt.want {
				t.Errorf("HasAnyFlag(%v, %v) = %v, want %v", tt.args, tt.flags, got, tt.want)
			}
		})
	}
}
