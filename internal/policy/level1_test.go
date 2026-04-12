// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

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
		command  string
		wantDeny bool
	}{
		{"rm -rf /", "rm -rf /", true},
		{"rm -rf .", "rm -rf .", true},
		{"rm -rf ..", "rm -rf ..", true},
		{"rm -rf ~", "rm -rf ~", true},
		{"rm -rf ~/", "rm -rf ~/", true},
		{"rm -r /", "rm -r /", true},
		{"rm -R /", "rm -R /", true},
		{"rm -rf /tmp/safe", "rm -rf /tmp/safe", false},
		{"rm file.txt (no recursive flag)", "rm file.txt", false},
		{"grep -rf / (not rm)", "grep -rf /", false},
		{"rm -fr /", "rm -fr /", true},
		{"rm -rf //", "rm -rf //", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{Command: tt.command})
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
		Command: "rm -rf /",
		Retry:   true,
	})
	if result.Decision != Deny {
		t.Errorf("got decision=%v, want deny (hardcoded rules cannot be bypassed)", result.Decision)
	}
}

func TestDenyMakeFlags(t *testing.T) {
	l1 := defaultLevel1()
	tests := []struct {
		name     string
		command  string
		wantDeny bool
	}{
		{"make -j4", "make -j4", true},
		{"make -j", "make -j", true},
		{"make clean", "make clean", false},
		{"make (no args)", "make", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{Command: tt.command})
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
		command  string
		wantDeny bool
	}{
		{"git push --force", "git push --force", true},
		{"git push -f", "git push -f", true},
		{"git push --force-with-lease", "git push --force-with-lease", true},
		{"git push", "git push", false},
		{"git push origin master", "git push origin master", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{Command: tt.command})
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
		command  string
		wantDeny bool
	}{
		{"git reset --hard", "git reset --hard", true},
		{"git reset --hard HEAD~1", "git reset --hard HEAD~1", true},
		{"git reset", "git reset", false},
		{"git reset --soft", "git reset --soft", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{Command: tt.command})
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
		command  string
		wantDeny bool
	}{
		{"git checkout .", "git checkout .", true},
		{"git checkout -- .", "git checkout -- .", true},
		{"git checkout ./", "git checkout ./", true},
		{"git checkout branch", "git checkout feature", false},
		{"git checkout -- file.go", "git checkout -- file.go", false},
		{"git status", "git status", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{Command: tt.command})
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

func TestRetryBypassesConfigRules(t *testing.T) {
	l1 := defaultLevel1()

	tests := []struct {
		name    string
		command string
	}{
		{"make -j bypassed", "make -j4"},
		{"git push --force bypassed", "git push --force"},
		{"git checkout . bypassed", "git checkout ."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{
				Command: tt.command,
				Retry:   true,
			})
			if result.Decision == Deny {
				t.Errorf("got deny, want non-deny (config rules should be bypassed with retry): %s", result.Reason)
			}
		})
	}
}

func TestEscalateWhenNoRuleMatches(t *testing.T) {
	l1 := defaultLevel1()
	result := l1.Evaluate(&Request{Command: "make"})
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
		Command:       "grep foo file",
		Justification: "need to search for error patterns",
		SafetyArg:     "read-only grep, no side effects",
	})
	// grep is not a known-deny command; it escalates (no whitelist in L1).
	if result.Decision == Deny {
		t.Errorf("got deny, want non-deny for grep command")
	}
	// Justification and SafetyArg are on the Request, not the Result.
	// They flow through to audit logging via the daemon.
}

func TestEmptyCommand(t *testing.T) {
	l1 := defaultLevel1()
	result := l1.Evaluate(&Request{Command: ""})
	if result.Decision != Escalate {
		t.Errorf("got decision=%v, want escalate for empty command", result.Decision)
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
