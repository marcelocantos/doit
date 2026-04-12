// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// bypass_regression_test.go verifies that the L1 engine never auto-allows
// commands that contain shell composition operators or otherwise look
// superficially read-only but are actually dangerous.
//
// Before 🎯T17, the checkSafePipeline rule vacuously allowed any command
// whose first word was a read-tier capability, because req.Segments always
// contained exactly one synthetic segment (the first token). That meant
// "ls && rm -rf /" was allowed at L1. This file ensures those bypasses
// never return.
//
// These commands must NOT be allowed by any L1 rule. They must escalate
// (or be denied by a specific deny rule) so that L2/L3 gets a chance to
// evaluate them.
package policy

import (
	"testing"
)

// TestNoL1BypassForCompositeCommands verifies that commands containing shell
// composition operators, redirects, or subshells are never auto-allowed by L1.
// Each command must escalate (not be allowed) at L1.
func TestNoL1BypassForCompositeCommands(t *testing.T) {
	l1 := defaultLevel1()

	tests := []struct {
		name    string
		command string
	}{
		// Shell composition operators
		{"ls && rm -rf /", "ls && rm -rf /"},
		{"ls; rm -rf /tmp/x", "ls; rm -rf /tmp/x"},
		{"cat foo | tee bar", "cat foo | tee bar"},
		// Output redirection
		{"cat /etc/passwd > /tmp/stolen", "cat /etc/passwd > /tmp/stolen"},
		// Command substitution (backtick)
		{"ls with backtick subshell", "ls `rm -rf /`"},
		// Command substitution ($(...))
		{"ls with dollar-paren subshell", "ls $(rm -rf /)"},
		// Bare echo — unknown cap, no whitelist, must escalate
		{"echo hello", "echo hello"},
		// Bare ls — read-tier cap, but no whitelist, must escalate
		{"bare ls", "ls"},
		// git push without flags — no deny rule matches, must escalate
		{"git push bare", "git push"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{Command: tt.command})
			if result.Decision == Allow {
				t.Errorf("command %q was allowed at L1 (rule=%q, reason=%q) — must escalate or be denied",
					tt.command, result.RuleID, result.Reason)
			}
		})
	}
}

// TestSpecificDenyRulesStillWork verifies that the specific deny rules that
// existed before 🎯T17 still match correctly after the opaque-string refactor.
func TestSpecificDenyRulesStillWork(t *testing.T) {
	l1 := defaultLevel1()

	tests := []struct {
		name       string
		command    string
		wantRuleID string
	}{
		{"rm -rf / still denied", "rm -rf /", "deny-rm-catastrophic"},
		{"git push --force still denied", "git push --force", "deny-git-push-flags"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l1.Evaluate(&Request{Command: tt.command})
			if result.Decision != Deny {
				t.Errorf("command %q: got decision=%v, want deny", tt.command, result.Decision)
			}
		})
	}
}
