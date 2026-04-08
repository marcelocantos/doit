// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package starlark

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rulesDir returns the path to the rules/ directory at repo root.
func rulesDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	dir := filepath.Join(root, "rules")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("rules/ directory not found at %s", dir)
	}
	return dir
}

func TestExampleRulesLoad(t *testing.T) {
	dir := rulesDir(t)
	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir(%s): %v", dir, err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules loaded from rules/ directory")
	}

	// Verify expected rules are present.
	expectedIDs := map[string]bool{
		"deny-rm-catastrophic":  false,
		"deny-make-j":           false,
		"deny-git-push-force":   false,
		"deny-git-reset-hard":   false,
		"deny-git-checkout-all": false,
	}
	for _, rule := range rules {
		if _, ok := expectedIDs[rule.ID]; ok {
			expectedIDs[rule.ID] = true
		}
	}
	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected rule %q not found in loaded rules", id)
		}
	}
}

func TestExampleRmCatastrophic(t *testing.T) {
	dir := rulesDir(t)
	rule, err := LoadRule(filepath.Join(dir, "deny_rm_catastrophic.star"))
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}

	tests := []struct {
		command string
		args    []string
		deny    bool
	}{
		{"rm", []string{"-rf", "/"}, true},
		{"rm", []string{"-rf", "."}, true},
		{"rm", []string{"-rf", "~"}, true},
		{"rm", []string{"-rf", "~/Documents"}, true},
		{"rm", []string{"-rf", "build/"}, false},
		{"rm", []string{"somefile"}, false},
		{"ls", []string{"-la"}, false},
	}
	for _, tt := range tests {
		result, err := rule.Evaluate(tt.command, tt.args)
		if err != nil {
			t.Errorf("Evaluate(%s, %v): %v", tt.command, tt.args, err)
			continue
		}
		got := result != nil && result.Decision == "deny"
		if got != tt.deny {
			t.Errorf("Evaluate(%s, %v): got deny=%v, want %v", tt.command, tt.args, got, tt.deny)
		}
	}
}

func TestExampleMakeJ(t *testing.T) {
	dir := rulesDir(t)
	rule, err := LoadRule(filepath.Join(dir, "deny_make_j.star"))
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}

	tests := []struct {
		command string
		args    []string
		deny    bool
	}{
		{"make", []string{"-j"}, true},
		{"make", []string{"-j4"}, true},
		{"make", []string{"all"}, false},
		{"go", []string{"-j"}, false},
	}
	for _, tt := range tests {
		result, err := rule.Evaluate(tt.command, tt.args)
		if err != nil {
			t.Errorf("Evaluate(%s, %v): %v", tt.command, tt.args, err)
			continue
		}
		got := result != nil && result.Decision == "deny"
		if got != tt.deny {
			t.Errorf("Evaluate(%s, %v): got deny=%v, want %v", tt.command, tt.args, got, tt.deny)
		}
	}
}

func TestExampleGitForcePush(t *testing.T) {
	dir := rulesDir(t)
	rule, err := LoadRule(filepath.Join(dir, "deny_git_force_push.star"))
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}

	tests := []struct {
		command string
		args    []string
		deny    bool
	}{
		{"git", []string{"push", "--force"}, true},
		{"git", []string{"push", "-f"}, true},
		{"git", []string{"push", "--force-with-lease"}, true},
		{"git", []string{"push"}, false},
		{"git", []string{"pull", "--force"}, false},
	}
	for _, tt := range tests {
		result, err := rule.Evaluate(tt.command, tt.args)
		if err != nil {
			t.Errorf("Evaluate(%s, %v): %v", tt.command, tt.args, err)
			continue
		}
		got := result != nil && result.Decision == "deny"
		if got != tt.deny {
			t.Errorf("Evaluate(%s, %v): got deny=%v, want %v", tt.command, tt.args, got, tt.deny)
		}
	}
}

func TestExampleGitResetHard(t *testing.T) {
	dir := rulesDir(t)
	rule, err := LoadRule(filepath.Join(dir, "deny_git_reset_hard.star"))
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}

	tests := []struct {
		command string
		args    []string
		deny    bool
	}{
		{"git", []string{"reset", "--hard"}, true},
		{"git", []string{"reset", "--hard", "HEAD~1"}, true},
		{"git", []string{"reset"}, false},
		{"git", []string{"reset", "--soft", "HEAD~1"}, false},
	}
	for _, tt := range tests {
		result, err := rule.Evaluate(tt.command, tt.args)
		if err != nil {
			t.Errorf("Evaluate(%s, %v): %v", tt.command, tt.args, err)
			continue
		}
		got := result != nil && result.Decision == "deny"
		if got != tt.deny {
			t.Errorf("Evaluate(%s, %v): got deny=%v, want %v", tt.command, tt.args, got, tt.deny)
		}
	}
}

func TestExampleGitCheckoutAll(t *testing.T) {
	dir := rulesDir(t)
	rule, err := LoadRule(filepath.Join(dir, "deny_git_checkout_all.star"))
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}

	tests := []struct {
		command string
		args    []string
		deny    bool
	}{
		{"git", []string{"checkout", "."}, true},
		{"git", []string{"checkout", "--", "."}, true},
		{"git", []string{"checkout", "main"}, false},
		{"git", []string{"checkout", "-b", "feature"}, false},
	}
	for _, tt := range tests {
		result, err := rule.Evaluate(tt.command, tt.args)
		if err != nil {
			t.Errorf("Evaluate(%s, %v): %v", tt.command, tt.args, err)
			continue
		}
		got := result != nil && result.Decision == "deny"
		if got != tt.deny {
			t.Errorf("Evaluate(%s, %v): got deny=%v, want %v", tt.command, tt.args, got, tt.deny)
		}
	}
}
