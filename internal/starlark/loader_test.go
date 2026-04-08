// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package starlark

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRuleValid(t *testing.T) {
	src := `
rule_id = "test-rule"
description = "A test rule"
bypassable = True

def check(command, args):
    if command == "danger":
        return {"decision": "deny", "reason": "too dangerous"}
    return None

tests = [
    {"command": "danger", "args": [], "expect": "deny"},
    {"command": "safe", "args": [], "expect": "escalate"},
]
`
	rule, err := LoadRuleFromSource("test.star", src)
	if err != nil {
		t.Fatalf("LoadRuleFromSource: %v", err)
	}
	if rule.ID != "test-rule" {
		t.Errorf("ID = %q, want %q", rule.ID, "test-rule")
	}
	if rule.Description != "A test rule" {
		t.Errorf("Description = %q, want %q", rule.Description, "A test rule")
	}
	if !rule.Bypassable {
		t.Error("Bypassable = false, want true")
	}
	if len(rule.Tests) != 2 {
		t.Errorf("len(Tests) = %d, want 2", len(rule.Tests))
	}
}

func TestLoadRuleMissingRuleID(t *testing.T) {
	src := `
def check(command, args):
    return None
tests = [{"command": "x", "args": [], "expect": "escalate"}]
`
	_, err := LoadRuleFromSource("test.star", src)
	if err == nil || !strings.Contains(err.Error(), "missing rule_id") {
		t.Errorf("expected 'missing rule_id' error, got: %v", err)
	}
}

func TestLoadRuleMissingCheck(t *testing.T) {
	src := `
rule_id = "test"
tests = [{"command": "x", "args": [], "expect": "escalate"}]
`
	_, err := LoadRuleFromSource("test.star", src)
	if err == nil || !strings.Contains(err.Error(), "missing check function") {
		t.Errorf("expected 'missing check function' error, got: %v", err)
	}
}

func TestLoadRuleMissingTests(t *testing.T) {
	src := `
rule_id = "test"
def check(command, args):
    return None
`
	_, err := LoadRuleFromSource("test.star", src)
	if err == nil || !strings.Contains(err.Error(), "missing tests") {
		t.Errorf("expected 'missing tests' error, got: %v", err)
	}
}

func TestLoadRuleEmptyTests(t *testing.T) {
	src := `
rule_id = "test"
def check(command, args):
    return None
tests = []
`
	_, err := LoadRuleFromSource("test.star", src)
	if err == nil || !strings.Contains(err.Error(), "tests list must not be empty") {
		t.Errorf("expected 'tests list must not be empty' error, got: %v", err)
	}
}

func TestLoadRuleTestValidationFailure(t *testing.T) {
	src := `
rule_id = "test"
def check(command, args):
    return None
tests = [
    {"command": "x", "args": [], "expect": "deny"},
]
`
	_, err := LoadRuleFromSource("test.star", src)
	if err == nil || !strings.Contains(err.Error(), "test validation failed") {
		t.Errorf("expected 'test validation failed' error, got: %v", err)
	}
}

func TestLoadRuleSyntaxError(t *testing.T) {
	src := `
rule_id = "test"
def check(command args):  # missing comma
    return None
tests = []
`
	_, err := LoadRuleFromSource("test.star", src)
	if err == nil || !strings.Contains(err.Error(), "exec starlark") {
		t.Errorf("expected starlark syntax error, got: %v", err)
	}
}

func TestLoadRuleInvalidDecision(t *testing.T) {
	src := `
rule_id = "test"
def check(command, args):
    return {"decision": "maybe", "reason": "unsure"}
tests = [
    {"command": "x", "args": [], "expect": "maybe"},
]
`
	_, err := LoadRuleFromSource("test.star", src)
	if err == nil || !strings.Contains(err.Error(), "invalid decision") {
		t.Errorf("expected 'invalid decision' error, got: %v", err)
	}
}

func TestLoadRuleCheckWrongParams(t *testing.T) {
	src := `
rule_id = "test"
def check(command):
    return None
tests = [{"command": "x", "args": [], "expect": "escalate"}]
`
	_, err := LoadRuleFromSource("test.star", src)
	if err == nil || !strings.Contains(err.Error(), "check function must take 2 parameters") {
		t.Errorf("expected 'check function must take 2 parameters' error, got: %v", err)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()

	// Write a valid rule.
	validRule := `
rule_id = "dir-test"
description = "test"
def check(command, args):
    if command == "bad":
        return {"decision": "deny", "reason": "bad command"}
    return None
tests = [
    {"command": "bad", "args": [], "expect": "deny"},
    {"command": "good", "args": [], "expect": "escalate"},
]
`
	if err := os.WriteFile(filepath.Join(dir, "valid.star"), []byte(validRule), 0644); err != nil {
		t.Fatal(err)
	}

	// Write a non-.star file (should be skipped).
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("ignore me"), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("len(rules) = %d, want 1", len(rules))
	}
	if rules[0].ID != "dir-test" {
		t.Errorf("ID = %q, want %q", rules[0].ID, "dir-test")
	}
}

func TestLoadDirNonexistent(t *testing.T) {
	rules, err := LoadDir("/nonexistent/path")
	if err != nil {
		t.Fatalf("LoadDir nonexistent: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("len(rules) = %d, want 0", len(rules))
	}
}

func TestLoadDirInvalidRule(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.star"), []byte("rule_id = 42"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDir(dir)
	if err == nil {
		t.Error("expected error for invalid rule, got nil")
	}
}

func TestLoadRuleFromFile(t *testing.T) {
	dir := t.TempDir()
	src := `
rule_id = "file-test"
def check(command, args):
    return None
tests = [{"command": "x", "args": [], "expect": "escalate"}]
`
	path := filepath.Join(dir, "test.star")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	rule, err := LoadRule(path)
	if err != nil {
		t.Fatalf("LoadRule: %v", err)
	}
	if rule.ID != "file-test" {
		t.Errorf("ID = %q, want %q", rule.ID, "file-test")
	}
}
