// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package starlark

import (
	"testing"
)

func loadTestRule(t *testing.T, src string) *Rule {
	t.Helper()
	rule, err := LoadRuleFromSource("test.star", src)
	if err != nil {
		t.Fatalf("LoadRuleFromSource: %v", err)
	}
	return rule
}

func TestEvaluatorDeny(t *testing.T) {
	rule := loadTestRule(t, `
rule_id = "test-deny"
def check(command, args):
    if command == "rm":
        return {"decision": "deny", "reason": "blocked"}
    return None
tests = [
    {"command": "rm", "args": [], "expect": "deny"},
    {"command": "ls", "args": [], "expect": "escalate"},
]
`)
	eval := NewEvaluator([]*Rule{rule})

	result, ruleID := eval.EvaluateCommand("rm", nil, false)
	if result == nil {
		t.Fatal("expected deny result, got nil")
	}
	if result.Decision != "deny" {
		t.Errorf("Decision = %q, want deny", result.Decision)
	}
	if ruleID != "test-deny" {
		t.Errorf("RuleID = %q, want test-deny", ruleID)
	}
}

func TestEvaluatorNoOpinion(t *testing.T) {
	rule := loadTestRule(t, `
rule_id = "test-noop"
def check(command, args):
    return None
tests = [{"command": "x", "args": [], "expect": "escalate"}]
`)
	eval := NewEvaluator([]*Rule{rule})

	result, ruleID := eval.EvaluateCommand("ls", nil, false)
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
	if ruleID != "" {
		t.Errorf("expected empty ruleID, got %q", ruleID)
	}
}

func TestEvaluatorBypassable(t *testing.T) {
	rule := loadTestRule(t, `
rule_id = "test-bypass"
bypassable = True
def check(command, args):
    if command == "make":
        return {"decision": "deny", "reason": "no"}
    return None
tests = [
    {"command": "make", "args": [], "expect": "deny"},
    {"command": "go", "args": [], "expect": "escalate"},
]
`)
	eval := NewEvaluator([]*Rule{rule})

	// Without retry: should deny.
	result, _ := eval.EvaluateCommand("make", nil, false)
	if result == nil || result.Decision != "deny" {
		t.Error("expected deny without retry")
	}

	// With retry: bypassable rule skipped.
	result, _ = eval.EvaluateCommand("make", nil, true)
	if result != nil {
		t.Errorf("expected nil with retry, got %+v", result)
	}
}

func TestEvaluatorFirstRuleWins(t *testing.T) {
	rule1 := loadTestRule(t, `
rule_id = "rule1"
def check(command, args):
    if command == "x":
        return {"decision": "deny", "reason": "rule1"}
    return None
tests = [
    {"command": "x", "args": [], "expect": "deny"},
    {"command": "y", "args": [], "expect": "escalate"},
]
`)
	rule2 := loadTestRule(t, `
rule_id = "rule2"
def check(command, args):
    if command == "x":
        return {"decision": "allow", "reason": "rule2"}
    return None
tests = [
    {"command": "x", "args": [], "expect": "allow"},
    {"command": "y", "args": [], "expect": "escalate"},
]
`)
	eval := NewEvaluator([]*Rule{rule1, rule2})

	result, ruleID := eval.EvaluateCommand("x", nil, false)
	if result == nil || result.Decision != "deny" {
		t.Error("expected first rule to win with deny")
	}
	if ruleID != "rule1" {
		t.Errorf("ruleID = %q, want rule1", ruleID)
	}
}

func TestEvaluatorRuleCount(t *testing.T) {
	rule := loadTestRule(t, `
rule_id = "count"
def check(command, args):
    return None
tests = [{"command": "x", "args": [], "expect": "escalate"}]
`)
	eval := NewEvaluator([]*Rule{rule, rule, rule})
	if eval.RuleCount() != 3 {
		t.Errorf("RuleCount() = %d, want 3", eval.RuleCount())
	}
}

func TestEvaluatorAllow(t *testing.T) {
	rule := loadTestRule(t, `
rule_id = "test-allow"
def check(command, args):
    if command == "ls":
        return {"decision": "allow", "reason": "safe"}
    return None
tests = [
    {"command": "ls", "args": [], "expect": "allow"},
    {"command": "rm", "args": [], "expect": "escalate"},
]
`)
	eval := NewEvaluator([]*Rule{rule})

	result, _ := eval.EvaluateCommand("ls", nil, false)
	if result == nil || result.Decision != "allow" {
		t.Error("expected allow result")
	}
}
