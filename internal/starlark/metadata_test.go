// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package starlark

import (
	"testing"
)

func TestRule_ThreeParamReceivesMetadata(t *testing.T) {
	src := `
rule_id = "uses-meta"
def check(command, args, meta):
    if command != "sleep":
        return None
    expected = meta.get("expected_duration_seconds", 0)
    if expected > 0 and len(args) > 0 and int(args[0]) > expected * 2:
        return {"decision": "deny", "reason": "sleep exceeds expectation"}
    return None

tests = [
    # With metadata set: flagged
    {"command": "sleep", "args": ["30"], "expect": "deny", "meta": {"expected_duration_seconds": 5}},
    # Without metadata: silent
    {"command": "sleep", "args": ["30"], "expect": "escalate"},
    # Matched metadata: silent
    {"command": "sleep", "args": ["5"], "expect": "escalate", "meta": {"expected_duration_seconds": 5}},
    # Unrelated command: silent
    {"command": "ls", "args": ["-la"], "expect": "escalate", "meta": {"expected_duration_seconds": 5}},
]
`
	rule := loadTestRule(t, src)
	if !rule.WantsMeta {
		t.Error("rule should have WantsMeta=true when check has 3 params")
	}

	eval := NewEvaluator([]*Rule{rule})

	// With meta: flagged.
	result, ruleID, _ := eval.EvaluateCommandWithMeta("sleep", []string{"30"}, false, &Metadata{ExpectedDurationSeconds: 5})
	if result == nil || result.Decision != "deny" {
		t.Fatalf("expected deny with meta, got %+v (rule=%q)", result, ruleID)
	}
	if ruleID != "uses-meta" {
		t.Errorf("rule id: got %q", ruleID)
	}

	// Without meta: silent.
	result, _, _ = eval.EvaluateCommand("sleep", []string{"30"}, false)
	if result != nil {
		t.Errorf("expected nil without meta, got %+v", result)
	}

	// Within-budget: silent.
	result, _, _ = eval.EvaluateCommandWithMeta("sleep", []string{"5"}, false, &Metadata{ExpectedDurationSeconds: 5})
	if result != nil {
		t.Errorf("expected nil when within budget, got %+v", result)
	}
}

func TestRule_TwoParamUnaffectedByMetadata(t *testing.T) {
	// Existing 2-param rules should continue working unchanged when
	// callers pass metadata; the rule simply never sees it.
	src := `
rule_id = "ignores-meta"
def check(command, args):
    if command == "rm":
        return {"decision": "deny", "reason": "no rm"}
    return None
tests = [{"command": "rm", "args": [], "expect": "deny"}]
`
	rule := loadTestRule(t, src)
	if rule.WantsMeta {
		t.Error("2-param rule should have WantsMeta=false")
	}

	eval := NewEvaluator([]*Rule{rule})

	result, _, _ := eval.EvaluateCommandWithMeta("rm", nil, false, &Metadata{
		TimeoutSeconds:          60,
		ExpectedDurationSeconds: 10,
	})
	if result == nil || result.Decision != "deny" {
		t.Errorf("2-param rule should still fire; got %+v", result)
	}
}

func TestMetaToStarlark_NilRendersEmptyDict(t *testing.T) {
	d := metaToStarlark(nil)
	if d == nil {
		t.Fatal("metaToStarlark(nil) returned nil; want empty dict")
	}
}
