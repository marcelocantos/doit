// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package starlark

import (
	"strings"
	"testing"
)

func TestGenerateBasicDenyRule(t *testing.T) {
	req := GenerateRequest{
		RuleID:        "deny-test-cmd",
		Description:   "Block test command",
		Bypassable:    true,
		Command:       "test",
		RejectFlags:   []string{"--bad", "-b"},
		Decision:      "deny",
		Justification: "test commands are dangerous",
		TestCases: []GenerateTestCase{
			{Command: "test", Args: []string{"--bad"}, Expect: "deny"},
			{Command: "test", Args: []string{"-b"}, Expect: "deny"},
			{Command: "test", Args: []string{"--good"}, Expect: "escalate"},
			{Command: "other", Args: []string{"--bad"}, Expect: "escalate"},
		},
	}

	src := Generate(req)

	// Verify generated source contains key elements.
	checks := []string{
		`rule_id = "deny-test-cmd"`,
		`description = "Block test command"`,
		`bypassable = True`,
		`def has_any_flag(args, flags):`,
		`def check(command, args):`,
		`if command != "test"`,
		`"--bad", "-b"`,
		`"decision": "deny"`,
		`tests = [`,
	}
	for _, c := range checks {
		if !strings.Contains(src, c) {
			t.Errorf("generated source missing %q\n\nFull source:\n%s", c, src)
		}
	}

	// Verify the generated rule actually loads and passes its tests.
	rule, err := LoadRuleFromSource("generated.star", src)
	if err != nil {
		t.Fatalf("generated rule failed to load: %v\n\nSource:\n%s", err, src)
	}
	if rule.ID != "deny-test-cmd" {
		t.Errorf("rule ID = %q, want deny-test-cmd", rule.ID)
	}
}

func TestGenerateSubcommandRule(t *testing.T) {
	req := GenerateRequest{
		RuleID:      "deny-git-push-force",
		Description: "Block force push",
		Command:     "git",
		Subcommand:  "push",
		RejectFlags: []string{"--force", "-f"},
		Decision:    "deny",
		TestCases: []GenerateTestCase{
			{Command: "git", Args: []string{"push", "--force"}, Expect: "deny"},
			{Command: "git", Args: []string{"push"}, Expect: "escalate"},
			{Command: "git", Args: []string{"pull", "--force"}, Expect: "escalate"},
		},
	}

	src := Generate(req)

	if !strings.Contains(src, `args[0] != "push"`) {
		t.Errorf("generated source missing subcommand check\n\nSource:\n%s", src)
	}

	// Verify the generated rule loads and passes tests.
	rule, err := LoadRuleFromSource("generated.star", src)
	if err != nil {
		t.Fatalf("generated rule failed to load: %v\n\nSource:\n%s", err, src)
	}
	if rule.ID != "deny-git-push-force" {
		t.Errorf("rule ID = %q, want deny-git-push-force", rule.ID)
	}
}

func TestGenerateNonBypassable(t *testing.T) {
	req := GenerateRequest{
		RuleID:      "deny-critical",
		Description: "Critical safety rule",
		Bypassable:  false,
		Command:     "danger",
		RejectFlags: []string{"--destroy"},
		Decision:    "deny",
		TestCases: []GenerateTestCase{
			{Command: "danger", Args: []string{"--destroy"}, Expect: "deny"},
			{Command: "danger", Args: []string{"--safe"}, Expect: "escalate"},
		},
	}

	src := Generate(req)
	if !strings.Contains(src, "bypassable = False") {
		t.Errorf("expected bypassable = False in output\n\nSource:\n%s", src)
	}

	rule, err := LoadRuleFromSource("generated.star", src)
	if err != nil {
		t.Fatalf("generated rule failed to load: %v", err)
	}
	if rule.Bypassable {
		t.Error("expected bypassable=false")
	}
}

func TestGeneratePathRejection(t *testing.T) {
	req := GenerateRequest{
		RuleID:      "deny-rm-root",
		Description: "Block rm on root paths",
		Command:     "rm",
		RejectPaths: []string{"/", ".", ".."},
		Decision:    "deny",
		TestCases: []GenerateTestCase{
			{Command: "rm", Args: []string{"/"}, Expect: "deny"},
			{Command: "rm", Args: []string{"."}, Expect: "deny"},
			{Command: "rm", Args: []string{".."}, Expect: "deny"},
			{Command: "rm", Args: []string{"foo"}, Expect: "escalate"},
			{Command: "ls", Args: []string{"/"}, Expect: "escalate"},
		},
	}

	src := Generate(req)
	rule, err := LoadRuleFromSource("generated.star", src)
	if err != nil {
		t.Fatalf("generated rule failed to load: %v\n\nSource:\n%s", err, src)
	}
	if rule.ID != "deny-rm-root" {
		t.Errorf("rule ID = %q, want deny-rm-root", rule.ID)
	}
}
