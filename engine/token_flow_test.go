// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"strings"
	"testing"
)

// issueAndApprove escalates a command through the mock L3 and applies
// the human approval step a library consumer performs after its own UI
// confirmation.
func issueAndApprove(t *testing.T, eng *Engine, command string) string {
	t.Helper()
	res := eng.Execute(context.Background(), Request{Command: command})
	if res.EscalateToken == "" {
		t.Fatalf("expected escalation token, got %+v", res)
	}
	if err := eng.ApproveToken(res.EscalateToken); err != nil {
		t.Fatalf("ApproveToken: %v", err)
	}
	return res.EscalateToken
}

// TestEvaluateDoesNotConsumeToken is the 🎯T46 regression: the dry-run
// Evaluate that precedes every MCP execute must not burn the token.
func TestEvaluateDoesNotConsumeToken(t *testing.T) {
	eng := newTestEngineWithEscalatingL3(t)
	token := issueAndApprove(t, eng, "echo approved-flow")

	eval := eng.Evaluate(context.Background(), Request{Command: "echo approved-flow", Approved: token})
	if eval.Decision != "allow" {
		t.Fatalf("Evaluate with approved token: got %s (%s)", eval.Decision, eval.Reason)
	}
	res := eng.Execute(context.Background(), Request{Command: "echo approved-flow", Approved: token})
	if res.PolicyDecision != "allow" || res.ExitCode != 0 || !strings.Contains(res.Stdout, "approved-flow") {
		t.Fatalf("Execute after Evaluate should run on the same token, got %+v", res)
	}

	// The token is single-use on the real execute path.
	again := eng.Execute(context.Background(), Request{Command: "echo approved-flow", Approved: token})
	if again.PolicyDecision != "deny" {
		t.Fatalf("token should be consumed by Execute, got %+v", again)
	}
}

// TestValidateApprovalDoesNotConsumeToken is the 🎯T47 regression:
// doit_approve's check leaves the token intact for the execute.
func TestValidateApprovalDoesNotConsumeToken(t *testing.T) {
	eng := newTestEngineWithEscalatingL3(t)
	token := issueAndApprove(t, eng, "echo approve-then-execute")
	args := []string{"echo", "approve-then-execute"}

	if err := eng.ValidateApproval(token, args); err != nil {
		t.Fatalf("ValidateApproval: %v", err)
	}
	res := eng.Execute(context.Background(), Request{Command: "echo approve-then-execute", Approved: token})
	if res.PolicyDecision != "allow" || res.ExitCode != 0 {
		t.Fatalf("Execute after ValidateApproval should run, got %+v", res)
	}
}

// TestValidateApprovalReportsPendingToken: a token nobody has approved
// validates as pending, not as authorised.
func TestValidateApprovalReportsPendingToken(t *testing.T) {
	eng := newTestEngineWithEscalatingL3(t)
	res := eng.Execute(context.Background(), Request{Command: "echo pending"})
	err := eng.ValidateApproval(res.EscalateToken, []string{"echo", "pending"})
	if err == nil || !strings.Contains(err.Error(), "human") {
		t.Fatalf("expected pending-approval error, got %v", err)
	}
}
