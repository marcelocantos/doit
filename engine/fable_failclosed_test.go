// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestExecute_FailsClosedOnEscalate reproduces Fable-5 finding F1 (🎯T40, the
// CRITICAL fail-open bug): with L3 disabled/nil, a command that no L1/L2 rule
// recognises resolves to Escalate, and Execute must NOT run it. Before the fix
// the Escalate fell through both guards straight to runCommand.
func TestExecute_FailsClosedOnEscalate(t *testing.T) {
	eng := newTestEngine(t) // level3_enabled:false => policyL3 and tokenStore nil
	dir := t.TempDir()
	marker := filepath.Join(dir, "PWNED")

	res := eng.Execute(context.Background(), Request{
		Command: "touch " + marker,
		Cwd:     dir,
	})

	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("fail-open: escalated command executed and created %s", marker)
	}
	if res.ExitCode == 0 {
		t.Errorf("expected non-zero exit for a fail-closed escalate, got %d", res.ExitCode)
	}
	if res.PolicyDecision == "allow" {
		t.Errorf("policy decision = allow; an escalate must not be reported as allow")
	}
}

// TestExecuteStreaming_FailsClosedOnEscalate is the streaming counterpart.
func TestExecuteStreaming_FailsClosedOnEscalate(t *testing.T) {
	eng := newTestEngine(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "PWNED")

	res := eng.ExecuteStreaming(context.Background(), Request{
		Command: "touch " + marker,
		Cwd:     dir,
	}, io.Discard, io.Discard)

	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("fail-open: escalated command executed and created %s", marker)
	}
	if res.ExitCode == 0 {
		t.Errorf("expected non-zero exit for a fail-closed escalate, got %d", res.ExitCode)
	}
}

// TestExecute_HumanRetryStillExecutes guards the fail-closed change against
// over-reach: a human-approved retry (req.Retry, set only by the elicitation
// accept path — never by agent MCP args) must still authorise execution even
// when L3 is disabled.
func TestExecute_HumanRetryStillExecutes(t *testing.T) {
	eng := newTestEngine(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "APPROVED")

	res := eng.Execute(context.Background(), Request{
		Command: "touch " + marker,
		Cwd:     dir,
		Retry:   true, // human approved via elicitation
	})

	if res.ExitCode != 0 {
		t.Fatalf("human-approved retry should execute, got exit %d, stderr=%q", res.ExitCode, res.Stderr)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("approved command did not run: %v", err)
	}
}

// TestExecute_RejectsSelfIssuedToken reproduces Fable-5 finding F3 (🎯T41):
// an engine-self-issued escalation token carries no human-approval provenance
// and must not be replayable via approved= to authorise the escalated command.
func TestExecute_RejectsSelfIssuedToken(t *testing.T) {
	eng := newTestEngineWithL3(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "SELF_APPROVED")
	args := []string{"touch", marker}

	// Simulate the engine's escalation self-issuance (engine.go:781 path).
	tok, err := eng.tokenStore.Issue("touch "+marker, args)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	res := eng.Execute(context.Background(), Request{
		Command:  "touch " + marker,
		Cwd:      dir,
		Approved: tok,
	})

	if res.PolicyDecision == "allow" {
		t.Errorf("self-issued token was accepted as allow — replay self-approval not blocked")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("self-issued token replay executed the command (created %s)", marker)
	}
}

// TestEvaluateDoesNotConsumeToken reproduces Fable-5 finding F2 (🎯T46): the
// Phase-1 dry-run Evaluate must not consume the single-use token, so the
// subsequent real Execute with the same token still succeeds.
func TestEvaluateDoesNotConsumeToken(t *testing.T) {
	eng := newTestEngineWithL3(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "OK")
	args := []string{"touch", marker}

	tok, err := eng.tokenStore.IssueApproved("touch "+marker, args)
	if err != nil {
		t.Fatalf("IssueApproved: %v", err)
	}

	// Dry-run first (mirrors handleExecute Phase 1).
	ev := eng.Evaluate(context.Background(), Request{Command: "touch " + marker, Cwd: dir, Approved: tok})
	if ev.Decision != "allow" {
		t.Fatalf("dry-run Evaluate: decision=%q reason=%q, want allow", ev.Decision, ev.Reason)
	}

	// Real execution must still see a valid token.
	res := eng.Execute(context.Background(), Request{Command: "touch " + marker, Cwd: dir, Approved: tok})
	if res.PolicyDecision != "allow" {
		t.Fatalf("Execute after dry-run: decision=%q reason=%q, want allow (token burned by dry-run?)", res.PolicyDecision, res.PolicyReason)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("approved command did not run: %v", err)
	}
}

// TestValidateApprovalDoesNotConsumeToken reproduces Fable-5 finding F8 (🎯T47):
// doit_approve (ValidateApproval) must not consume the token, so the subsequent
// Execute still authorises.
func TestValidateApprovalDoesNotConsumeToken(t *testing.T) {
	eng := newTestEngineWithL3(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "OK2")
	args := []string{"touch", marker}

	tok, err := eng.tokenStore.IssueApproved("touch "+marker, args)
	if err != nil {
		t.Fatalf("IssueApproved: %v", err)
	}

	if err := eng.ValidateApproval(tok, args); err != nil {
		t.Fatalf("ValidateApproval: %v", err)
	}

	res := eng.Execute(context.Background(), Request{Command: "touch " + marker, Cwd: dir, Approved: tok})
	if res.PolicyDecision != "allow" {
		t.Fatalf("Execute after ValidateApproval: decision=%q, want allow (token burned by validate?)", res.PolicyDecision)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("approved command did not run: %v", err)
	}
}
