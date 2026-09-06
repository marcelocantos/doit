// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marcelocantos/doit/internal/policy"
)

// newTestEngineWithEscalatingL3 wires a mock L3 that always escalates,
// which is the only path that mints approval tokens.
func newTestEngineWithEscalatingL3(t *testing.T) *Engine {
	t.Helper()
	eng := newTestEngine(t)
	mock := &mockSessionPrompter{response: `{"decision":"escalate","reasoning":"needs a human"}`}
	eng.policyL3 = policy.NewLevel3(mock)
	eng.tokenStore = policy.NewTokenStore(5 * time.Minute)
	return eng
}

// TestExecute_SelfIssuedTokenCannotApprove is the 🎯T41 regression: the
// token the engine hands back on an L3 escalation is a receipt, not a
// capability. Replaying it through Execute must not run the command.
func TestExecute_SelfIssuedTokenCannotApprove(t *testing.T) {
	eng := newTestEngineWithEscalatingL3(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "MARKER")

	first := eng.Execute(context.Background(), Request{Command: "touch MARKER", Cwd: dir})
	if first.EscalateToken == "" {
		t.Fatalf("expected an escalation token, got %+v", first)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("escalated command ran")
	}

	for attempt := 1; attempt <= 2; attempt++ {
		replay := eng.Execute(context.Background(), Request{
			Command:  "touch MARKER",
			Cwd:      dir,
			Approved: first.EscalateToken,
		})
		if replay.PolicyDecision != "deny" || replay.ExitCode == 0 {
			t.Fatalf("attempt %d: self-issued token was honoured: %+v", attempt, replay)
		}
		if !strings.Contains(replay.PolicyReason, "human") {
			t.Errorf("attempt %d: reason should say the token lacks human approval, got %q", attempt, replay.PolicyReason)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("attempt %d: command ran on a self-issued token", attempt)
		}
	}
}
