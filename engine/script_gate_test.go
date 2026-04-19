// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marcelocantos/doit/internal/script"
)

// newTestEngineForScriptGate returns an engine with an isolated script
// approval store so tests don't touch the user's real config.
func newTestEngineForScriptGate(t *testing.T) (*Engine, string) {
	t.Helper()
	eng := newTestEngine(t)

	// Redirect the script approval store into the test tempdir.
	storeDir := t.TempDir()
	storePath := filepath.Join(storeDir, "script-approvals.yaml")
	eng.scriptStore = script.NewStore(storePath)
	return eng, storePath
}

func writeShellScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestScriptGate_EvaluateEscalatesOnFirstEncounter(t *testing.T) {
	eng, _ := newTestEngineForScriptGate(t)
	dir := t.TempDir()
	writeShellScript(t, dir, "first.sh", "#!/bin/bash\necho hi\n")

	result := eng.Evaluate(context.Background(), Request{
		Command: "bash first.sh",
		Cwd:     dir,
	})
	if result.Decision != "escalate" {
		t.Fatalf("expected escalate, got %s: %s", result.Decision, result.Reason)
	}
	if result.RuleID != "script-hash-pending" {
		t.Errorf("RuleID: got %q, want script-hash-pending", result.RuleID)
	}
	if result.ScriptApproval == nil {
		t.Fatal("expected ScriptApproval to be set")
	}
	if result.ScriptApproval.Interpreter != "bash" {
		t.Errorf("Interpreter: got %q", result.ScriptApproval.Interpreter)
	}
	if !contains(result.ScriptApproval.ContentHash, "sha256:") {
		t.Errorf("ContentHash should be sha256-prefixed, got %q", result.ScriptApproval.ContentHash)
	}
	if result.ScriptApproval.ContentPreview == "" {
		t.Error("expected a non-empty preview")
	}
	if !result.Bypassable {
		t.Error("expected Bypassable=true on script-hash escalation")
	}
}

func TestScriptGate_ApprovalPersistsAndBypassesPolicy(t *testing.T) {
	eng, _ := newTestEngineForScriptGate(t)
	dir := t.TempDir()
	writeShellScript(t, dir, "approved.sh", "#!/bin/bash\nexit 0\n")

	// First evaluation — should escalate.
	first := eng.Evaluate(context.Background(), Request{
		Command: "bash approved.sh",
		Cwd:     dir,
	})
	if first.ScriptApproval == nil {
		t.Fatal("expected ScriptApproval on first encounter")
	}
	hash := first.ScriptApproval.ContentHash

	// User approves.
	if _, err := eng.ApproveScript(hash, first.ScriptApproval.Path, "test"); err != nil {
		t.Fatalf("ApproveScript: %v", err)
	}

	// Second evaluation — should allow with script-hash-approved.
	second := eng.Evaluate(context.Background(), Request{
		Command: "bash approved.sh",
		Cwd:     dir,
	})
	if second.Decision != "allow" {
		t.Fatalf("expected allow after approval, got %s: %s", second.Decision, second.Reason)
	}
	if second.RuleID != "script-hash-approved" {
		t.Errorf("RuleID: got %q, want script-hash-approved", second.RuleID)
	}
	if second.ScriptApproval != nil {
		t.Error("ScriptApproval should be nil when the hash is already approved")
	}
}

func TestScriptGate_MutationForcesReapproval(t *testing.T) {
	eng, _ := newTestEngineForScriptGate(t)
	dir := t.TempDir()
	path := writeShellScript(t, dir, "mut.sh", "#!/bin/bash\necho v1\n")

	first := eng.Evaluate(context.Background(), Request{Command: "bash mut.sh", Cwd: dir})
	if _, err := eng.ApproveScript(first.ScriptApproval.ContentHash, path, ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Modify the script.
	if err := os.WriteFile(path, []byte("#!/bin/bash\necho v2\n"), 0755); err != nil {
		t.Fatalf("write: %v", err)
	}

	mutated := eng.Evaluate(context.Background(), Request{Command: "bash mut.sh", Cwd: dir})
	if mutated.Decision != "escalate" {
		t.Fatalf("expected re-escalation after modification, got %s", mutated.Decision)
	}
	if mutated.ScriptApproval == nil {
		t.Fatal("expected ScriptApproval after modification")
	}
	if mutated.ScriptApproval.ContentHash == first.ScriptApproval.ContentHash {
		t.Error("hash did not change after modification")
	}
}

func TestScriptGate_ExecuteRunsApprovedScript(t *testing.T) {
	eng, _ := newTestEngineForScriptGate(t)
	dir := t.TempDir()
	path := writeShellScript(t, dir, "run.sh", "#!/bin/bash\necho approved-output\n")

	eval := eng.Evaluate(context.Background(), Request{Command: "bash run.sh", Cwd: dir})
	if _, err := eng.ApproveScript(eval.ScriptApproval.ContentHash, path, ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	res := eng.Execute(context.Background(), Request{Command: "bash run.sh", Cwd: dir})
	if res.ExitCode != 0 {
		t.Fatalf("exit code: got %d, stderr=%q", res.ExitCode, res.Stderr)
	}
	if !contains(res.Stdout, "approved-output") {
		t.Errorf("stdout: got %q", res.Stdout)
	}
	if res.PolicyRuleID != "script-hash-matched" {
		t.Errorf("RuleID: got %q, want script-hash-matched", res.PolicyRuleID)
	}
}

func TestScriptGate_ExecuteBlocksUnapproved(t *testing.T) {
	eng, _ := newTestEngineForScriptGate(t)
	dir := t.TempDir()
	writeShellScript(t, dir, "block.sh", "#!/bin/bash\necho should-not-run\n")

	res := eng.Execute(context.Background(), Request{Command: "bash block.sh", Cwd: dir})
	if res.ExitCode == 0 {
		t.Fatal("expected non-zero exit for unapproved script")
	}
	if res.PolicyDecision != "escalate" {
		t.Errorf("PolicyDecision: got %q, want escalate", res.PolicyDecision)
	}
	if res.PolicyRuleID != "script-hash-pending" {
		t.Errorf("RuleID: got %q", res.PolicyRuleID)
	}
	if contains(res.Stdout, "should-not-run") {
		t.Error("script ran despite not being approved")
	}
}

func TestScriptGate_Revocation(t *testing.T) {
	eng, _ := newTestEngineForScriptGate(t)
	dir := t.TempDir()
	path := writeShellScript(t, dir, "rev.sh", "#!/bin/bash\necho x\n")

	eval := eng.Evaluate(context.Background(), Request{Command: "bash rev.sh", Cwd: dir})
	hash := eval.ScriptApproval.ContentHash
	if _, err := eng.ApproveScript(hash, path, ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Approved → allow.
	if r := eng.Evaluate(context.Background(), Request{Command: "bash rev.sh", Cwd: dir}); r.Decision != "allow" {
		t.Fatalf("pre-revoke: expected allow, got %s", r.Decision)
	}

	if err := eng.RevokeScriptApproval(hash); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Revoked → escalate again.
	if r := eng.Evaluate(context.Background(), Request{Command: "bash rev.sh", Cwd: dir}); r.Decision != "escalate" {
		t.Fatalf("post-revoke: expected escalate, got %s", r.Decision)
	}
}

func TestScriptGate_DoesNotApplyToNormalCommands(t *testing.T) {
	eng, _ := newTestEngineForScriptGate(t)

	// A non-script command should not be affected by the gate.
	result := eng.Evaluate(context.Background(), Request{
		Command: "cat foo.txt",
	})
	// Not allow, but more importantly not script-hash-pending.
	if result.RuleID == "script-hash-pending" || result.RuleID == "script-hash-approved" {
		t.Errorf("non-script command should not be gated, got RuleID=%q", result.RuleID)
	}
	if result.ScriptApproval != nil {
		t.Error("non-script command should not carry ScriptApproval")
	}
}

func TestScriptGate_PipelinesFallThrough(t *testing.T) {
	eng, _ := newTestEngineForScriptGate(t)
	dir := t.TempDir()
	writeShellScript(t, dir, "pipe.sh", "#!/bin/bash\necho x\n")

	// Piped commands are not gated — they fall through to normal policy.
	result := eng.Evaluate(context.Background(), Request{
		Command: "bash pipe.sh | cat",
		Cwd:     dir,
	})
	if result.RuleID == "script-hash-pending" {
		t.Error("pipelines should not trigger the script-hash gate")
	}
}

func TestScriptGate_ListAndRevoke(t *testing.T) {
	eng, _ := newTestEngineForScriptGate(t)
	if _, err := eng.ApproveScript("sha256:a", "/one.sh", ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := eng.ApproveScript("sha256:b", "/two.sh", ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	list, err := eng.ListScriptApprovals()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("list size: got %d, want 2", len(list))
	}

	if err := eng.RevokeScriptApproval("sha256:a"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	list, _ = eng.ListScriptApprovals()
	if len(list) != 1 {
		t.Errorf("list after revoke: got %d, want 1", len(list))
	}
}

func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
