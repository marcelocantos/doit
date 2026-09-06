// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Write several entries.
	for i := 0; i < 5; i++ {
		_, err := logger.Log(
			"test pipeline",
			[]string{"grep", "head"},
			[]string{"read", "read"},
			0, "",
			time.Duration(i)*time.Millisecond,
			"/tmp",
			false,
			nil,
		)
		if err != nil {
			t.Fatalf("log entry %d: %v", i, err)
		}
	}

	// Verify the chain.
	if err := Verify(path); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		_, _ = logger.Log("test", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
	}

	// Tamper with the file: modify a byte in the middle.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Find and modify a character in the middle of the file.
	mid := len(data) / 2
	if data[mid] == 'a' {
		data[mid] = 'b'
	} else {
		data[mid] = 'a'
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	if err := Verify(path); err == nil {
		t.Fatal("expected verify to detect tampering")
	}
}

func TestVerifyDetectsSequenceGap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		_, _ = logger.Log("test", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
	}

	// Delete the middle line (line 3 of 5).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(data)
	// Remove line at index 2.
	remaining := append(lines[:2], lines[3:]...)
	var newData []byte
	for _, line := range remaining {
		newData = append(newData, line...)
		newData = append(newData, '\n')
	}
	if err := os.WriteFile(path, newData, 0600); err != nil {
		t.Fatal(err)
	}

	if err := Verify(path); err == nil {
		t.Fatal("expected verify to detect sequence gap")
	}
}

func TestVerifyEmptyLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	if err := Verify(path); err != nil {
		t.Fatalf("empty log should be valid: %v", err)
	}
}

func TestLoggerResumesChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Write some entries.
	logger1, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = logger1.Log("first", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
	_, _ = logger1.Log("second", []string{"grep"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)

	// Create a new logger (simulating process restart).
	logger2, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = logger2.Log("third", []string{"head"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)

	// The chain should still be valid.
	if err := Verify(path); err != nil {
		t.Fatalf("chain should be valid after restart: %v", err)
	}

	// Check sequence continuity.
	entries, err := Tail(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[2].Seq != 3 {
		t.Errorf("expected seq 3, got %d", entries[2].Seq)
	}
}

func TestLoggerSizeLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// 1-byte limit: the size check fires on the sizeCheckInterval-th write,
	// sees the file over the limit, and every Log from then on must refuse
	// loudly with ErrAuditFull rather than returning (0, nil) (🎯T43).
	logger, err := NewLogger(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < sizeCheckInterval-1; i++ {
		if _, err := logger.Log("test", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sizeAtLimit := info.Size()

	if _, err := logger.Log("over-limit", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil); !errors.Is(err, ErrAuditFull) {
		t.Fatalf("expected ErrAuditFull once the limit is hit, got %v", err)
	}
	if _, err := logger.Log("over-limit-2", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil); !errors.Is(err, ErrAuditFull) {
		t.Fatalf("expected ErrAuditFull to persist, got %v", err)
	}
	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if infoAfter.Size() != sizeAtLimit {
		t.Errorf("file grew after size limit: %d -> %d", sizeAtLimit, infoAfter.Size())
	}

	// Rotation (operator truncates or moves the file aside) must let
	// logging resume instead of latching the refusal forever.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	logger.maxSizeBytes = 1 << 20
	if _, err := logger.Log("after-rotation", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil); err != nil {
		t.Fatalf("expected logging to resume after rotation, got %v", err)
	}
}

// TestLogFailedWriteDoesNotAdvanceChain is the 🎯T43 regression: a write
// that fails must leave seq/prev_hash untouched so the next successful
// write continues the on-disk chain without a gap.
func TestLogFailedWriteDoesNotAdvanceChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logger.Log("first", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil); err != nil {
		t.Fatal(err)
	}

	// Make the file unwritable so the next append fails.
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := logger.Log("lost", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil); err == nil {
		t.Skip("append to a 0400 file succeeded (running as root?); cannot exercise the failed-write path")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	seq, err := logger.Log("second", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 2 {
		t.Errorf("seq after failed write: got %d, want 2 (no gap)", seq)
	}
	if err := Verify(path); err != nil {
		t.Fatalf("chain should verify after a failed then successful write: %v", err)
	}
}

// TestNewLoggerCorruptTailResumesFromLastParseable: a torn final line
// (crash mid-write) must not silently reset the chain to genesis.
func TestNewLoggerCorruptTailResumesFromLastParseable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger1, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"first", "second"} {
		if _, err := logger1.Log(cmd, []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"seq":3,"time":"2026-01-01T00:00:00Z","prev_ha`) // torn line, no newline
	f.Close()

	logger2, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	seq, err := logger2.Log("third", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 3 {
		t.Errorf("seq after corrupt tail: got %d, want 3", seq)
	}
	entries, _ := Tail(path, 10) // Tail reports the skipped torn line as an error
	if len(entries) != 3 || entries[2].PrevHash != entries[1].Hash {
		t.Errorf("chain did not resume from the last parseable entry: %+v", entries)
	}
}

func TestTailMalformedEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Write 3 valid entries.
	for i := 0; i < 3; i++ {
		_, _ = logger.Log("test", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
	}

	// Inject a malformed line.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{not valid json}\n")
	f.Close()

	// Write one more valid entry.
	_, _ = logger.Log("after", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)

	entries, err := Tail(path, 10)
	if err == nil {
		t.Fatal("expected non-nil error for malformed entries, got nil")
	}
	if !strings.Contains(err.Error(), "skipped") {
		t.Errorf("expected 'skipped' in error, got: %v", err)
	}
	// Should still return the valid entries.
	if len(entries) != 4 {
		t.Errorf("expected 4 valid entries, got %d", len(entries))
	}
}

func TestLogReturnsSeq(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	seq1, err := logger.Log("cmd1", nil, nil, 0, "", time.Millisecond, "/tmp", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	seq2, err := logger.Log("cmd2", nil, nil, 0, "", time.Millisecond, "/tmp", false, nil)
	if err != nil {
		t.Fatal(err)
	}

	if seq1 != 1 {
		t.Errorf("expected seq1=1, got %d", seq1)
	}
	if seq2 != 2 {
		t.Errorf("expected seq2=2, got %d", seq2)
	}
}

func TestElicitationFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Write a command entry and capture its seq.
	cmdSeq, err := logger.Log("git push", []string{"git"}, []string{"write"}, 0, "", time.Millisecond, "/tmp", false, &LogOptions{
		PolicyLevel:  3,
		PolicyResult: "escalate",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Write a Phase 1 elicitation entry linking back to the command.
	elicSeq, err := logger.Log("<elicitation>", nil, nil, 0, "", 0, "", false, &LogOptions{
		PolicyResult:         "allow_once",
		ParentSeq:            cmdSeq,
		ElicitationPrompt:    "Policy escalate for command: git push",
		ElicitationChoice:    "allow_once",
		ElicitationLatencyMs: 1234.5,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Write a Phase 2 promotion entry.
	_, err = logger.Log("<elicitation-promotion>", nil, nil, 0, "", 0, "", false, &LogOptions{
		PolicyResult:           "proposal_accepted",
		ParentSeq:              cmdSeq,
		ElicitationPrompt:      "Would you like a permanent rule?",
		ElicitationChoice:      "proposal_accepted",
		ProposedRuleSource:     "def check(cmd, args): return allow()",
		ProposedRuleGenerality: "narrow",
		ProposedRuleID:         "allow-git-push-42",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the chain is valid (hash chain covers all new fields).
	if err := Verify(path); err != nil {
		t.Fatalf("chain verify failed: %v", err)
	}

	entries, err := Tail(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	cmd := entries[0]
	elicit := entries[1]
	promotion := entries[2]

	// Command entry has no elicitation fields.
	if cmd.ParentSeq != 0 {
		t.Errorf("command entry should have no parent_seq, got %d", cmd.ParentSeq)
	}
	if cmd.ElicitationChoice != "" {
		t.Errorf("command entry should have no elicitation_choice, got %q", cmd.ElicitationChoice)
	}

	// Phase 1 elicitation entry links back to command.
	if elicit.ParentSeq != cmdSeq {
		t.Errorf("elicitation parent_seq=%d, want %d", elicit.ParentSeq, cmdSeq)
	}
	if elicit.ElicitationChoice != "allow_once" {
		t.Errorf("elicitation_choice=%q, want allow_once", elicit.ElicitationChoice)
	}
	if elicit.ElicitationLatencyMs != 1234.5 {
		t.Errorf("elicitation_latency_ms=%f, want 1234.5", elicit.ElicitationLatencyMs)
	}
	if elicit.ElicitationPrompt == "" {
		t.Error("elicitation_prompt should not be empty")
	}
	if elicit.PolicyResult != "allow_once" {
		t.Errorf("policy_result=%q, want allow_once", elicit.PolicyResult)
	}
	if elicit.Seq != elicSeq {
		t.Errorf("elicitation seq=%d, want %d", elicit.Seq, elicSeq)
	}

	// Phase 2 promotion entry.
	if promotion.ParentSeq != cmdSeq {
		t.Errorf("promotion parent_seq=%d, want %d", promotion.ParentSeq, cmdSeq)
	}
	if promotion.ProposedRuleSource == "" {
		t.Error("proposed_rule_source should not be empty")
	}
	if promotion.ProposedRuleGenerality != "narrow" {
		t.Errorf("proposed_rule_generality=%q, want narrow", promotion.ProposedRuleGenerality)
	}
	if promotion.ProposedRuleID != "allow-git-push-42" {
		t.Errorf("proposed_rule_id=%q, want allow-git-push-42", promotion.ProposedRuleID)
	}
	if promotion.PolicyResult != "proposal_accepted" {
		t.Errorf("policy_result=%q, want proposal_accepted", promotion.PolicyResult)
	}
}
