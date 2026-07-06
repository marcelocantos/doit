// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestVerify_ShortHashDoesNotPanic reproduces Fable-5 finding F5 (🎯T42):
// Verify slices PrevHash[:16]/Hash[:16] on untrusted entries, so a tampered
// line with a short/empty hash triggers a slice-out-of-range panic that
// crashes the verifier instead of reporting the tamper.
func TestVerify_ShortHashDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// One valid, genesis-chained entry (seq 1).
	l, err := NewLogger(path, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if _, err := l.Log("echo hi", nil, nil, 0, "", 0, "", false, nil); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// Append a tampered line whose prev_hash is a short string. It passes the
	// sequence check (seq 2 == prevSeq 1 + 1) and then hits the prev_hash
	// mismatch branch, where PrevHash[:16] panics for len<16.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.WriteString(`{"seq":2,"prev_hash":"x","hash":"","ts":"2026-07-05T00:00:00Z"}` + "\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	// Before the fix this panics; guard so the failure is a clear test
	// failure rather than a crash that aborts the whole package run.
	err = verifyNoPanic(t, path)
	if err == nil {
		t.Fatal("Verify: expected a non-nil tamper error for the short-hash line, got nil")
	}
}

func verifyNoPanic(t *testing.T, path string) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked on a tampered short-hash entry (should report tamper): %v", r)
		}
	}()
	return Verify(path)
}

// TestLogger_WriteFailureKeepsChainGapFree reproduces Fable-5 finding F4
// (🎯T43): Log advances l.seq and l.prevHash before the file write and never
// rolls back on failure, so a transient write error leaves in-memory state
// ahead of disk and permanently forks/gaps the on-disk chain.
func TestLogger_WriteFailureKeepsChainGapFree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("cannot make a file unwritable as root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := NewLogger(path, 0)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	// Two good entries (seq 1, 2).
	for i := 0; i < 2; i++ {
		if _, err := l.Log("echo ok", nil, nil, 0, "", 0, "", false, nil); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	// Force the next write to fail by making the file unwritable.
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatalf("chmod ro: %v", err)
	}
	if _, err := l.Log("echo fails", nil, nil, 0, "", 0, "", false, nil); err == nil {
		t.Skip("write unexpectedly succeeded on a 0400 file; cannot exercise the failure path here")
	}

	// Recover writability and log again.
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatalf("chmod rw: %v", err)
	}
	if _, err := l.Log("echo again", nil, nil, 0, "", 0, "", false, nil); err != nil {
		t.Fatalf("Log after recovery: %v", err)
	}

	// The failed write must not have advanced the chain: Verify must accept
	// the on-disk log with no sequence gap or orphaned prev_hash.
	if err := Verify(path); err != nil {
		t.Fatalf("Verify: chain broken by a failed write that advanced in-memory state: %v", err)
	}
}
