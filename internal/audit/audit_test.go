// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package audit

import (
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
		err := logger.Log(
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
		_ = logger.Log("test", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
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
		_ = logger.Log("test", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
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
	_ = logger1.Log("first", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
	_ = logger1.Log("second", []string{"grep"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)

	// Create a new logger (simulating process restart).
	logger2, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = logger2.Log("third", []string{"head"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)

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

	// Use a very small max size to trigger the limit quickly.
	// We set sizeCheckInterval to 1 implicitly by using a tiny limit and
	// writing enough entries that the check fires on the first interval.
	// Since sizeCheckInterval=100, we write 101 entries to trigger the check,
	// but that is expensive. Instead we write 1 entry, then manually stat the
	// file after writes to confirm the limit was enforced. We use a max of 1
	// byte so even the first real check sees it exceeded.
	logger, err := NewLogger(path, 1) // 1 byte max
	if err != nil {
		t.Fatal(err)
	}

	// Write 100 entries to hit the first size check at writesSince==100.
	for i := 0; i < sizeCheckInterval; i++ {
		_ = logger.Log("test", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
	}

	// Get file size after 100 writes (before the size check fires).
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sizeAfter100 := info.Size()

	// Write one more entry — this triggers the size check (writesSince resets),
	// which should set sizeLimitHit=true for future writes.
	_ = logger.Log("trigger", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)

	// Further writes should be skipped.
	_ = logger.Log("skipped", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
	_ = logger.Log("skipped2", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)

	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// File should not have grown significantly after the limit was hit.
	// (One trigger entry may have been written before sizeLimitHit was set.)
	if infoAfter.Size() > sizeAfter100+4096 {
		t.Errorf("file grew unexpectedly after size limit: %d -> %d", sizeAfter100, infoAfter.Size())
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
		_ = logger.Log("test", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)
	}

	// Inject a malformed line.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{not valid json}\n")
	f.Close()

	// Write one more valid entry.
	_ = logger.Log("after", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false, nil)

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
