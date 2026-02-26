package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewLogger(path)
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

	logger, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		_ = logger.Log("test", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false)
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

	logger, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		_ = logger.Log("test", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false)
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
	logger1, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = logger1.Log("first", []string{"cat"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false)
	_ = logger1.Log("second", []string{"grep"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false)

	// Create a new logger (simulating process restart).
	logger2, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = logger2.Log("third", []string{"head"}, []string{"read"}, 0, "", time.Millisecond, "/tmp", false)

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
