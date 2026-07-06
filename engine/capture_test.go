// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/marcelocantos/doit/internal/audit"
	"github.com/marcelocantos/doit/internal/cap"
)

// lastAuditEntry reads the final JSON line from the audit log at path.
func lastAuditEntry(t *testing.T, path string) audit.Entry {
	t.Helper()
	entries, err := audit.Tail(path, 1)
	if err != nil {
		t.Fatalf("audit.Tail: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("audit log has no entries")
	}
	return entries[0]
}

func newTestEngineWithCapture(t *testing.T, auditExtra string) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	base := "tiers:\n  read: true\n  build: true\n  write: true\n  dangerous: true\n" +
		"audit:\n  path: " + auditPath + "\n" +
		auditExtra +
		"policy:\n  level1_enabled: true\n  level2_enabled: false\n  level3_enabled: false\n"
	os.WriteFile(cfgPath, []byte(base), 0600)
	eng, err := New(Options{ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("newTestEngineWithCapture: %v", err)
	}
	return eng, auditPath
}

// TestCapture_DefaultNoExcerptOnSuccess verifies that a successful command
// with default config ("on_failure") produces no excerpt fields.
func TestCapture_DefaultNoExcerptOnSuccess(t *testing.T) {
	eng, auditPath := newTestEngineWithCapture(t, "")

	result := eng.Execute(context.Background(), Request{
		Command: "echo hello",
		Retry:   true, // human-approved: reach execution under fail-closed policy
	})
	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d: %s", result.ExitCode, result.Stderr)
	}

	entry := lastAuditEntry(t, auditPath)
	if entry.StdoutExcerpt != "" {
		t.Errorf("StdoutExcerpt should be empty for successful command with on_failure, got %q", entry.StdoutExcerpt)
	}
	if entry.StderrExcerpt != "" {
		t.Errorf("StderrExcerpt should be empty for successful command with on_failure, got %q", entry.StderrExcerpt)
	}
}

// TestCapture_FailedCommandProducesExcerpts verifies that a failed command
// with default config produces non-empty excerpts within the size cap.
func TestCapture_FailedCommandProducesExcerpts(t *testing.T) {
	eng, auditPath := newTestEngineWithCapture(t, "")

	result := eng.Execute(context.Background(), Request{
		Command: "echo 'fail output' >&2; exit 1",
		Retry:   true, // human-approved
	})
	if result.ExitCode == 0 {
		t.Fatal("expected non-zero exit code")
	}

	entry := lastAuditEntry(t, auditPath)
	if !strings.Contains(entry.StderrExcerpt, "fail output") {
		t.Errorf("StderrExcerpt should contain 'fail output', got %q", entry.StderrExcerpt)
	}
}

// TestCapture_TruncationMarker verifies that output exceeding the cap is
// truncated with the marker recording the original byte count.
func TestCapture_TruncationMarker(t *testing.T) {
	eng, auditPath := newTestEngineWithCapture(t,
		"  capture_output: always\n  output_excerpt_bytes: 10\n")

	// Generate output larger than 10 bytes (echo adds newline, so "123456789012" = 13 bytes).
	result := eng.Execute(context.Background(), Request{
		Command: "echo '123456789012'",
		Retry:   true, // human-approved
	})
	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d: %s", result.ExitCode, result.Stderr)
	}

	entry := lastAuditEntry(t, auditPath)
	if !strings.Contains(entry.StdoutExcerpt, "\n[\u2026truncated, total") {
		t.Errorf("expected truncation marker in StdoutExcerpt, got %q", entry.StdoutExcerpt)
	}
	// The excerpt before the marker must be at most 10 bytes.
	markerIdx := strings.Index(entry.StdoutExcerpt, "\n[\u2026truncated")
	if markerIdx < 0 {
		t.Fatal("no truncation marker found")
	}
	if markerIdx > 10 {
		t.Errorf("excerpt before marker is %d bytes, want <= 10", markerIdx)
	}
}

// TestCapture_AlwaysCapturesSuccess verifies that capture_output: always
// captures output even for successful commands.
func TestCapture_AlwaysCapturesSuccess(t *testing.T) {
	eng, auditPath := newTestEngineWithCapture(t,
		"  capture_output: always\n")

	result := eng.Execute(context.Background(), Request{
		Command: "echo hello_world",
		Retry:   true, // human-approved
	})
	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d: %s", result.ExitCode, result.Stderr)
	}

	entry := lastAuditEntry(t, auditPath)
	if !strings.Contains(entry.StdoutExcerpt, "hello_world") {
		t.Errorf("StdoutExcerpt should contain 'hello_world' with always, got %q", entry.StdoutExcerpt)
	}
}

// TestCapture_NeverCapturesNothing verifies that capture_output: never
// produces no excerpt fields regardless of exit code.
func TestCapture_NeverCapturesNothing(t *testing.T) {
	eng, auditPath := newTestEngineWithCapture(t,
		"  capture_output: never\n")

	// Fail to confirm even failures produce no excerpts.
	eng.Execute(context.Background(), Request{
		Command: "echo fail_output; exit 2",
		Retry:   true, // human-approved
	})

	entry := lastAuditEntry(t, auditPath)
	if entry.StdoutExcerpt != "" {
		t.Errorf("StdoutExcerpt should be empty with never, got %q", entry.StdoutExcerpt)
	}
	if entry.StderrExcerpt != "" {
		t.Errorf("StderrExcerpt should be empty with never, got %q", entry.StderrExcerpt)
	}
}

// TestCapture_TruncationUTF8Safe verifies that the truncation point lands
// on a valid rune boundary and does not produce invalid UTF-8.
func TestCapture_TruncationUTF8Safe(t *testing.T) {
	cw := &captureWriter{cap: 5}
	// "αβγδ" encodes to 8 bytes (2 bytes each in UTF-8).
	// Cap at 5 cuts "γ" (bytes 4–5) in half.
	cw.Write([]byte("αβγδ"))

	excerpt := cw.excerpt()
	// Strip the truncation marker for the validity check.
	prefix := excerpt
	if idx := strings.Index(excerpt, "\n["); idx >= 0 {
		prefix = excerpt[:idx]
	}
	if !utf8.ValidString(prefix) {
		t.Errorf("excerpt prefix is not valid UTF-8: %q", prefix)
	}
}

// TestCapture_RedactedCapability verifies that a registered capability with
// RedactOutput() = true produces the redaction marker in audit excerpts.
func TestCapture_RedactedCapability(t *testing.T) {
	eng, auditPath := newTestEngineWithCapture(t,
		"  capture_output: on_failure\n")
	eng.reg.Register(&mockRedactCap{})

	// Run a command that will fail; mock-redact is the first token so lookup
	// will find it and return RedactOutput()=true. The shell will fail to find
	// "mock-redact" but exit non-zero, triggering the failure path.
	eng.Execute(context.Background(), Request{
		Command: "mock-redact some-arg",
		Retry:   true, // human-approved
	})

	entry := lastAuditEntry(t, auditPath)
	// With RedactOutput=true, excerpts must be the redaction marker (not actual output).
	if entry.StdoutExcerpt != redactedMarker && entry.StderrExcerpt != redactedMarker {
		// If both are empty that also means no actual output leaked.
		// Accept empty OR redacted marker.
		if entry.StdoutExcerpt != "" && entry.StdoutExcerpt != redactedMarker {
			t.Errorf("StdoutExcerpt should be redacted marker or empty, got %q", entry.StdoutExcerpt)
		}
		if entry.StderrExcerpt != "" && entry.StderrExcerpt != redactedMarker {
			t.Errorf("StderrExcerpt should be redacted marker or empty, got %q", entry.StderrExcerpt)
		}
	}
	// Run with always mode to ensure the marker appears.
	eng2, auditPath2 := newTestEngineWithCapture(t,
		"  capture_output: always\n")
	eng2.reg.Register(&mockRedactCap{})
	eng2.Execute(context.Background(), Request{
		Command: "mock-redact some-arg",
		Retry:   true, // human-approved
	})
	entry2 := lastAuditEntry(t, auditPath2)
	if entry2.StdoutExcerpt != redactedMarker {
		t.Errorf("StdoutExcerpt: want redacted marker, got %q", entry2.StdoutExcerpt)
	}
	if entry2.StderrExcerpt != redactedMarker {
		t.Errorf("StderrExcerpt: want redacted marker, got %q", entry2.StderrExcerpt)
	}
}

// mockRedactCap is a capability with RedactOutput()=true for testing.
type mockRedactCap struct{}

var _ cap.Capability = (*mockRedactCap)(nil)

func (m *mockRedactCap) Name() string              { return "mock-redact" }
func (m *mockRedactCap) Description() string       { return "mock redact cap for testing" }
func (m *mockRedactCap) Tier() cap.Tier            { return cap.TierRead }
func (m *mockRedactCap) Validate([]string) error   { return nil }
func (m *mockRedactCap) RedactOutput() bool        { return true }
