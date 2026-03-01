package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func seedTestLog(t *testing.T) (string, *Logger) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}

	opts := func(level int, result string) *LogOptions {
		return &LogOptions{PolicyLevel: level, PolicyResult: result}
	}

	// Entry 1: L1 allow, cap=go
	if err := logger.Log("go build ./...", []string{"go"}, []string{"build"}, 0, "", time.Millisecond, "/tmp", false, opts(1, "allow")); err != nil {
		t.Fatal(err)
	}
	// Entry 2: L3 allow, cap=git
	if err := logger.Log("git push", []string{"git"}, []string{"write"}, 0, "", time.Millisecond, "/tmp", false, opts(3, "allow")); err != nil {
		t.Fatal(err)
	}
	// Entry 3: L3 deny, cap=rm
	if err := logger.Log("rm -rf /tmp/x", []string{"rm"}, []string{"dangerous"}, 1, "denied", time.Millisecond, "/tmp", false, opts(3, "deny")); err != nil {
		t.Fatal(err)
	}
	// Entry 4: L2 allow, cap=go
	if err := logger.Log("go test ./...", []string{"go"}, []string{"build"}, 0, "", time.Millisecond, "/tmp", false, opts(2, "allow")); err != nil {
		t.Fatal(err)
	}
	// Entry 5: L3 allow, cap=go
	if err := logger.Log("go vet ./...", []string{"go"}, []string{"build"}, 0, "", time.Millisecond, "/tmp", false, opts(3, "allow")); err != nil {
		t.Fatal(err)
	}

	return path, logger
}

func TestQueryByLevel(t *testing.T) {
	path, _ := seedTestLog(t)
	entries, err := Query(path, &Filter{PolicyLevel: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 L3 entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.PolicyLevel != 3 {
			t.Errorf("expected PolicyLevel 3, got %d", e.PolicyLevel)
		}
	}
}

func TestQueryByResult(t *testing.T) {
	path, _ := seedTestLog(t)
	entries, err := Query(path, &Filter{PolicyResult: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 allow entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.PolicyResult != "allow" {
			t.Errorf("expected PolicyResult allow, got %q", e.PolicyResult)
		}
	}
}

func TestQueryByCap(t *testing.T) {
	path, _ := seedTestLog(t)
	entries, err := Query(path, &Filter{Cap: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 go entries, got %d", len(entries))
	}
	for _, e := range entries {
		found := false
		for _, seg := range e.Segments {
			if seg == "go" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected cap 'go' in segments %v", e.Segments)
		}
	}
}

func TestQueryByTimeRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}

	// Log entries.
	for i, cmd := range []string{"go build", "git status", "go test"} {
		segs := []string{cmd[:strings.IndexByte(cmd, ' ')]}
		if err := logger.Log(cmd, segs, []string{"build"}, 0, "", time.Millisecond, "/tmp", false, nil); err != nil {
			t.Fatalf("log entry %d: %v", i, err)
		}
	}

	// Read back to get actual timestamps.
	all, err := Query(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}

	// A range that covers all entries (1ns before first, 1ns after last).
	rangeStart := all[0].Time.Add(-time.Nanosecond)
	rangeEnd := all[len(all)-1].Time.Add(time.Nanosecond)

	inRange, err := Query(path, &Filter{After: rangeStart, Before: rangeEnd})
	if err != nil {
		t.Fatal(err)
	}
	if len(inRange) != 3 {
		t.Fatalf("expected 3 entries in full range, got %d", len(inRange))
	}

	// A range that excludes all entries (entirely in the future).
	future := rangeEnd.Add(time.Hour)
	none, err := Query(path, &Filter{After: future})
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("expected 0 entries after future cutoff, got %d", len(none))
	}

	// A range that excludes all entries (entirely in the past).
	past := rangeStart.Add(-time.Hour)
	none, err = Query(path, &Filter{Before: past})
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("expected 0 entries before past cutoff, got %d", len(none))
	}
}

func TestQueryCombinedFilters(t *testing.T) {
	path, _ := seedTestLog(t)
	entries, err := Query(path, &Filter{PolicyLevel: 3, PolicyResult: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	// L3 entries: git(allow), rm(deny), go(allow) => 2 match both L3+allow
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries with L3+allow, got %d", len(entries))
	}
	for _, e := range entries {
		if e.PolicyLevel != 3 || e.PolicyResult != "allow" {
			t.Errorf("unexpected entry: level=%d result=%q", e.PolicyLevel, e.PolicyResult)
		}
	}
}

func TestQueryNilFilter(t *testing.T) {
	path, _ := seedTestLog(t)
	entries, err := Query(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries with nil filter, got %d", len(entries))
	}
}

func TestQueryNonexistentFile(t *testing.T) {
	entries, err := Query("/nonexistent/path/audit.jsonl", nil)
	if err != nil {
		t.Fatalf("expected nil error for nonexistent file, got %v", err)
	}
	if entries != nil {
		t.Fatalf("expected nil entries for nonexistent file, got %v", entries)
	}
}

func TestQueryEmptyLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = logger // file created but no entries written

	entries, err := Query(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries from empty log, got %d", len(entries))
	}
}
