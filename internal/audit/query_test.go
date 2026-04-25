// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedTestLogFull writes a richer set of entries used by the T38 filter tests.
func seedTestLogFull(t *testing.T) (string, *Logger) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	write := func(pipeline string, segments, tiers []string, exitCode int, errMsg string, cwd string, opts *LogOptions) uint64 {
		t.Helper()
		seq, err := logger.Log(pipeline, segments, tiers, exitCode, errMsg, time.Millisecond, cwd, false, opts)
		if err != nil {
			t.Fatal(err)
		}
		return seq
	}

	// Entry 1: L1 allow, cap=go, exit=0, cwd=/project/alpha
	write("go build ./...", []string{"go"}, []string{"build"}, 0, "", "/project/alpha", &LogOptions{
		PolicyLevel:  1,
		PolicyResult: "allow",
		PolicyRuleID: "rule-go-build",
		ProjectRoot:  "/project/alpha",
	})

	// Entry 2: L3 deny, cap=rm, exit=1, cwd=/project/alpha
	write("rm -rf /tmp/x", []string{"rm"}, []string{"dangerous"}, 1, "denied", "/project/alpha", &LogOptions{
		PolicyLevel:  3,
		PolicyResult: "deny",
		PolicyRuleID: "no-rm-rf",
		ProjectRoot:  "/project/alpha",
		StdoutExcerpt: "",
		StderrExcerpt: "error: denied",
		L3Fast:        &L3Evidence{Model: "sonnet", Decision: "deny"},
	})

	// Entry 3: L2 allow, cap=git, exit=0, cwd=/project/beta
	write("git status", []string{"git"}, []string{"read"}, 0, "", "/project/beta", &LogOptions{
		PolicyLevel:  2,
		PolicyResult: "allow",
		ProjectRoot:  "/project/beta",
		StdoutExcerpt: "On branch master",
	})

	// Entry 4: elicitation child entry linking back to entry 2
	write("<elicitation>", nil, nil, 0, "", "", &LogOptions{
		PolicyResult:         "allow_once",
		ParentSeq:            2,
		ElicitationPrompt:    "Policy deny for rm -rf /tmp/x",
		ElicitationChoice:    "allow_once",
		ElicitationLatencyMs: 500.0,
	})

	// Entry 5: L1 allow, cap=make, exit=2 (nonzero), cwd=/project/alpha
	write("make test", []string{"make"}, []string{"build"}, 2, "test failed", "/project/alpha", &LogOptions{
		PolicyLevel:  1,
		PolicyResult: "allow",
		ProjectRoot:  "/project/alpha",
	})

	return path, logger
}

func seedTestLog(t *testing.T) (string, *Logger) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	opts := func(level int, result string) *LogOptions {
		return &LogOptions{PolicyLevel: level, PolicyResult: result}
	}

	// Entry 1: L1 allow, cap=go
	if _, err := logger.Log("go build ./...", []string{"go"}, []string{"build"}, 0, "", time.Millisecond, "/tmp", false, opts(1, "allow")); err != nil {
		t.Fatal(err)
	}
	// Entry 2: L3 allow, cap=git
	if _, err := logger.Log("git push", []string{"git"}, []string{"write"}, 0, "", time.Millisecond, "/tmp", false, opts(3, "allow")); err != nil {
		t.Fatal(err)
	}
	// Entry 3: L3 deny, cap=rm
	if _, err := logger.Log("rm -rf /tmp/x", []string{"rm"}, []string{"dangerous"}, 1, "denied", time.Millisecond, "/tmp", false, opts(3, "deny")); err != nil {
		t.Fatal(err)
	}
	// Entry 4: L2 allow, cap=go
	if _, err := logger.Log("go test ./...", []string{"go"}, []string{"build"}, 0, "", time.Millisecond, "/tmp", false, opts(2, "allow")); err != nil {
		t.Fatal(err)
	}
	// Entry 5: L3 allow, cap=go
	if _, err := logger.Log("go vet ./...", []string{"go"}, []string{"build"}, 0, "", time.Millisecond, "/tmp", false, opts(3, "allow")); err != nil {
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
	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Log entries.
	for i, cmd := range []string{"go build", "git status", "go test"} {
		segs := []string{cmd[:strings.IndexByte(cmd, ' ')]}
		if _, err := logger.Log(cmd, segs, []string{"build"}, 0, "", time.Millisecond, "/tmp", false, nil); err != nil {
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
	logger, err := NewLogger(path, 0)
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

// T38: new filter fields

func TestQueryByRuleID(t *testing.T) {
	path, _ := seedTestLogFull(t)
	entries, err := Query(path, &Filter{RuleID: "rule-go-build"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].PolicyRuleID != "rule-go-build" {
		t.Errorf("unexpected rule_id: %q", entries[0].PolicyRuleID)
	}
}

func TestQueryByCwdSubstring(t *testing.T) {
	path, _ := seedTestLogFull(t)
	entries, err := Query(path, &Filter{CwdSubstring: "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	// entries 1, 2, 5 have cwd=/project/alpha; entry 4 has empty cwd
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries with cwd containing 'alpha', got %d", len(entries))
	}
	for _, e := range entries {
		if !strings.Contains(e.Cwd, "alpha") {
			t.Errorf("unexpected cwd %q", e.Cwd)
		}
	}
}

func TestQueryByProjectRoot(t *testing.T) {
	path, _ := seedTestLogFull(t)
	entries, err := Query(path, &Filter{ProjectRoot: "/project/beta"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry with project_root=/project/beta, got %d", len(entries))
	}
	if entries[0].ProjectRoot != "/project/beta" {
		t.Errorf("unexpected project_root: %q", entries[0].ProjectRoot)
	}
}

func TestQueryByExitCodeExact(t *testing.T) {
	path, _ := seedTestLogFull(t)
	code := 2
	entries, err := Query(path, &Filter{ExitCode: &code})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry with exit_code=2, got %d", len(entries))
	}
	if entries[0].ExitCode != 2 {
		t.Errorf("unexpected exit_code: %d", entries[0].ExitCode)
	}
}

func TestQueryByNonzeroExitCode(t *testing.T) {
	path, _ := seedTestLogFull(t)
	entries, err := Query(path, &Filter{Nonzero: true})
	if err != nil {
		t.Fatal(err)
	}
	// entries 2 (exit=1) and 5 (exit=2) have nonzero exit codes
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries with nonzero exit_code, got %d", len(entries))
	}
	for _, e := range entries {
		if e.ExitCode == 0 {
			t.Errorf("expected nonzero exit_code, got 0 for entry %d", e.Seq)
		}
	}
}

func TestQueryByCommandSubstring(t *testing.T) {
	path, _ := seedTestLogFull(t)
	entries, err := Query(path, &Filter{CommandSubstring: "go"})
	if err != nil {
		t.Fatal(err)
	}
	// "go build ./..." matches, "git status" does not, "<elicitation>" does not
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry matching 'go' command, got %d", len(entries))
	}
	if !strings.Contains(entries[0].Pipeline, "go") {
		t.Errorf("unexpected pipeline: %q", entries[0].Pipeline)
	}
}

func TestQueryByParentSeq(t *testing.T) {
	path, _ := seedTestLogFull(t)
	entries, err := Query(path, &Filter{ParentSeq: 2})
	if err != nil {
		t.Fatal(err)
	}
	// Only entry 4 has parent_seq=2
	if len(entries) != 1 {
		t.Fatalf("expected 1 elicitation child entry, got %d", len(entries))
	}
	if entries[0].ParentSeq != 2 {
		t.Errorf("unexpected parent_seq: %d", entries[0].ParentSeq)
	}
	if entries[0].ElicitationChoice != "allow_once" {
		t.Errorf("unexpected elicitation_choice: %q", entries[0].ElicitationChoice)
	}
}

func TestQueryLimit(t *testing.T) {
	path, _ := seedTestLogFull(t)
	entries, err := Query(path, &Filter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	// With 5 entries and limit=2, we should get the 2 most recent entries.
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries with limit=2, got %d", len(entries))
	}
	// Entries are oldest-first within the limit window, so the last two.
	if entries[0].Seq != 4 {
		t.Errorf("expected first returned entry to be seq=4, got %d", entries[0].Seq)
	}
	if entries[1].Seq != 5 {
		t.Errorf("expected second returned entry to be seq=5, got %d", entries[1].Seq)
	}
}

func TestQueryLatest_ReturnsOneEntry(t *testing.T) {
	path, _ := seedTestLogFull(t)
	entry, err := QueryLatest(path, &Filter{PolicyResult: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected an entry, got nil")
	}
	if entry.PolicyResult != "allow" {
		t.Errorf("expected policy_result=allow, got %q", entry.PolicyResult)
	}
	// The latest "allow" entry is seq=5 (make test)
	if entry.Seq != 5 {
		t.Errorf("expected seq=5, got %d", entry.Seq)
	}
}

func TestQueryLatest_NoMatch_ReturnsNil(t *testing.T) {
	path, _ := seedTestLogFull(t)
	entry, err := QueryLatest(path, &Filter{PolicyResult: "escalate"})
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil {
		t.Errorf("expected nil entry for no-match, got entry seq=%d", entry.Seq)
	}
}

func TestQueryEmptyResult(t *testing.T) {
	path, _ := seedTestLogFull(t)
	entries, err := Query(path, &Filter{RuleID: "nonexistent-rule"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestQuerySince(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := NewLogger(path, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Write 3 entries.
	for i, cmd := range []string{"go build", "git status", "make test"} {
		segs := []string{cmd[:strings.IndexByte(cmd, ' ')]}
		if _, err := logger.Log(cmd, segs, []string{"build"}, 0, "", time.Millisecond, "/tmp", false, nil); err != nil {
			t.Fatalf("log entry %d: %v", i, err)
		}
	}

	// Read them back to get timestamps.
	all, err := Query(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}

	// "since" just before the second entry's timestamp — should return 2 entries.
	cutoff := all[1].Time.Add(-time.Nanosecond)
	got, err := Query(path, &Filter{After: cutoff})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries after cutoff, got %d", len(got))
	}
}

func TestQueryCombinedFiltersT38(t *testing.T) {
	path, _ := seedTestLogFull(t)
	// L3 deny entries in /project/alpha
	entries, err := Query(path, &Filter{
		PolicyLevel:  3,
		PolicyResult: "deny",
		ProjectRoot:  "/project/alpha",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 L3+deny+alpha entry, got %d", len(entries))
	}
	if entries[0].PolicyLevel != 3 || entries[0].PolicyResult != "deny" {
		t.Errorf("unexpected entry: level=%d result=%q", entries[0].PolicyLevel, entries[0].PolicyResult)
	}
}
