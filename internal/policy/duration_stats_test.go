// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/marcelocantos/doit/internal/audit"
)

func entry(pipeline string, segments []string, durationMs float64, exitCode int, timedOut bool, result string) audit.Entry {
	return audit.Entry{
		Pipeline:     pipeline,
		Segments:     segments,
		Duration:     durationMs,
		ExitCode:     exitCode,
		TimedOut:     timedOut,
		PolicyResult: result,
		Time:         time.Now().UTC(),
	}
}

func TestAggregateDurations_HappyPath(t *testing.T) {
	entries := []audit.Entry{
		entry("git status", []string{"git"}, 100, 0, false, "allow"),
		entry("git status", []string{"git"}, 200, 0, false, "allow"),
		entry("git status", []string{"git"}, 150, 0, false, "allow"),
		entry("git status", []string{"git"}, 120, 0, false, "allow"),
		entry("git status", []string{"git"}, 180, 0, false, "allow"),
	}
	stats := AggregateDurations(entries)
	if len(stats) != 1 {
		t.Fatalf("expected 1 stats entry, got %d", len(stats))
	}
	s := stats[0]
	if s.Cap != "git" || s.Subcmd != "status" {
		t.Errorf("key: got %s/%s", s.Cap, s.Subcmd)
	}
	if s.SampleCount != 5 {
		t.Errorf("sample count: got %d", s.SampleCount)
	}
	if s.P50Ms < 100 || s.P50Ms > 200 {
		t.Errorf("p50 out of range: %v", s.P50Ms)
	}
	if s.P95Ms <= s.P50Ms {
		t.Errorf("p95 should exceed p50; got p50=%v p95=%v", s.P50Ms, s.P95Ms)
	}
}

func TestAggregateDurations_ExcludesFailuresAndTimeouts(t *testing.T) {
	entries := []audit.Entry{
		entry("make test", []string{"make"}, 1000, 0, false, "allow"),
		entry("make test", []string{"make"}, 2000, 1, false, "allow"),  // failure — excluded
		entry("make test", []string{"make"}, 9999, 137, true, "allow"), // timeout — excluded
		entry("make test", []string{"make"}, 1500, 0, false, "escalate"),
	}
	stats := AggregateDurations(entries)
	if len(stats) != 1 {
		t.Fatalf("expected 1 stats entry, got %d", len(stats))
	}
	// Successful runs count regardless of policy_result — what matters
	// is that the command actually ran to completion.
	if stats[0].SampleCount != 2 {
		t.Errorf("sample count: got %d, want 2 (success runs only)", stats[0].SampleCount)
	}
}

func TestAggregateDurations_GroupsByCapAndSubcmd(t *testing.T) {
	entries := []audit.Entry{
		entry("git status", []string{"git"}, 50, 0, false, "allow"),
		entry("git log", []string{"git"}, 80, 0, false, "allow"),
		entry("git status", []string{"git"}, 60, 0, false, "allow"),
	}
	stats := AggregateDurations(entries)
	if len(stats) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(stats))
	}
}

func TestCheckDurationAnomaly_NoStats(t *testing.T) {
	r := CheckDurationAnomaly(&Request{ExpectedDurationSeconds: 1}, nil)
	if r != nil {
		t.Errorf("expected nil when stats are absent, got %+v", r)
	}
}

func TestCheckDurationAnomaly_InsufficientSamples(t *testing.T) {
	stats := &DurationStats{SampleCount: 2, P50Ms: 1000, P95Ms: 5000}
	r := CheckDurationAnomaly(&Request{ExpectedDurationSeconds: 1}, stats)
	if r != nil {
		t.Errorf("expected nil for n<minSamplesForAnomaly, got %+v", r)
	}
}

func TestCheckDurationAnomaly_SharpUnderExpected(t *testing.T) {
	stats := &DurationStats{SampleCount: 20, P50Ms: 10_000, P95Ms: 20_000}
	// expected=1s → 1000ms, which is far below p50/5 = 2000ms.
	r := CheckDurationAnomaly(&Request{ExpectedDurationSeconds: 1}, stats)
	if r == nil || r.Decision != Deny {
		t.Fatalf("expected Deny, got %+v", r)
	}
	if r.RuleID != "duration-anomaly" {
		t.Errorf("rule ID: got %q", r.RuleID)
	}
	if !r.Bypassable {
		t.Error("expected bypassable=true")
	}
}

func TestCheckDurationAnomaly_SharpOverExpected(t *testing.T) {
	stats := &DurationStats{SampleCount: 20, P50Ms: 100, P95Ms: 200}
	// expected=10s → 10000ms > p95*5=1000ms.
	r := CheckDurationAnomaly(&Request{ExpectedDurationSeconds: 10}, stats)
	if r == nil || r.Decision != Deny {
		t.Fatalf("expected Deny, got %+v", r)
	}
}

func TestCheckDurationAnomaly_WithinRange(t *testing.T) {
	stats := &DurationStats{SampleCount: 20, P50Ms: 1000, P95Ms: 3000}
	r := CheckDurationAnomaly(&Request{ExpectedDurationSeconds: 2}, stats)
	if r != nil {
		t.Errorf("expected nil when within range, got %+v", r)
	}
}

func TestCheckDurationAnomaly_TimeoutTooShort(t *testing.T) {
	stats := &DurationStats{SampleCount: 20, P50Ms: 10_000, P95Ms: 20_000}
	// timeout=1s → 1000ms < p50=10000ms.
	r := CheckDurationAnomaly(&Request{TimeoutSeconds: 1}, stats)
	if r == nil || r.Decision != Deny {
		t.Fatalf("expected Deny, got %+v", r)
	}
	if r.RuleID != "timeout-too-short" {
		t.Errorf("rule ID: got %q", r.RuleID)
	}
}

func TestCheckDurationAnomaly_TimeoutReasonable(t *testing.T) {
	stats := &DurationStats{SampleCount: 20, P50Ms: 1000, P95Ms: 3000}
	r := CheckDurationAnomaly(&Request{TimeoutSeconds: 10}, stats)
	if r != nil {
		t.Errorf("expected nil for reasonable timeout, got %+v", r)
	}
}

func TestDurationStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.yaml")
	s1 := NewDurationStore(path)

	stats := []DurationStats{
		{Cap: "git", Subcmd: "status", SampleCount: 10, P50Ms: 100, P95Ms: 200, LastUpdated: time.Now().UTC()},
		{Cap: "make", Subcmd: "test", SampleCount: 5, P50Ms: 30000, P95Ms: 60000, LastUpdated: time.Now().UTC()},
	}
	if err := s1.Replace(stats); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	s2 := NewDurationStore(path)
	loaded, err := s2.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 2 {
		t.Errorf("loaded count: got %d", len(loaded))
	}

	got, err := s2.Lookup("git", "status")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got == nil || got.SampleCount != 10 {
		t.Errorf("lookup git status: got %+v", got)
	}

	got, _ = s2.Lookup("nonexistent", "")
	if got != nil {
		t.Errorf("lookup missing: got %+v", got)
	}
}

func TestDurationStore_LookupForCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.yaml")
	s := NewDurationStore(path)
	if err := s.Replace([]DurationStats{
		{Cap: "git", Subcmd: "status", SampleCount: 10, P50Ms: 100, P95Ms: 200},
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	got, err := s.LookupForCommand("git status")
	if err != nil {
		t.Fatalf("LookupForCommand: %v", err)
	}
	if got == nil {
		t.Fatal("expected to find git status")
	}

	got, _ = s.LookupForCommand("git push --force")
	if got != nil {
		t.Errorf("git push should miss; got %+v", got)
	}

	got, _ = s.LookupForCommand("")
	if got != nil {
		t.Errorf("empty command should miss; got %+v", got)
	}
}
