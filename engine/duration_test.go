// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcelocantos/doit/internal/policy"
)

// newTestEngineForDurations replaces the learned-duration store with
// an isolated test-local path so we don't touch the user's real file.
func newTestEngineForDurations(t *testing.T) *Engine {
	t.Helper()
	eng := newTestEngine(t)
	dir := t.TempDir()
	eng.durationStore = policy.NewDurationStore(filepath.Join(dir, "stats.yaml"))
	return eng
}

func TestEngine_LearnAndFlagAnomaly(t *testing.T) {
	eng := newTestEngineForDurations(t)

	// Generate successful executions of the same pattern. Each Execute
	// appends an audit entry with a realistic duration.
	for i := 0; i < 10; i++ {
		r := eng.Execute(context.Background(), Request{
			Command: "echo learned",
			Retry:   true, // bypass rules just for this harness
		})
		if r.ExitCode != 0 {
			t.Fatalf("seed run %d: exit=%d stderr=%q", i, r.ExitCode, r.Stderr)
		}
	}

	// Learn from the audit log.
	n, err := eng.LearnDurations()
	if err != nil {
		t.Fatalf("LearnDurations: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least one learned pattern")
	}

	// `echo` runs in single-digit milliseconds, so an agent declaring
	// expected_duration_seconds=1 is over-estimating by ~250× — the
	// anomaly rule should fire. This exercises the end-to-end path:
	// real audit log → aggregator → store → evaluator.
	res := eng.Evaluate(context.Background(), Request{
		Command:                 "echo learned",
		ExpectedDurationSeconds: 1,
	})
	if res.RuleID != "duration-anomaly" {
		t.Errorf("expected duration-anomaly to fire for 1s expectation on an echo that takes ~ms; got %+v", res)
	}
}

func TestEngine_FlagAnomalyWithPrimedStore(t *testing.T) {
	eng := newTestEngineForDurations(t)

	// Prime the store with known stats — simulate learned history.
	stats := []policy.DurationStats{
		{Cap: "make", Subcmd: "test", SampleCount: 20, P50Ms: 30_000, P95Ms: 60_000},
	}
	if err := eng.durationStore.Replace(stats); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Agent claims `make test` takes 1 second — far below p50=30s.
	res := eng.Evaluate(context.Background(), Request{
		Command:                 "make test",
		ExpectedDurationSeconds: 1,
	})
	if res.Decision != "deny" {
		t.Fatalf("expected deny, got %s (reason=%q, rule=%q)", res.Decision, res.Reason, res.RuleID)
	}
	if res.RuleID != "duration-anomaly" {
		t.Errorf("rule ID: got %q, want duration-anomaly", res.RuleID)
	}
	if !res.Bypassable {
		t.Error("expected bypassable=true")
	}
	if !strings.Contains(res.Reason, "p50") {
		t.Errorf("reason: got %q", res.Reason)
	}
}

func TestEngine_AnomalyBypassedByRetry(t *testing.T) {
	eng := newTestEngineForDurations(t)

	stats := []policy.DurationStats{
		{Cap: "make", Subcmd: "test", SampleCount: 20, P50Ms: 30_000, P95Ms: 60_000},
	}
	if err := eng.durationStore.Replace(stats); err != nil {
		t.Fatalf("prime: %v", err)
	}

	res := eng.Evaluate(context.Background(), Request{
		Command:                 "make test",
		ExpectedDurationSeconds: 1,
		Retry:                   true,
	})
	if res.RuleID == "duration-anomaly" {
		t.Errorf("retry should bypass anomaly, got %+v", res)
	}
}

func TestEngine_NoAnomalyWithoutExpectation(t *testing.T) {
	eng := newTestEngineForDurations(t)

	stats := []policy.DurationStats{
		{Cap: "make", Subcmd: "test", SampleCount: 20, P50Ms: 30_000, P95Ms: 60_000},
	}
	if err := eng.durationStore.Replace(stats); err != nil {
		t.Fatalf("prime: %v", err)
	}

	res := eng.Evaluate(context.Background(), Request{
		Command: "make test",
		// No expectation supplied — should not flag.
	})
	if res.RuleID == "duration-anomaly" {
		t.Errorf("no expectation should not flag; got %+v", res)
	}
}

func TestEngine_DurationStorePathExposed(t *testing.T) {
	eng := newTestEngineForDurations(t)
	if eng.DurationStorePath() == "" {
		t.Error("DurationStorePath should be non-empty")
	}
}
