// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"
	"time"

	"github.com/marcelocantos/doit/internal/audit"
)

func makeL3Entry(cap, subcmd, result string) audit.Entry {
	pipeline := cap
	if subcmd != "" {
		pipeline = cap + " " + subcmd
	}
	return audit.Entry{
		PolicyLevel:  3,
		PolicyResult: result,
		Pipeline:     pipeline,
		Segments:     []string{cap},
	}
}

func TestAnalyseUniformAllows(t *testing.T) {
	var entries []audit.Entry
	for i := 0; i < 5; i++ {
		entries = append(entries, makeL3Entry("go", "test", "allow"))
	}

	candidates := AnalyseL3Decisions(entries, PromoteOptions{})
	if len(candidates) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(candidates))
	}
	c := candidates[0]
	if c.Count != 5 {
		t.Errorf("Count: want 5, got %d", c.Count)
	}
	if c.Decision != "allow" {
		t.Errorf("Decision: want %q, got %q", "allow", c.Decision)
	}
	if c.Uniformity != 1.0 {
		t.Errorf("Uniformity: want 1.0, got %f", c.Uniformity)
	}
}

func TestAnalyseBelowMinCount(t *testing.T) {
	entries := []audit.Entry{
		makeL3Entry("go", "test", "allow"),
		makeL3Entry("go", "test", "allow"),
	}

	candidates := AnalyseL3Decisions(entries, PromoteOptions{})
	if len(candidates) != 0 {
		t.Errorf("want 0 candidates, got %d", len(candidates))
	}
}

func TestAnalyseMixedDecisions(t *testing.T) {
	var entries []audit.Entry
	for i := 0; i < 3; i++ {
		entries = append(entries, makeL3Entry("go", "test", "allow"))
		entries = append(entries, makeL3Entry("go", "test", "deny"))
	}

	candidates := AnalyseL3Decisions(entries, PromoteOptions{})
	if len(candidates) != 0 {
		t.Errorf("want 0 candidates (uniformity 0.5 < 0.90), got %d", len(candidates))
	}
}

func TestAnalyseMultipleGroups(t *testing.T) {
	var entries []audit.Entry
	for i := 0; i < 4; i++ {
		entries = append(entries, makeL3Entry("go", "test", "allow"))
	}
	for i := 0; i < 3; i++ {
		entries = append(entries, makeL3Entry("rm", "-rf", "deny"))
	}

	// "rm -rf": second word starts with "-", so subcmd is empty; group is (rm, "")
	// But result "deny" has count 3, total 3, uniformity 1.0 → candidate
	candidates := AnalyseL3Decisions(entries, PromoteOptions{})
	if len(candidates) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(candidates))
	}
	// sorted by count descending: go test (4) before rm (3)
	if candidates[0].Match.Cap != "go" || candidates[0].Count != 4 {
		t.Errorf("first candidate: want go/4, got %s/%d", candidates[0].Match.Cap, candidates[0].Count)
	}
	if candidates[1].Match.Cap != "rm" || candidates[1].Count != 3 {
		t.Errorf("second candidate: want rm/3, got %s/%d", candidates[1].Match.Cap, candidates[1].Count)
	}
}

func TestAnalyseSubcmdGrouping(t *testing.T) {
	var entries []audit.Entry
	for i := 0; i < 3; i++ {
		entries = append(entries, makeL3Entry("git", "push", "allow"))
		entries = append(entries, makeL3Entry("git", "status", "allow"))
	}

	candidates := AnalyseL3Decisions(entries, PromoteOptions{})
	if len(candidates) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(candidates))
	}

	subcmds := map[string]bool{}
	for _, c := range candidates {
		if c.Match.Cap != "git" {
			t.Errorf("cap: want git, got %s", c.Match.Cap)
		}
		subcmds[c.Match.Subcmd] = true
	}
	if !subcmds["push"] || !subcmds["status"] {
		t.Errorf("expected subcmds push and status, got %v", subcmds)
	}
}

func TestAnalyseIgnoresNonL3(t *testing.T) {
	var entries []audit.Entry
	for i := 0; i < 3; i++ {
		e := makeL3Entry("go", "test", "allow")
		e.PolicyLevel = 1
		entries = append(entries, e)
	}
	for i := 0; i < 3; i++ {
		entries = append(entries, makeL3Entry("go", "test", "allow"))
	}

	candidates := AnalyseL3Decisions(entries, PromoteOptions{})
	if len(candidates) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Count != 3 {
		t.Errorf("Count: want 3 (only L3 entries), got %d", candidates[0].Count)
	}
}

func TestCandidateToEntry(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	c := &Candidate{
		Match:      MatchCriteria{Cap: "go", Subcmd: "test"},
		Decision:   "allow",
		Reasoning:  "auto-promoted: 5/5 allow decisions for go test",
		Count:      5,
		Uniformity: 1.0,
	}

	e := CandidateToEntry(c, now)

	if e.ID != "auto-go-test-allow" {
		t.Errorf("ID: want %q, got %q", "auto-go-test-allow", e.ID)
	}
	if e.Approved {
		t.Error("Approved: want false")
	}
	if e.Provenance != "gatekeeper" {
		t.Errorf("Provenance: want %q, got %q", "gatekeeper", e.Provenance)
	}
	if e.Review.Created != now {
		t.Errorf("Review.Created: want %v, got %v", now, e.Review.Created)
	}
	if e.Review.ReviewCount != 0 {
		t.Errorf("Review.ReviewCount: want 0, got %d", e.Review.ReviewCount)
	}
	expectedNext := NextReviewTime(now, 0)
	if e.Review.NextReview != expectedNext {
		t.Errorf("Review.NextReview: want %v, got %v", expectedNext, e.Review.NextReview)
	}
	if e.Match.Cap != "go" || e.Match.Subcmd != "test" {
		t.Errorf("Match: want go/test, got %s/%s", e.Match.Cap, e.Match.Subcmd)
	}
}

func TestCandidateToEntryNoSubcmd(t *testing.T) {
	now := time.Now()
	c := &Candidate{
		Match:      MatchCriteria{Cap: "go"},
		Decision:   "allow",
		Reasoning:  "auto-promoted: 3/3 allow decisions for go",
		Count:      3,
		Uniformity: 1.0,
	}

	e := CandidateToEntry(c, now)

	if e.ID != "auto-go-allow" {
		t.Errorf("ID: want %q, got %q", "auto-go-allow", e.ID)
	}
}

func TestCandidateToEntryHighConfidence(t *testing.T) {
	now := time.Now()
	c := &Candidate{
		Match:      MatchCriteria{Cap: "go", Subcmd: "test"},
		Decision:   "allow",
		Reasoning:  "auto-promoted: 19/20 allow decisions for go test",
		Count:      20,
		Uniformity: 0.95,
	}

	e := CandidateToEntry(c, now)

	if e.Confidence != "high" {
		t.Errorf("Confidence: want %q, got %q", "high", e.Confidence)
	}

	// Also verify medium confidence for just below 0.95
	c2 := &Candidate{
		Match:      MatchCriteria{Cap: "go", Subcmd: "test"},
		Decision:   "allow",
		Reasoning:  "auto-promoted: 9/10 allow decisions for go test",
		Count:      10,
		Uniformity: 0.90,
	}
	e2 := CandidateToEntry(c2, now)
	if e2.Confidence != "medium" {
		t.Errorf("Confidence: want %q, got %q", "medium", e2.Confidence)
	}
}
