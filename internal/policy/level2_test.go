// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/marcelocantos/doit/internal/cap"
)

func testEntries() []PolicyEntry {
	return []PolicyEntry{
		{
			ID:       "allow-go-test",
			Match:    MatchCriteria{Cap: "go", Subcmd: "test"},
			Decision: "allow",
			Reasoning: "safe build-time operation",
			Approved: true,
		},
		{
			ID:       "allow-make-any",
			Match:    MatchCriteria{Cap: "make"},
			Decision: "allow",
			Reasoning: "make is safe",
			Approved: true,
		},
		{
			ID:       "allow-git-rm-build",
			Match:    MatchCriteria{Cap: "git", Subcmd: "rm", ArgsGlob: []string{"build/*", "dist/*"}},
			Decision: "allow",
			Reasoning: "build artifacts are regenerated",
			Approved: true,
		},
		{
			ID:       "escalate-git-rm-source",
			Match:    MatchCriteria{Cap: "git", Subcmd: "rm"},
			Decision: "escalate",
			Reasoning: "source removal needs human confirmation",
			Approved: true,
		},
		{
			ID:       "deny-npm-global",
			Match:    MatchCriteria{Cap: "npm", Subcmd: "install", HasFlags: []string{"-g", "--global"}},
			Decision: "deny",
			Reasoning: "global installs are dangerous",
			Approved: true,
		},
		{
			ID:       "allow-npm-install",
			Match:    MatchCriteria{Cap: "npm", Subcmd: "install", NoFlags: []string{"-g", "--global"}},
			Decision: "allow",
			Reasoning: "local install is safe",
			Approved: true,
		},
		{
			ID:       "unapproved-entry",
			Match:    MatchCriteria{Cap: "python"},
			Decision: "allow",
			Reasoning: "not yet approved",
			Approved: false,
		},
	}
}

func TestLevel2CapOnlyMatch(t *testing.T) {
	l2 := NewLevel2(testEntries())
	result := l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "make", Tier: cap.TierBuild}},
	})
	if result.Decision != Allow {
		t.Errorf("got %v, want allow for make", result.Decision)
	}
	if result.RuleID != "allow-make-any" {
		t.Errorf("got rule %q, want allow-make-any", result.RuleID)
	}
}

func TestLevel2CapSubcmdMatch(t *testing.T) {
	l2 := NewLevel2(testEntries())
	result := l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "go", Args: []string{"test", "./..."}, Tier: cap.TierBuild}},
	})
	if result.Decision != Allow {
		t.Errorf("got %v, want allow for go test", result.Decision)
	}
	if result.RuleID != "allow-go-test" {
		t.Errorf("got rule %q, want allow-go-test", result.RuleID)
	}
}

func TestLevel2ArgsGlobMatch(t *testing.T) {
	l2 := NewLevel2(testEntries())

	// build artifact → allow
	result := l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "git", Args: []string{"rm", "build/foo.o"}, Tier: cap.TierWrite}},
	})
	if result.Decision != Allow || result.RuleID != "allow-git-rm-build" {
		t.Errorf("build artifact: got decision=%v rule=%q, want allow by allow-git-rm-build",
			result.Decision, result.RuleID)
	}

	// dist artifact → allow
	result = l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "git", Args: []string{"rm", "dist/bundle.js"}, Tier: cap.TierWrite}},
	})
	if result.Decision != Allow || result.RuleID != "allow-git-rm-build" {
		t.Errorf("dist artifact: got decision=%v rule=%q, want allow by allow-git-rm-build",
			result.Decision, result.RuleID)
	}
}

func TestLevel2OrderingFirstMatchWins(t *testing.T) {
	l2 := NewLevel2(testEntries())

	// source file → falls through to escalate-git-rm-source
	result := l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "git", Args: []string{"rm", "src/main.go"}, Tier: cap.TierWrite}},
	})
	if result.Decision != Escalate || result.RuleID != "escalate-git-rm-source" {
		t.Errorf("source file: got decision=%v rule=%q, want escalate by escalate-git-rm-source",
			result.Decision, result.RuleID)
	}
}

func TestLevel2HasFlagsMatch(t *testing.T) {
	l2 := NewLevel2(testEntries())

	// npm install -g → deny
	result := l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "npm", Args: []string{"install", "-g", "lodash"}, Tier: cap.TierWrite}},
	})
	if result.Decision != Deny || result.RuleID != "deny-npm-global" {
		t.Errorf("npm -g: got decision=%v rule=%q, want deny by deny-npm-global",
			result.Decision, result.RuleID)
	}

	// npm install --global → deny
	result = l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "npm", Args: []string{"install", "--global", "lodash"}, Tier: cap.TierWrite}},
	})
	if result.Decision != Deny {
		t.Errorf("npm --global: got %v, want deny", result.Decision)
	}
}

func TestLevel2NoFlagsMatch(t *testing.T) {
	l2 := NewLevel2(testEntries())

	// npm install (local) → allow
	result := l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "npm", Args: []string{"install", "lodash"}, Tier: cap.TierWrite}},
	})
	if result.Decision != Allow || result.RuleID != "allow-npm-install" {
		t.Errorf("npm local: got decision=%v rule=%q, want allow by allow-npm-install",
			result.Decision, result.RuleID)
	}
}

func TestLevel2UnapprovedSkipped(t *testing.T) {
	l2 := NewLevel2(testEntries())
	result := l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "python", Args: []string{"script.py"}, Tier: cap.TierBuild}},
	})
	if result.Decision != Escalate {
		t.Errorf("unapproved: got %v, want escalate", result.Decision)
	}
}

func TestLevel2RetryBypasses(t *testing.T) {
	l2 := NewLevel2(testEntries())
	result := l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "make", Tier: cap.TierBuild}},
		Retry:    true,
	})
	if result.Decision != Escalate {
		t.Errorf("retry: got %v, want escalate", result.Decision)
	}
	if result.Level != 2 {
		t.Errorf("retry: got level %d, want 2", result.Level)
	}
}

func TestLevel2PipelineAllAllow(t *testing.T) {
	l2 := NewLevel2(testEntries())
	result := l2.Evaluate(&Request{
		Segments: []Segment{
			{CapName: "grep", Args: []string{"foo"}, Tier: cap.TierRead},
			{CapName: "go", Args: []string{"test", "./..."}, Tier: cap.TierBuild},
		},
	})
	if result.Decision != Allow {
		t.Errorf("pipeline all-allow: got %v, want allow", result.Decision)
	}
}

func TestLevel2PipelineAnyDeny(t *testing.T) {
	l2 := NewLevel2(testEntries())
	result := l2.Evaluate(&Request{
		Segments: []Segment{
			{CapName: "go", Args: []string{"test", "./..."}, Tier: cap.TierBuild},
			{CapName: "npm", Args: []string{"install", "-g", "lodash"}, Tier: cap.TierWrite},
		},
	})
	if result.Decision != Deny {
		t.Errorf("pipeline any-deny: got %v, want deny", result.Decision)
	}
}

func TestLevel2PipelineMixedEscalate(t *testing.T) {
	l2 := NewLevel2(testEntries())
	result := l2.Evaluate(&Request{
		Segments: []Segment{
			{CapName: "go", Args: []string{"test", "./..."}, Tier: cap.TierBuild},
			{CapName: "python", Args: []string{"script.py"}, Tier: cap.TierBuild}, // unapproved
		},
	})
	if result.Decision != Escalate {
		t.Errorf("pipeline mixed: got %v, want escalate", result.Decision)
	}
}

func TestLevel2ImplicitTierReadAllow(t *testing.T) {
	l2 := NewLevel2(testEntries())
	// grep is TierRead, no explicit entry → implicit allow
	// go test has explicit entry → allow
	// Pipeline: all allow
	result := l2.Evaluate(&Request{
		Segments: []Segment{
			{CapName: "grep", Args: []string{"foo"}, Tier: cap.TierRead},
			{CapName: "go", Args: []string{"test", "./..."}, Tier: cap.TierBuild},
		},
	})
	if result.Decision != Allow {
		t.Errorf("implicit read + explicit allow: got %v, want allow", result.Decision)
	}
}

func TestLevel2EmptyStoreEscalates(t *testing.T) {
	l2 := NewLevel2(nil)
	result := l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "make", Tier: cap.TierBuild}},
	})
	if result.Decision != Escalate {
		t.Errorf("empty store: got %v, want escalate", result.Decision)
	}
}

func TestLevel2EmptySegments(t *testing.T) {
	l2 := NewLevel2(testEntries())
	result := l2.Evaluate(&Request{})
	if result.Decision != Escalate {
		t.Errorf("empty segments: got %v, want escalate", result.Decision)
	}
}

func TestLevel2Level(t *testing.T) {
	l2 := NewLevel2(testEntries())
	result := l2.Evaluate(&Request{
		Segments: []Segment{{CapName: "make", Tier: cap.TierBuild}},
	})
	if result.Level != 2 {
		t.Errorf("got level %d, want 2", result.Level)
	}
}

func TestExtractPositionalArgs(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		subcmd string
		want   []string
	}{
		{"no subcmd", []string{"foo", "bar"}, "", []string{"foo", "bar"}},
		{"with subcmd", []string{"test", "./..."}, "test", []string{"./..."}},
		{"flags filtered", []string{"rm", "-f", "build/a.o"}, "rm", []string{"build/a.o"}},
		{"-- separator", []string{"rm", "--", "-weird-file"}, "rm", []string{"-weird-file"}},
		{"empty", nil, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPositionalArgs(tt.args, tt.subcmd)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
