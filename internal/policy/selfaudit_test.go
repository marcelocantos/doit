// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"
	"time"
)

func TestAuditRules_Contradiction(t *testing.T) {
	l2 := []PolicyEntry{
		{
			ID:       "allow-git-push",
			Decision: "allow",
			Match:    MatchCriteria{Cap: "git", Subcmd: "push"},
		},
	}
	// L1 rule denies git push — contradicts the L2 allow.
	findings := auditRulesAt([]string{"deny git push"}, l2, nil, time.Now())

	found := false
	for _, f := range findings {
		if f.Category == "contradiction" && f.Severity == "error" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected contradiction finding, got %+v", findings)
	}
}

func TestAuditRules_NoContradiction_SameDecision(t *testing.T) {
	l2 := []PolicyEntry{
		{
			ID:       "deny-rm-rf",
			Decision: "deny",
			Match:    MatchCriteria{Cap: "rm", Subcmd: "-rf"},
		},
	}
	findings := auditRulesAt([]string{"deny rm -rf"}, l2, nil, time.Now())

	for _, f := range findings {
		if f.Category == "contradiction" {
			t.Errorf("unexpected contradiction finding: %+v", f)
		}
	}
}

func TestAuditRules_StaleEntry(t *testing.T) {
	// Entry whose review was due 100 days ago.
	overdueTime := time.Now().Add(-100 * 24 * time.Hour)
	l2 := []PolicyEntry{
		{
			ID:       "old-entry",
			Decision: "allow",
			Match:    MatchCriteria{Cap: "git"},
			Review:   ReviewSchedule{NextReview: overdueTime},
		},
	}

	findings := auditRulesAt(nil, l2, nil, time.Now())

	found := false
	for _, f := range findings {
		if f.Category == "stale" && f.Severity == "warning" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected stale finding for 100-day overdue entry, got %+v", findings)
	}
}

func TestAuditRules_NotStale_LessThan90Days(t *testing.T) {
	// Overdue but only by 30 days — should NOT trigger stale warning.
	overdueTime := time.Now().Add(-30 * 24 * time.Hour)
	l2 := []PolicyEntry{
		{
			ID:       "recent-entry",
			Decision: "allow",
			Match:    MatchCriteria{Cap: "git"},
			Review:   ReviewSchedule{NextReview: overdueTime},
		},
	}

	findings := auditRulesAt(nil, l2, nil, time.Now())

	for _, f := range findings {
		if f.Category == "stale" {
			t.Errorf("unexpected stale finding for 30-day overdue entry: %+v", f)
		}
	}
}

func TestAuditRules_MissingTest(t *testing.T) {
	l2 := []PolicyEntry{
		{
			ID:       "deny-rm",
			Decision: "deny",
			Match:    MatchCriteria{Cap: "rm"},
		},
	}
	// "deny-rm" is not in the Starlark rules list.
	starlarkRules := []string{"allow-cat"}
	findings := auditRulesAt(nil, l2, starlarkRules, time.Now())

	found := false
	for _, f := range findings {
		if f.Category == "missing_test" && f.Severity == "warning" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected missing_test finding, got %+v", findings)
	}
}

func TestAuditRules_MissingTest_SkipsUserEntries(t *testing.T) {
	l2 := []PolicyEntry{
		{
			ID:       "user-allow-git-1234",
			Decision: "allow",
			Match:    MatchCriteria{Cap: "git"},
		},
	}
	starlarkRules := []string{"other-rule"}
	findings := auditRulesAt(nil, l2, starlarkRules, time.Now())

	for _, f := range findings {
		if f.Category == "missing_test" {
			t.Errorf("unexpected missing_test finding for user entry: %+v", f)
		}
	}
}

func TestAuditRules_Duplicate(t *testing.T) {
	l2 := []PolicyEntry{
		{
			ID:       "allow-git-push-1",
			Decision: "allow",
			Match:    MatchCriteria{Cap: "git", Subcmd: "push"},
		},
		{
			ID:       "allow-git-push-2",
			Decision: "allow",
			Match:    MatchCriteria{Cap: "git", Subcmd: "push"},
		},
	}

	findings := auditRulesAt(nil, l2, nil, time.Now())

	found := false
	for _, f := range findings {
		if f.Category == "duplicate" && f.Severity == "info" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duplicate finding, got %+v", findings)
	}
}

func TestAuditRules_NoDuplicate_DifferentSubcmd(t *testing.T) {
	l2 := []PolicyEntry{
		{
			ID:       "allow-git-push",
			Decision: "allow",
			Match:    MatchCriteria{Cap: "git", Subcmd: "push"},
		},
		{
			ID:       "allow-git-pull",
			Decision: "allow",
			Match:    MatchCriteria{Cap: "git", Subcmd: "pull"},
		},
	}

	findings := auditRulesAt(nil, l2, nil, time.Now())

	for _, f := range findings {
		if f.Category == "duplicate" {
			t.Errorf("unexpected duplicate finding for different subcmds: %+v", f)
		}
	}
}

func TestAuditRules_Empty(t *testing.T) {
	findings := AuditRules(nil, nil, nil)
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty input, got %+v", findings)
	}
}
