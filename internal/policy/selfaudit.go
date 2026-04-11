// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"strings"
	"time"
)

// AuditFinding describes a potential issue found during a self-audit.
type AuditFinding struct {
	Severity    string // "error", "warning", "info"
	Category    string // "contradiction", "stale", "missing_test", "duplicate"
	Description string
}

// AuditRules checks for potential issues in the policy rule set.
//
//   - Contradictions: L1 denies what L2 allows (or vice versa) for the same
//     capability/subcommand combination.
//   - Stale entries: L2 entries whose review is overdue by 90+ days.
//   - Missing tests: Starlark rule IDs referenced but not found in the loaded
//     rule set (identified by absence from starlarkRules slice).
//   - Duplicate coverage: Multiple L2 entries covering the same cap+subcmd.
func AuditRules(l1Rules []string, l2Entries []PolicyEntry, starlarkRules []string) []AuditFinding {
	return auditRulesAt(l1Rules, l2Entries, starlarkRules, time.Now())
}

// auditRulesAt is the internal implementation with injectable clock for testing.
func auditRulesAt(l1Rules []string, l2Entries []PolicyEntry, starlarkRules []string, now time.Time) []AuditFinding {
	var findings []AuditFinding

	// Index Starlark rule IDs for fast lookup.
	starSet := make(map[string]bool, len(starlarkRules))
	for _, r := range starlarkRules {
		starSet[r] = true
	}

	// Build indexes over L2 entries.
	type l2Key struct{ cap, subcmd string }
	type l2Item struct{ decision, id string }
	l2Index := make(map[l2Key][]l2Item)
	for _, e := range l2Entries {
		k := l2Key{cap: e.Match.Cap, subcmd: e.Match.Subcmd}
		l2Index[k] = append(l2Index[k], l2Item{decision: e.Decision, id: e.ID})
	}

	// Check contradictions: for each L1 rule, look for L2 entries with a
	// conflicting decision for the same cap+subcmd. L1 rules are free-form
	// strings; we do a best-effort parse of the form "decision cap [subcmd]".
	for _, rule := range l1Rules {
		cap, subcmd, decision := parseL1RuleHint(rule)
		if cap == "" || decision == "" {
			continue
		}
		k := l2Key{cap: cap, subcmd: subcmd}
		for _, item := range l2Index[k] {
			if item.decision != decision && item.decision != "escalate" {
				findings = append(findings, AuditFinding{
					Severity:    "error",
					Category:    "contradiction",
					Description: fmt.Sprintf("L1 rule %q %ss %s %s but L2 entry %q %ss the same pattern",
						rule, decision, cap, subcmd, item.id, item.decision),
				})
			}
		}
	}

	// Check stale entries: overdue by 90+ days.
	const staleThreshold = 90 * 24 * time.Hour
	for _, e := range l2Entries {
		if e.Review.NextReview.IsZero() {
			continue
		}
		if now.After(e.Review.NextReview) {
			overdue := now.Sub(e.Review.NextReview)
			if overdue >= staleThreshold {
				findings = append(findings, AuditFinding{
					Severity:    "warning",
					Category:    "stale",
					Description: fmt.Sprintf("L2 entry %q is overdue for review by %d days (next_review: %s)",
						e.ID, int(overdue.Hours()/24), e.Review.NextReview.Format("2006-01-02")),
				})
			}
		}
	}

	// Check missing Starlark tests: non-user L2 entries whose ID is not present
	// in the loaded Starlark rule set.
	for _, e := range l2Entries {
		if strings.HasPrefix(e.ID, "user-") {
			continue
		}
		if len(starlarkRules) > 0 && !starSet[e.ID] {
			findings = append(findings, AuditFinding{
				Severity:    "warning",
				Category:    "missing_test",
				Description: fmt.Sprintf("L2 entry %q references a Starlark rule ID not found in loaded rules", e.ID),
			})
		}
	}

	// Check duplicate coverage: multiple L2 entries for the same cap+subcmd.
	type l2KeySorted struct{ cap, subcmd string }
	seen := make(map[l2KeySorted]bool)
	for k, items := range l2Index {
		ks := l2KeySorted{cap: k.cap, subcmd: k.subcmd}
		if seen[ks] {
			continue
		}
		seen[ks] = true
		if len(items) <= 1 {
			continue
		}
		ids := make([]string, len(items))
		for i, item := range items {
			ids[i] = item.id
		}
		pattern := k.cap
		if k.subcmd != "" {
			pattern += " " + k.subcmd
		}
		findings = append(findings, AuditFinding{
			Severity:    "info",
			Category:    "duplicate",
			Description: fmt.Sprintf("Multiple L2 entries cover %q: %s", pattern, strings.Join(ids, ", ")),
		})
	}

	return findings
}

// parseL1RuleHint attempts to extract (cap, subcmd, decision) from a free-form
// L1 rule string. Supports the format "<decision> <cap> [<subcmd>]".
func parseL1RuleHint(rule string) (cap, subcmd, decision string) {
	parts := strings.Fields(rule)
	if len(parts) < 2 {
		return "", "", ""
	}
	switch parts[0] {
	case "allow", "deny", "escalate":
		decision = parts[0]
		cap = parts[1]
		if len(parts) >= 3 {
			subcmd = parts[2]
		}
		return cap, subcmd, decision
	}
	return "", "", ""
}
