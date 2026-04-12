// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Level2 evaluates commands against the learned policy store.
type Level2 struct {
	entries []PolicyEntry
}

// NewLevel2 creates a Level2 engine from ordered policy entries.
func NewLevel2(entries []PolicyEntry) *Level2 {
	return &Level2{entries: entries}
}

// EntryCount returns the number of loaded policy entries.
func (l *Level2) EntryCount() int {
	return len(l.entries)
}

// Evaluate runs matching against the learned policy store.
//
// When req.Retry is true, Level 2 is bypassed entirely (returns Escalate).
// Learned policies are not hardcoded safety rules.
//
// The engine treats req.Command as an opaque string. L2 matches by parsing
// the first one or two tokens of the raw command string against the stored
// cap/subcmd criteria in each PolicyEntry. The shell handles all composition;
// L2 only reasons about what the first token looks like.
//
// Because the command may contain shell operators (&&, |, ;, subshells), L2
// does not auto-allow commands whose first token looks read-only — any command
// that is not matched by a specific approved entry escalates to L3.
func (l *Level2) Evaluate(req *Request) *Result {
	if req.Retry {
		return &Result{
			Decision: Escalate,
			Level:    2,
			Reason:   "--retry bypasses Level 2",
		}
	}

	if req.Command == "" {
		return &Result{
			Decision: Escalate,
			Level:    2,
			Reason:   "empty command",
		}
	}

	// Parse the first two tokens of the raw command string to build a
	// lightweight segment for matching against stored criteria. This is
	// intentionally shallow — we only look at the leading cap+args, not
	// the full command, because the full command may contain shell
	// composition that L2 is not equipped to reason about.
	seg := parseFirstSegment(req.Command)

	return l.matchSegment(&seg)
}

// parseFirstSegment builds a Segment from the leading tokens of the raw
// command string. It does not interpret shell operators; callers rely on
// the segment for stored-criteria matching only.
func parseFirstSegment(command string) Segment {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return Segment{}
	}
	return Segment{
		CapName: parts[0],
		Args:    parts[1:],
	}
}

// matchSegment finds the first matching approved entry for a segment.
// Returns Allow/Deny/Escalate per the matched entry, or Escalate if nothing
// matches. Unlike the pre-🎯T17 code, there is no implicit TierRead allow —
// all commands that lack a specific learned-policy match escalate to L3 so
// that shell composition is evaluated by the LLM gatekeeper.
func (l *Level2) matchSegment(seg *Segment) *Result {
	for _, entry := range l.entries {
		if !entry.Approved {
			continue
		}
		if matchesCriteria(seg, &entry.Match) {
			dec, err := ParseDecision(entry.Decision)
			if err != nil {
				continue // skip entries with invalid decisions
			}
			return &Result{
				Decision: dec,
				Level:    2,
				Reason:   fmt.Sprintf("matched learned policy %q: %s", entry.ID, entry.Reasoning),
				RuleID:   entry.ID,
			}
		}
	}

	return &Result{
		Decision: Escalate,
		Level:    2,
		Reason:   fmt.Sprintf("no learned policy for %s", seg.CapName),
	}
}

// matchesCriteria checks whether a segment satisfies all constraints in the
// match criteria. All specified fields must hold.
func matchesCriteria(seg *Segment, m *MatchCriteria) bool {
	// Cap must match exactly.
	if seg.CapName != m.Cap {
		return false
	}

	// Subcmd: args[0] must equal this if specified.
	if m.Subcmd != "" {
		if len(seg.Args) == 0 || seg.Args[0] != m.Subcmd {
			return false
		}
	}

	// HasFlags: at least one must be present.
	if len(m.HasFlags) > 0 {
		args := seg.Args
		if m.Subcmd != "" && len(args) > 0 {
			args = args[1:]
		}
		if !HasAnyFlag(args, m.HasFlags...) {
			return false
		}
	}

	// NoFlags: none may be present.
	if len(m.NoFlags) > 0 {
		args := seg.Args
		if m.Subcmd != "" && len(args) > 0 {
			args = args[1:]
		}
		if HasAnyFlag(args, m.NoFlags...) {
			return false
		}
	}

	// ArgsGlob: every non-flag positional arg (after subcmd) must match
	// at least one glob pattern.
	if len(m.ArgsGlob) > 0 {
		positional := extractPositionalArgs(seg.Args, m.Subcmd)
		if len(positional) == 0 {
			return false // no positional args to match against
		}
		for _, arg := range positional {
			if !matchAnyGlob(arg, m.ArgsGlob) {
				return false
			}
		}
	}

	return true
}

// extractPositionalArgs returns non-flag arguments after the subcmd.
func extractPositionalArgs(args []string, subcmd string) []string {
	start := 0
	if subcmd != "" && len(args) > 0 && args[0] == subcmd {
		start = 1
	}
	var pos []string
	pastDashes := false
	for _, arg := range args[start:] {
		if arg == "--" {
			pastDashes = true
			continue
		}
		if !pastDashes && strings.HasPrefix(arg, "-") {
			continue
		}
		pos = append(pos, arg)
	}
	return pos
}

// matchAnyGlob checks if s matches any of the glob patterns.
func matchAnyGlob(s string, patterns []string) bool {
	for _, p := range patterns {
		if matched, _ := filepath.Match(p, s); matched {
			return true
		}
	}
	return false
}

// Segment is used internally by L2 for matching against stored criteria.
// It is not part of the public policy.Request — the engine treats the
// full command as opaque and never exposes a parsed segment externally.
type Segment struct {
	CapName string
	Args    []string
}
