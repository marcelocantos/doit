// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/marcelocantos/doit/internal/cap"
)

// Level2 evaluates commands against the learned policy store.
type Level2 struct {
	entries []PolicyEntry
}

// NewLevel2 creates a Level2 engine from ordered policy entries.
func NewLevel2(entries []PolicyEntry) *Level2 {
	return &Level2{entries: entries}
}

// Evaluate runs per-segment matching against the learned policy store.
//
// When req.Retry is true, Level 2 is bypassed entirely (returns Escalate).
// Learned policies are not hardcoded safety rules.
//
// Per-segment matching: for each segment, walk the ordered entry list.
// First matching approved entry wins. If no entry matches but the segment
// is TierRead, it's implicitly safe.
//
// Pipeline-level decision:
//   - Any segment → Deny: whole pipeline is Deny (short-circuit)
//   - All segments → Allow: pipeline is Allow
//   - Any segment unmatched or Escalate: pipeline is Escalate
func (l *Level2) Evaluate(req *Request) *Result {
	if req.Retry {
		return &Result{
			Decision: Escalate,
			Level:    2,
			Reason:   "--retry bypasses Level 2",
		}
	}

	if len(req.Segments) == 0 {
		return &Result{
			Decision: Escalate,
			Level:    2,
			Reason:   "no segments to evaluate",
		}
	}

	results := make([]*Result, len(req.Segments))
	for i, seg := range req.Segments {
		results[i] = l.matchSegment(&seg)
		if results[i].Decision == Deny {
			return results[i]
		}
	}

	// Single segment: return its result directly (preserves RuleID).
	if len(results) == 1 {
		return results[0]
	}

	// Multi-segment: all must be Allow.
	for _, r := range results {
		if r.Decision != Allow {
			return &Result{
				Decision: Escalate,
				Level:    2,
				Reason:   "no learned policy matched all segments",
			}
		}
	}
	return &Result{
		Decision: Allow,
		Level:    2,
		Reason:   "all segments allowed by learned policy",
	}
}

// matchSegment finds the first matching approved entry for a segment.
// Returns Allow/Deny/Escalate per the matched entry, or implicit Allow
// for TierRead segments, or Escalate if nothing matches.
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

	// Implicit TierRead allow: read-only segments are safe even without
	// an explicit entry, extending Level 1's compositionality.
	if seg.Tier == cap.TierRead {
		return &Result{
			Decision: Allow,
			Level:    2,
			Reason:   fmt.Sprintf("%s is read-only (implicit allow)", seg.CapName),
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
