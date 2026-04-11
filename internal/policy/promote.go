// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marcelocantos/doit/internal/audit"
)

// Candidate represents a potential L2 policy entry derived from L3 patterns.
type Candidate struct {
	Match      MatchCriteria
	Decision   string
	Reasoning  string
	Count      int
	Uniformity float64
	Source     string // "uniform" (same decision), "conditional" (flag-dependent)
}

// PromoteOptions controls the thresholds for promotion analysis.
type PromoteOptions struct {
	MinCount      int
	MinUniformity float64
}

// groupKey identifies a semantic group of commands by capability and subcommand.
type groupKey struct {
	cap    string
	subcmd string
}

// entryInfo holds parsed metadata about an audit entry for grouping analysis.
type entryInfo struct {
	key    groupKey
	flags  []string // extracted flags from the command
	result string
}

// AnalyseL3Decisions scans audit entries for repeated L3 decisions and returns
// promotion candidates that exceed the count and uniformity thresholds.
//
// Analysis proceeds in two passes:
//  1. Uniform groups: commands with the same cap+subcmd that always get the
//     same decision. These become simple L2 entries.
//  2. Conditional branching: same cap+subcmd with mixed decisions where a
//     specific flag distinguishes allow from deny. These become flag-specific
//     L2 entries.
func AnalyseL3Decisions(entries []audit.Entry, opts PromoteOptions) []Candidate {
	if opts.MinCount <= 0 {
		opts.MinCount = 3
	}
	if opts.MinUniformity <= 0 {
		opts.MinUniformity = 0.90
	}

	// Parse all L3 entries into structured metadata.
	var parsed []entryInfo
	for _, e := range entries {
		if e.PolicyLevel != 3 || len(e.Segments) == 0 {
			continue
		}
		info := parseEntryInfo(e)
		parsed = append(parsed, info)
	}

	// Pass 1: Group by cap+subcmd, find uniform groups.
	groups := groupByKey(parsed)
	var candidates []Candidate
	var mixedGroups []groupKey // groups that don't meet uniformity threshold

	for key, infos := range groups {
		total := len(infos)
		if total < opts.MinCount {
			continue
		}

		resultCounts := countResults(infos)
		majorityResult, majorityCount := majorityDecision(resultCounts)
		uniformity := float64(majorityCount) / float64(total)

		if uniformity >= opts.MinUniformity {
			capSubcmdLabel := key.cap
			if key.subcmd != "" {
				capSubcmdLabel = key.cap + " " + key.subcmd
			}
			candidates = append(candidates, Candidate{
				Match: MatchCriteria{
					Cap:    key.cap,
					Subcmd: key.subcmd,
				},
				Decision:   majorityResult,
				Reasoning:  fmt.Sprintf("auto-promoted: %d/%d %s decisions for %s", majorityCount, total, majorityResult, capSubcmdLabel),
				Count:      total,
				Uniformity: uniformity,
				Source:     "uniform",
			})
		} else {
			mixedGroups = append(mixedGroups, key)
		}
	}

	// Pass 2: Conditional branching — analyse mixed groups for flag-dependent decisions.
	for _, key := range mixedGroups {
		infos := groups[key]
		flagCandidates := analyseConditionalBranching(key, infos, opts)
		candidates = append(candidates, flagCandidates...)
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Count > candidates[j].Count
	})

	return candidates
}

// parseEntryInfo extracts structured metadata from an audit entry.
func parseEntryInfo(e audit.Entry) entryInfo {
	capName := e.Segments[0]
	words := strings.Fields(e.Pipeline)

	var subcmd string
	if len(words) >= 2 && !strings.HasPrefix(words[1], "-") {
		subcmd = words[1]
	}

	// Extract flags from the full command.
	startIdx := 1
	if subcmd != "" {
		startIdx = 2
	}
	var flags []string
	for _, w := range words[startIdx:] {
		if w == "--" {
			break
		}
		if strings.HasPrefix(w, "-") {
			// Normalize: strip =value from long flags.
			if strings.HasPrefix(w, "--") {
				if eqIdx := strings.Index(w, "="); eqIdx >= 0 {
					w = w[:eqIdx]
				}
			}
			flags = append(flags, w)
		}
	}

	return entryInfo{
		key:    groupKey{cap: capName, subcmd: subcmd},
		flags:  flags,
		result: e.PolicyResult,
	}
}

// groupByKey groups parsed entries by their cap+subcmd key.
func groupByKey(infos []entryInfo) map[groupKey][]entryInfo {
	groups := make(map[groupKey][]entryInfo)
	for _, info := range infos {
		groups[info.key] = append(groups[info.key], info)
	}
	return groups
}

// countResults tallies decisions within a group.
func countResults(infos []entryInfo) map[string]int {
	counts := make(map[string]int)
	for _, info := range infos {
		counts[info.result]++
	}
	return counts
}

// majorityDecision returns the most common result and its count.
func majorityDecision(resultCounts map[string]int) (string, int) {
	var best string
	var bestCount int
	for result, cnt := range resultCounts {
		if cnt > bestCount {
			bestCount = cnt
			best = result
		}
	}
	return best, bestCount
}

// analyseConditionalBranching detects cases where the same cap+subcmd gets
// different decisions based on which flags are present. For example, "git push"
// might be allowed without --force but denied with --force.
//
// It works by finding flags that appear disproportionately in one decision vs
// another. A flag is considered distinguishing if it appears in >=80% of one
// decision's entries and <=20% of the other's.
func analyseConditionalBranching(key groupKey, infos []entryInfo, opts PromoteOptions) []Candidate {
	// Split entries by decision.
	byDecision := make(map[string][]entryInfo)
	for _, info := range infos {
		byDecision[info.result] = append(byDecision[info.result], info)
	}

	// We need exactly 2 decisions to do meaningful conditional analysis.
	if len(byDecision) != 2 {
		return nil
	}

	var decisions [2]string
	var decGroups [2][]entryInfo
	i := 0
	for dec, g := range byDecision {
		decisions[i] = dec
		decGroups[i] = g
		i++
	}

	// Count flag frequency per decision group.
	flagFreq := [2]map[string]int{{}, {}}
	for side := 0; side < 2; side++ {
		for _, info := range decGroups[side] {
			seen := make(map[string]bool) // deduplicate within one entry
			for _, f := range info.flags {
				if !seen[f] {
					flagFreq[side][f]++
					seen[f] = true
				}
			}
		}
	}

	var candidates []Candidate

	// Find flags that distinguish one decision from the other.
	allFlags := make(map[string]bool)
	for _, ff := range flagFreq {
		for f := range ff {
			allFlags[f] = true
		}
	}

	for flag := range allFlags {
		for side := 0; side < 2; side++ {
			other := 1 - side
			sideRate := float64(flagFreq[side][flag]) / float64(len(decGroups[side]))
			otherRate := float64(0)
			if len(decGroups[other]) > 0 {
				otherRate = float64(flagFreq[other][flag]) / float64(len(decGroups[other]))
			}

			// Flag appears in >=80% of one group and <=20% of the other.
			if sideRate >= 0.80 && otherRate <= 0.20 {
				total := flagFreq[side][flag]
				if total < opts.MinCount {
					continue
				}

				capSubcmdLabel := key.cap
				if key.subcmd != "" {
					capSubcmdLabel = key.cap + " " + key.subcmd
				}

				reasoning := fmt.Sprintf("conditional: %s with %s → %s (%d occurrences, %.0f%% rate)",
					capSubcmdLabel, flag, decisions[side], total, sideRate*100)

				candidates = append(candidates, Candidate{
					Match: MatchCriteria{
						Cap:      key.cap,
						Subcmd:   key.subcmd,
						HasFlags: []string{flag},
					},
					Decision:   decisions[side],
					Reasoning:  reasoning,
					Count:      total,
					Uniformity: sideRate,
					Source:     "conditional",
				})
			}
		}
	}

	return candidates
}

// CandidateToEntry converts a promotion candidate to a PolicyEntry ready for
// insertion into the learned policy store.
func CandidateToEntry(c *Candidate, now time.Time) PolicyEntry {
	id := fmt.Sprintf("auto-%s-%s", c.Match.Cap, c.Decision)
	if c.Match.Subcmd != "" {
		id = fmt.Sprintf("auto-%s-%s-%s", c.Match.Cap, c.Match.Subcmd, c.Decision)
	}

	confidence := "medium"
	if c.Uniformity >= 0.95 {
		confidence = "high"
	}

	return PolicyEntry{
		ID:          id,
		Description: c.Reasoning,
		Match:       c.Match,
		Decision:    c.Decision,
		Reasoning:   c.Reasoning,
		Confidence:  confidence,
		Provenance:  "gatekeeper",
		Approved:    false,
		Review: ReviewSchedule{
			Created:      now,
			LastReviewed: now,
			ReviewCount:  0,
			NextReview:   NextReviewTime(now, 0),
		},
	}
}
