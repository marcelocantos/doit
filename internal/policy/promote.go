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
}

// PromoteOptions controls the thresholds for promotion analysis.
type PromoteOptions struct {
	MinCount      int
	MinUniformity float64
}

// AnalyseL3Decisions scans audit entries for repeated L3 decisions and returns
// promotion candidates that exceed the count and uniformity thresholds.
func AnalyseL3Decisions(entries []audit.Entry, opts PromoteOptions) []Candidate {
	if opts.MinCount <= 0 {
		opts.MinCount = 3
	}
	if opts.MinUniformity <= 0 {
		opts.MinUniformity = 0.90
	}

	type groupKey struct {
		cap    string
		subcmd string
	}

	// counts maps groupKey → (result → count)
	counts := make(map[groupKey]map[string]int)
	totals := make(map[groupKey]int)

	for _, e := range entries {
		if e.PolicyLevel != 3 {
			continue
		}
		if len(e.Segments) == 0 {
			continue
		}
		cap := e.Segments[0]

		var subcmd string
		words := strings.Fields(e.Pipeline)
		if len(words) >= 2 && !strings.HasPrefix(words[1], "-") {
			subcmd = words[1]
		}

		key := groupKey{cap: cap, subcmd: subcmd}
		totals[key]++

		result := e.PolicyResult
		if counts[key] == nil {
			counts[key] = make(map[string]int)
		}
		counts[key][result]++
	}

	var candidates []Candidate

	for key, resultCounts := range counts {
		total := totals[key]
		if total < opts.MinCount {
			continue
		}

		// Find majority result.
		var majorityResult string
		var majorityCount int
		for result, cnt := range resultCounts {
			if cnt > majorityCount {
				majorityCount = cnt
				majorityResult = result
			}
		}

		uniformity := float64(majorityCount) / float64(total)
		if uniformity < opts.MinUniformity {
			continue
		}

		capSubcmdLabel := key.cap
		if key.subcmd != "" {
			capSubcmdLabel = key.cap + " " + key.subcmd
		}

		reasoning := fmt.Sprintf("auto-promoted: %d/%d %s decisions for %s",
			majorityCount, total, majorityResult, capSubcmdLabel)

		candidates = append(candidates, Candidate{
			Match: MatchCriteria{
				Cap:    key.cap,
				Subcmd: key.subcmd,
			},
			Decision:   majorityResult,
			Reasoning:  reasoning,
			Count:      total,
			Uniformity: uniformity,
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Count > candidates[j].Count
	})

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
