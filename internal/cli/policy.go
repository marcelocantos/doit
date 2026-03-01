// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/marcelocantos/doit/internal/audit"
	"github.com/marcelocantos/doit/internal/policy"
)

// RunPolicy handles the doit --policy subcommand.
func RunPolicy(w io.Writer, auditPath, storePath string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(w, "usage: doit --policy <promote|list|approve|reject> [args]")
		return 1
	}

	switch args[0] {
	case "promote":
		return runPolicyPromote(w, auditPath, storePath)
	case "list":
		return runPolicyList(w, storePath, args[1:])
	case "approve":
		if len(args) < 2 {
			fmt.Fprintln(w, "usage: doit --policy approve <id>")
			return 1
		}
		return runPolicyApprove(w, storePath, args[1])
	case "reject":
		if len(args) < 2 {
			fmt.Fprintln(w, "usage: doit --policy reject <id>")
			return 1
		}
		return runPolicyReject(w, storePath, args[1])
	default:
		fmt.Fprintf(w, "doit --policy: unknown subcommand %q\n", args[0])
		return 1
	}
}

func runPolicyPromote(w io.Writer, auditPath, storePath string) int {
	entries, err := audit.Query(auditPath, &audit.Filter{PolicyLevel: 3})
	if err != nil {
		fmt.Fprintf(w, "doit --policy promote: %v\n", err)
		return 1
	}
	if len(entries) == 0 {
		fmt.Fprintln(w, "No L3 entries found in audit log")
		return 0
	}

	candidates := policy.AnalyseL3Decisions(entries, policy.PromoteOptions{})
	if len(candidates) == 0 {
		fmt.Fprintln(w, "No candidates found (insufficient count or uniformity)")
		return 0
	}

	now := time.Now()
	policyEntries := make([]policy.PolicyEntry, len(candidates))
	for i := range candidates {
		policyEntries[i] = policy.CandidateToEntry(&candidates[i], now)
	}

	added, err := policy.AppendEntries(storePath, policyEntries)
	if err != nil {
		fmt.Fprintf(w, "doit --policy promote: %v\n", err)
		return 1
	}

	fmt.Fprintf(w, "Promoted %d candidates (%d new)\n", len(candidates), added)
	return 0
}

func runPolicyList(w io.Writer, storePath string, args []string) int {
	var filterPending, filterReview bool
	for _, arg := range args {
		switch arg {
		case "--pending":
			filterPending = true
		case "--review":
			filterReview = true
		default:
			fmt.Fprintf(w, "doit --policy list: unknown flag %q\n", arg)
			return 1
		}
	}

	entries, err := policy.LoadStore(storePath)
	if err != nil {
		fmt.Fprintf(w, "doit --policy list: %v\n", err)
		return 1
	}
	if len(entries) == 0 {
		fmt.Fprintln(w, "No policy entries")
		return 0
	}

	fmt.Fprintf(w, "%-30s %-10s %-10s %-10s %s\n", "ID", "CAP", "SUBCMD", "DECISION", "STATUS")
	for _, e := range entries {
		status := entryStatus(e)
		if filterPending && status != "PENDING" {
			continue
		}
		if filterReview && status != "REVIEW DUE" {
			continue
		}
		fmt.Fprintf(w, "%-30s %-10s %-10s %-10s %s\n",
			e.ID, e.Match.Cap, e.Match.Subcmd, e.Decision, status)
	}
	return 0
}

func entryStatus(e policy.PolicyEntry) string {
	if !e.Approved {
		return "PENDING"
	}
	if !e.Review.NextReview.IsZero() && policy.NeedsReview(e.Review.NextReview) {
		return "REVIEW DUE"
	}
	return "APPROVED"
}

func runPolicyApprove(w io.Writer, storePath, id string) int {
	err := policy.UpdateEntry(storePath, id, func(e *policy.PolicyEntry) {
		now := time.Now()
		e.Approved = true
		e.Review.LastReviewed = now
		e.Review.ReviewCount++
		e.Review.NextReview = policy.NextReviewTime(now, e.Review.ReviewCount)
	})
	if err != nil {
		fmt.Fprintf(w, "doit --policy approve: %v\n", err)
		return 1
	}
	fmt.Fprintf(w, "Approved: %s\n", id)
	return 0
}

func runPolicyReject(w io.Writer, storePath, id string) int {
	if err := policy.DeleteEntry(storePath, id); err != nil {
		fmt.Fprintf(w, "doit --policy reject: %v\n", err)
		return 1
	}
	fmt.Fprintf(w, "Rejected: %s (removed)\n", id)
	return 0
}
