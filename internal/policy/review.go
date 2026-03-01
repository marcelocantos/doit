// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import "time"

// Spaced repetition intervals indexed by review count.
// 1 week → 2 weeks → 1 month → 2 months → 4 months (cap).
var reviewIntervals = []time.Duration{
	7 * 24 * time.Hour,   // 0 reviews → next in 1 week
	14 * 24 * time.Hour,  // 1 review  → next in 2 weeks
	30 * 24 * time.Hour,  // 2 reviews → next in 1 month
	60 * 24 * time.Hour,  // 3 reviews → next in 2 months
	120 * 24 * time.Hour, // 4+ reviews → next in 4 months (cap)
}

// NextReviewInterval returns the time until the next review based on how
// many reviews have been completed.
func NextReviewInterval(reviewCount int) time.Duration {
	if reviewCount < 0 {
		reviewCount = 0
	}
	if reviewCount >= len(reviewIntervals) {
		return reviewIntervals[len(reviewIntervals)-1]
	}
	return reviewIntervals[reviewCount]
}

// NextReviewTime returns the absolute time of the next review.
func NextReviewTime(lastReviewed time.Time, reviewCount int) time.Time {
	return lastReviewed.Add(NextReviewInterval(reviewCount))
}

// NeedsReview reports whether the next review time has passed.
func NeedsReview(nextReview time.Time) bool {
	return time.Now().After(nextReview)
}
