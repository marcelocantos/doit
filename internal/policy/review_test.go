// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"
	"time"
)

func TestNextReviewInterval(t *testing.T) {
	tests := []struct {
		name        string
		reviewCount int
		want        time.Duration
	}{
		{"0 reviews → 1 week", 0, 7 * 24 * time.Hour},
		{"1 review → 2 weeks", 1, 14 * 24 * time.Hour},
		{"2 reviews → 1 month", 2, 30 * 24 * time.Hour},
		{"3 reviews → 2 months", 3, 60 * 24 * time.Hour},
		{"4 reviews → 4 months (cap)", 4, 120 * 24 * time.Hour},
		{"10 reviews → 4 months (still capped)", 10, 120 * 24 * time.Hour},
		{"negative → 1 week", -1, 7 * 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NextReviewInterval(tt.reviewCount)
			if got != tt.want {
				t.Errorf("NextReviewInterval(%d) = %v, want %v", tt.reviewCount, got, tt.want)
			}
		})
	}
}

func TestNextReviewTime(t *testing.T) {
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	got := NextReviewTime(base, 0)
	want := base.Add(7 * 24 * time.Hour)
	if !got.Equal(want) {
		t.Errorf("NextReviewTime = %v, want %v", got, want)
	}
}

func TestNeedsReview(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	if !NeedsReview(past) {
		t.Error("NeedsReview(past) = false, want true")
	}
	if NeedsReview(future) {
		t.Error("NeedsReview(future) = true, want false")
	}
}
