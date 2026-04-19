// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"
	"testing"
)

func TestCheckDurationMismatch(t *testing.T) {
	l1 := defaultLevel1()

	cases := []struct {
		name      string
		command   string
		expected  int
		wantDeny  bool
		wantRule  string
		wantMatch string
	}{
		{
			name:      "sleep far exceeds expected",
			command:   "sleep 3600",
			expected:  5,
			wantDeny:  true,
			wantRule:  "flag-duration-mismatch",
			wantMatch: "exceeds declared expected_duration_seconds=5",
		},
		{
			name:     "sleep within threshold",
			command:  "sleep 10",
			expected: 10,
			wantDeny: false,
		},
		{
			name:     "sleep exactly at 2x threshold — do not flag",
			command:  "sleep 20",
			expected: 10,
			wantDeny: false,
		},
		{
			name:     "sleep one past 2x threshold — flag",
			command:  "sleep 21",
			expected: 10,
			wantDeny: true,
		},
		{
			name:     "no expectation — silent",
			command:  "sleep 9999",
			expected: 0,
			wantDeny: false,
		},
		{
			name:     "non-sleep command — silent",
			command:  "make test",
			expected: 1,
			wantDeny: false,
		},
		{
			name:     "sleep with non-integer arg — silent",
			command:  "sleep infinity",
			expected: 1,
			wantDeny: false,
		},
		{
			name:     "sleep with shell composition — still flagged",
			command:  "sleep 3600 && echo done",
			expected: 5,
			wantDeny: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := l1.Evaluate(&Request{
				Command:                 tc.command,
				ExpectedDurationSeconds: tc.expected,
			})
			if tc.wantDeny {
				if res.Decision != Deny {
					t.Fatalf("decision: got %v, want Deny; reason=%q", res.Decision, res.Reason)
				}
				if tc.wantRule != "" && res.RuleID != tc.wantRule {
					t.Errorf("rule ID: got %q, want %q", res.RuleID, tc.wantRule)
				}
				if tc.wantMatch != "" && !strings.Contains(res.Reason, tc.wantMatch) {
					t.Errorf("reason: got %q, want substring %q", res.Reason, tc.wantMatch)
				}
				if !res.Bypassable {
					t.Error("rule should be bypassable")
				}
			} else {
				if res.Decision == Deny && res.RuleID == "flag-duration-mismatch" {
					t.Errorf("unexpectedly flagged: %+v", res)
				}
			}
		})
	}
}

func TestCheckDurationMismatch_BypassableWithRetry(t *testing.T) {
	l1 := defaultLevel1()
	res := l1.Evaluate(&Request{
		Command:                 "sleep 3600",
		ExpectedDurationSeconds: 5,
		Retry:                   true,
	})
	if res.Decision == Deny && res.RuleID == "flag-duration-mismatch" {
		t.Errorf("retry should bypass the mismatch rule, got %+v", res)
	}
}
