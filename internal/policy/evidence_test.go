// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"strings"
	"testing"
)

// TestEvaluateWithEvidenceSingleTier verifies that a single-tier sonnet
// decision records l3_fast only (l3_deep is nil).
func TestEvaluateWithEvidenceSingleTier(t *testing.T) {
	mock := &mockPrompter{response: `{"decision":"allow","reasoning":"looks safe"}`}
	l3 := NewLevel3(mock)

	result, ev := l3.EvaluateWithEvidence(context.Background(), &Request{
		Command: "make test",
	}, nil, 0)

	if result.Decision != Allow {
		t.Errorf("decision = %v, want Allow", result.Decision)
	}
	if ev == nil {
		t.Fatal("expected non-nil CascadeEvidence")
	}
	if ev.Fast == nil {
		t.Fatal("expected non-nil Fast evidence")
	}
	if ev.Deep != nil {
		t.Errorf("expected nil Deep evidence for single-tier, got %+v", ev.Deep)
	}
	if ev.Fast.Decision != "allow" {
		t.Errorf("Fast.Decision = %q, want 'allow'", ev.Fast.Decision)
	}
	if ev.Fast.Reason != "looks safe" {
		t.Errorf("Fast.Reason = %q, want 'looks safe'", ev.Fast.Reason)
	}
	if ev.Fast.Prompt == "" {
		t.Error("expected non-empty Fast.Prompt")
	}
	if ev.Fast.Response == "" {
		t.Error("expected non-empty Fast.Response")
	}
}

// TestEvaluateWithEvidenceCascade verifies that when the fast tier
// escalates, the deep tier fires and both blocks are recorded.
func TestEvaluateWithEvidenceCascade(t *testing.T) {
	fastMock := &mockPrompter{response: `{"decision":"escalate","reasoning":"unsure"}`}
	deepMock := &mockPrompter{response: `{"decision":"deny","reasoning":"too dangerous"}`}
	l3 := NewLevel3(fastMock, deepMock)

	result, ev := l3.EvaluateWithEvidence(context.Background(), &Request{
		Command: "rm -rf /",
	}, nil, 0)

	if result.Decision != Deny {
		t.Errorf("decision = %v, want Deny", result.Decision)
	}
	if ev == nil {
		t.Fatal("expected non-nil CascadeEvidence")
	}
	if ev.Fast == nil {
		t.Fatal("expected non-nil Fast evidence")
	}
	if ev.Deep == nil {
		t.Fatal("expected non-nil Deep evidence when cascade fires")
	}
	if ev.Fast.Decision != "escalate" {
		t.Errorf("Fast.Decision = %q, want 'escalate'", ev.Fast.Decision)
	}
	if ev.Deep.Decision != "deny" {
		t.Errorf("Deep.Decision = %q, want 'deny'", ev.Deep.Decision)
	}
}

// TestEvaluateWithEvidenceDisabledL3 verifies that when L3 is not
// involved (retry bypass), evidence is nil.
func TestEvaluateWithEvidenceDisabledL3(t *testing.T) {
	mock := &mockPrompter{}
	l3 := NewLevel3(mock)

	result, ev := l3.EvaluateWithEvidence(context.Background(), &Request{
		Command: "rm -rf /",
		Retry:   true,
	}, nil, 0)

	if result.Decision != Allow {
		t.Errorf("decision = %v, want Allow (retry bypass)", result.Decision)
	}
	if ev != nil {
		t.Errorf("expected nil CascadeEvidence for retry bypass, got %+v", ev)
	}
	if mock.called {
		t.Error("Prompt should not be called on retry")
	}
}

// TestEvaluateWithEvidenceTruncation verifies that prompts and responses
// longer than maxChars are truncated with the expected marker.
func TestEvaluateWithEvidenceTruncation(t *testing.T) {
	longResponse := `{"decision":"allow","reasoning":"` + strings.Repeat("x", 200) + `"}`
	mock := &mockPrompter{response: longResponse}
	l3 := NewLevel3(mock)

	_, ev := l3.EvaluateWithEvidence(context.Background(), &Request{
		Command:       "make test",
		Justification: strings.Repeat("a", 50),
	}, nil, 100) // cap at 100 chars

	if ev == nil || ev.Fast == nil {
		t.Fatal("expected evidence")
	}
	if !ev.Fast.Truncated {
		t.Error("expected Truncated=true for prompt or response exceeding cap")
	}
	marker := "[…truncated"
	if !strings.Contains(ev.Fast.Prompt, marker) && !strings.Contains(ev.Fast.Response, marker) {
		t.Errorf("expected truncation marker %q in prompt or response", marker)
	}
	if ev.Fast.OriginalPromptBytes == 0 && ev.Fast.OriginalResponseBytes == 0 {
		t.Error("expected at least one OriginalXxxBytes set when truncated")
	}
}

// TestTruncateField unit-tests the truncation helper directly.
func TestTruncateField(t *testing.T) {
	t.Run("no truncation needed", func(t *testing.T) {
		s := "hello"
		result, orig, trunc := truncateField(s, 100)
		if trunc {
			t.Error("should not be truncated")
		}
		if result != s {
			t.Errorf("result = %q, want %q", result, s)
		}
		if orig != len(s) {
			t.Errorf("orig = %d, want %d", orig, len(s))
		}
	})

	t.Run("truncation applied", func(t *testing.T) {
		s := strings.Repeat("a", 200)
		result, orig, trunc := truncateField(s, 50)
		if !trunc {
			t.Error("should be truncated")
		}
		if orig != 200 {
			t.Errorf("orig = %d, want 200", orig)
		}
		if len(result) > 50+len("[…truncated, total 200 bytes]")+1 {
			t.Errorf("result too long: %d", len(result))
		}
		if !strings.Contains(result, "total 200 bytes") {
			t.Errorf("result %q missing byte count", result)
		}
	})

	t.Run("zero cap means no truncation", func(t *testing.T) {
		s := strings.Repeat("x", 50000)
		result, _, trunc := truncateField(s, 0)
		if trunc {
			t.Error("zero cap should not truncate")
		}
		if result != s {
			t.Error("zero cap should return original string unchanged")
		}
	})
}
