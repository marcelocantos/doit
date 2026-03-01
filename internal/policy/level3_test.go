// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/marcelocantos/doit/internal/cap"
)

type mockPrompter struct {
	response string
	err      error
	called   bool
}

func (m *mockPrompter) Prompt(ctx context.Context, prompt string) (string, error) {
	m.called = true
	return m.response, m.err
}

func TestParseL3Decision(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantDecision Decision
		wantReason   string
		wantErr      bool
	}{
		{
			name:         "valid allow",
			input:        `{"decision":"allow","reasoning":"safe"}`,
			wantDecision: Allow,
			wantReason:   "safe",
		},
		{
			name:         "valid deny",
			input:        `{"decision":"deny","reasoning":"dangerous"}`,
			wantDecision: Deny,
			wantReason:   "dangerous",
		},
		{
			name:         "valid escalate",
			input:        `{"decision":"escalate","reasoning":"unsure"}`,
			wantDecision: Escalate,
			wantReason:   "unsure",
		},
		{
			name:         "markdown fenced json",
			input:        "```json\n{\"decision\":\"allow\",\"reasoning\":\"ok\"}\n```",
			wantDecision: Allow,
			wantReason:   "ok",
		},
		{
			name:         "markdown fenced no language",
			input:        "```\n{\"decision\":\"deny\",\"reasoning\":\"bad\"}\n```",
			wantDecision: Deny,
			wantReason:   "bad",
		},
		{
			name:    "invalid json",
			input:   "not json",
			wantErr: true,
		},
		{
			name:    "invalid decision",
			input:   `{"decision":"maybe","reasoning":"x"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec, reason, err := parseL3Decision(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec != tt.wantDecision {
				t.Errorf("decision = %v, want %v", dec, tt.wantDecision)
			}
			if reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestBuildPrompt(t *testing.T) {
	req := &Request{
		Command: "git push origin master",
		Segments: []Segment{
			{CapName: "git", Args: []string{"push", "origin", "master"}, Tier: cap.TierDangerous},
		},
		Cwd:            "/home/user/project",
		HasRedirectOut: false,
		Justification:  "deploy to production",
		SafetyArg:      "reviewed all commits",
	}

	prompt := buildPrompt(req)

	checks := []string{
		"git push origin master",
		"git",
		"/home/user/project",
		"deploy to production",
		"reviewed all commits",
		"allow",
		"deny",
		"escalate",
	}
	for _, s := range checks {
		if !strings.Contains(prompt, s) {
			t.Errorf("prompt missing %q", s)
		}
	}
}

func TestLevel3EvaluateRetry(t *testing.T) {
	mock := &mockPrompter{}
	l3 := NewLevel3(mock)

	result := l3.Evaluate(context.Background(), &Request{
		Command: "rm -rf .",
		Retry:   true,
	})

	if mock.called {
		t.Error("Prompt should not be called when req.Retry is true")
	}
	if result.Decision != Allow {
		t.Errorf("decision = %v, want Allow", result.Decision)
	}
	if result.Level != 3 {
		t.Errorf("level = %d, want 3", result.Level)
	}
}

func TestLevel3EvaluateAllow(t *testing.T) {
	mock := &mockPrompter{response: `{"decision":"allow","reasoning":"looks safe"}`}
	l3 := NewLevel3(mock)

	result := l3.Evaluate(context.Background(), &Request{
		Command:  "make test",
		Segments: []Segment{{CapName: "make", Args: []string{"test"}, Tier: cap.TierBuild}},
	})

	if result.Decision != Allow {
		t.Errorf("decision = %v, want Allow", result.Decision)
	}
	if result.Level != 3 {
		t.Errorf("level = %d, want 3", result.Level)
	}
	if result.RuleID != "llm-gatekeeper" {
		t.Errorf("ruleID = %q, want llm-gatekeeper", result.RuleID)
	}
}

func TestLevel3EvaluateDeny(t *testing.T) {
	mock := &mockPrompter{response: `{"decision":"deny","reasoning":"too dangerous"}`}
	l3 := NewLevel3(mock)

	result := l3.Evaluate(context.Background(), &Request{
		Command:  "rm important.txt",
		Segments: []Segment{{CapName: "rm", Args: []string{"important.txt"}, Tier: cap.TierDangerous}},
	})

	if result.Decision != Deny {
		t.Errorf("decision = %v, want Deny", result.Decision)
	}
	if result.Level != 3 {
		t.Errorf("level = %d, want 3", result.Level)
	}
}

func TestLevel3EvaluateEscalate(t *testing.T) {
	mock := &mockPrompter{response: `{"decision":"escalate","reasoning":"need more context"}`}
	l3 := NewLevel3(mock)

	result := l3.Evaluate(context.Background(), &Request{
		Command:  "git push --force",
		Segments: []Segment{{CapName: "git", Args: []string{"push", "--force"}, Tier: cap.TierDangerous}},
	})

	if result.Decision != Escalate {
		t.Errorf("decision = %v, want Escalate", result.Decision)
	}
	if result.Level != 3 {
		t.Errorf("level = %d, want 3", result.Level)
	}
}

func TestLevel3EvaluateLLMError(t *testing.T) {
	mock := &mockPrompter{err: fmt.Errorf("connection refused")}
	l3 := NewLevel3(mock)

	result := l3.Evaluate(context.Background(), &Request{
		Command: "make",
	})

	if result.Decision != Escalate {
		t.Errorf("decision = %v, want Escalate", result.Decision)
	}
	if result.Level != 3 {
		t.Errorf("level = %d, want 3", result.Level)
	}
	if !strings.Contains(result.Reason, "LLM error") {
		t.Errorf("reason %q should contain 'LLM error'", result.Reason)
	}
}

func TestLevel3EvaluateInvalidResponse(t *testing.T) {
	mock := &mockPrompter{response: "garbage response that is not json"}
	l3 := NewLevel3(mock)

	result := l3.Evaluate(context.Background(), &Request{
		Command: "make",
	})

	if result.Decision != Escalate {
		t.Errorf("decision = %v, want Escalate", result.Decision)
	}
	if result.Level != 3 {
		t.Errorf("level = %d, want 3", result.Level)
	}
	if !strings.Contains(result.Reason, "unparseable") {
		t.Errorf("reason %q should contain 'unparseable'", result.Reason)
	}
}
