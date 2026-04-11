// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"testing"
)

func TestNewClaudiaClient(t *testing.T) {
	c := NewClaudiaClient("sonnet", "/tmp", 0)
	if c == nil {
		t.Fatal("NewClaudiaClient returned nil")
	}
	if c.model != "sonnet" {
		t.Errorf("model = %q, want %q", c.model, "sonnet")
	}
	if c.workDir != "/tmp" {
		t.Errorf("workDir = %q, want %q", c.workDir, "/tmp")
	}
}

func TestClaudiaClientPromptWithoutStart(t *testing.T) {
	c := NewClaudiaClient("sonnet", "/tmp", 0)
	_, err := c.Prompt(t.Context(), "hello")
	if err == nil {
		t.Fatal("expected error when session not started")
	}
	if got := err.Error(); got != "claudia session not started" {
		t.Errorf("error = %q, want %q", got, "claudia session not started")
	}
}

func TestClaudiaClientCloseWithoutStart(t *testing.T) {
	c := NewClaudiaClient("sonnet", "/tmp", 0)
	// Close should be safe to call even without Start.
	c.Close()
}

func TestClaudiaClientCloseIdempotent(t *testing.T) {
	c := NewClaudiaClient("sonnet", "/tmp", 0)
	c.Close()
	c.Close() // second close should not panic
}

func TestSystemPromptContent(t *testing.T) {
	// Verify the system prompt contains key gatekeeper instructions.
	checks := []string{
		"security gatekeeper",
		"JSON",
		"allow",
		"deny",
		"escalate",
		"reasoning",
	}
	for _, s := range checks {
		found := false
		for i := range systemPrompt {
			if i+len(s) <= len(systemPrompt) && systemPrompt[i:i+len(s)] == s {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("systemPrompt missing %q", s)
		}
	}
}
