// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Prompter abstracts the LLM call for testability.
type Prompter interface {
	Prompt(ctx context.Context, prompt string) (string, error)
}

// Level3 evaluates commands by asking an LLM gatekeeper.
type Level3 struct {
	client Prompter
}

// NewLevel3 creates a Level3 engine using the given Prompter.
func NewLevel3(client Prompter) *Level3 {
	return &Level3{client: client}
}

// Evaluate asks the LLM whether to allow, deny, or escalate the request.
// If req.Retry is true, the command is allowed immediately without an LLM call.
func (l *Level3) Evaluate(ctx context.Context, req *Request) *Result {
	if req.Retry {
		return &Result{
			Decision: Allow,
			Level:    3,
			Reason:   "--retry bypasses Level 3",
		}
	}

	prompt := buildPrompt(req)
	raw, err := l.client.Prompt(ctx, prompt)
	if err != nil {
		return &Result{
			Decision: Escalate,
			Level:    3,
			Reason:   fmt.Sprintf("LLM error: %v", err),
		}
	}

	dec, reasoning, err := parseL3Decision(raw)
	if err != nil {
		return &Result{
			Decision: Escalate,
			Level:    3,
			Reason:   fmt.Sprintf("unparseable LLM response: %v", err),
		}
	}

	return &Result{
		Decision: dec,
		Level:    3,
		Reason:   reasoning,
		RuleID:   "llm-gatekeeper",
	}
}

// buildPrompt constructs the prompt sent to the LLM.
func buildPrompt(req *Request) string {
	var sb strings.Builder

	sb.WriteString("You are a security gatekeeper for a command execution broker. ")
	sb.WriteString("Evaluate whether this command should be allowed, denied, or escalated to a human.\n\n")

	sb.WriteString("Safety tiers (from least to most dangerous):\n")
	sb.WriteString("  read      — read-only operations (grep, cat, find, ls)\n")
	sb.WriteString("  build     — build/compile operations (make, go build)\n")
	sb.WriteString("  write     — file mutations (cp, mv, mkdir, tee)\n")
	sb.WriteString("  dangerous — destructive operations (rm, chmod, git push)\n\n")

	sb.WriteString("Decision options:\n")
	sb.WriteString("  allow    — command is safe to proceed\n")
	sb.WriteString("  deny     — command is clearly dangerous or harmful\n")
	sb.WriteString("  escalate — uncertain, needs human review\n\n")

	sb.WriteString("Command details:\n")
	fmt.Fprintf(&sb, "  Command: %s\n", req.Command)
	if len(req.Segments) > 0 {
		sb.WriteString("  Segments:\n")
		for _, seg := range req.Segments {
			fmt.Fprintf(&sb, "    - %s (tier: %s)", seg.CapName, seg.Tier.String())
			if len(seg.Args) > 0 {
				fmt.Fprintf(&sb, " args: %v", seg.Args)
			}
			sb.WriteString("\n")
		}
	}
	if req.Cwd != "" {
		fmt.Fprintf(&sb, "  Working directory: %s\n", req.Cwd)
	}
	if req.HasRedirectOut {
		sb.WriteString("  Output redirect: yes\n")
	}
	if req.Justification != "" {
		fmt.Fprintf(&sb, "  Worker justification: %s\n", req.Justification)
	}
	if req.SafetyArg != "" {
		fmt.Fprintf(&sb, "  Worker safety argument: %s\n", req.SafetyArg)
	}

	sb.WriteString("\nRespond with JSON only:\n")
	sb.WriteString(`{"decision": "allow|deny|escalate", "reasoning": "brief explanation"}`)
	sb.WriteString("\n")

	return sb.String()
}

// parseL3Decision parses the LLM's JSON response into a Decision and reasoning.
// Strips markdown code fences if present.
func parseL3Decision(raw string) (Decision, string, error) {
	s := strings.TrimSpace(raw)

	// Strip markdown code fences (```json ... ``` or ``` ... ```).
	if strings.HasPrefix(s, "```") {
		// Find end of opening fence line.
		end := strings.Index(s, "\n")
		if end == -1 {
			return 0, "", fmt.Errorf("malformed code fence")
		}
		s = s[end+1:]
		// Strip closing fence.
		if idx := strings.LastIndex(s, "```"); idx != -1 {
			s = s[:idx]
		}
		s = strings.TrimSpace(s)
	}

	var payload struct {
		Decision  string `json:"decision"`
		Reasoning string `json:"reasoning"`
	}
	if err := json.Unmarshal([]byte(s), &payload); err != nil {
		return 0, "", fmt.Errorf("invalid JSON: %w", err)
	}

	dec, err := ParseDecision(payload.Decision)
	if err != nil {
		return 0, "", err
	}

	return dec, payload.Reasoning, nil
}
