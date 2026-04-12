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

// SessionPrompter extends Prompter with session-aware prompting that
// skips context clearing between evaluations.
type SessionPrompter interface {
	Prompter
	PromptWithinSession(ctx context.Context, prompt string) (string, error)
}

// Level3 evaluates commands by asking an LLM gatekeeper. It supports a
// two-tier cascade: a fast model (sonnet) handles obvious cases, and a
// deep model (opus) handles uncertain ones. If only one client is provided,
// it acts as both tiers.
type Level3 struct {
	fast Prompter // fast triage (sonnet) — required
	deep Prompter // deep reasoning (opus) — optional, falls back to fast
}

// NewLevel3 creates a Level3 engine. If deep is nil, fast handles everything.
func NewLevel3(fast Prompter, deep ...Prompter) *Level3 {
	l := &Level3{fast: fast}
	if len(deep) > 0 && deep[0] != nil {
		l.deep = deep[0]
	}
	return l
}

// SessionContext provides work session information for L3 evaluation.
type SessionContext struct {
	Scope       string // declared scope of the work session
	Description string // what the worker is doing
}

// Evaluate asks the LLM whether to allow, deny, or escalate the request.
// If req.Retry is true, the command is allowed immediately without an LLM call.
func (l *Level3) Evaluate(ctx context.Context, req *Request) *Result {
	return l.evaluate(ctx, req, nil)
}

// EvaluateInSession is like Evaluate but prepends the active work
// session's scope and description to every prompt (via
// buildSessionPrefix) so the gatekeeper has the context it needs to
// make scope-aware decisions.
func (l *Level3) EvaluateInSession(ctx context.Context, req *Request, session *SessionContext) *Result {
	return l.evaluate(ctx, req, session)
}

func (l *Level3) evaluate(ctx context.Context, req *Request, session *SessionContext) *Result {
	if req.Retry {
		return &Result{
			Decision: Allow,
			Level:    3,
			Reason:   "--retry bypasses Level 3",
		}
	}

	// Tier 1: fast model triage.
	fastResult := l.callLLM(ctx, req, session, l.fast, true)
	if fastResult.Decision != Escalate {
		// Fast model was confident — use its decision.
		return fastResult
	}

	// Tier 2: deep model for uncertain cases.
	if l.deep != nil {
		return l.callLLM(ctx, req, session, l.deep, false)
	}

	// No deep model — return the fast model's escalation.
	return fastResult
}

func (l *Level3) callLLM(ctx context.Context, req *Request, session *SessionContext, client Prompter, fast bool) *Result {
	prompt := buildPrompt(req, fast)
	if session != nil {
		prompt = buildSessionPrefix(session) + prompt
	}

	var (
		raw string
		err error
	)
	if session != nil {
		if sp, ok := client.(SessionPrompter); ok {
			raw, err = sp.PromptWithinSession(ctx, prompt)
		} else {
			raw, err = client.Prompt(ctx, prompt)
		}
	} else {
		raw, err = client.Prompt(ctx, prompt)
	}

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

	ruleID := "llm-gatekeeper"
	if session != nil {
		ruleID = "llm-gatekeeper-session"
	}
	if fast {
		ruleID += "-fast"
	}

	return &Result{
		Decision:   dec,
		Level:      3,
		Reason:     reasoning,
		RuleID:     ruleID,
		Bypassable: true,
	}
}

// buildSessionPrefix creates an instruction prefix for session-aware evaluation.
func buildSessionPrefix(session *SessionContext) string {
	var sb strings.Builder
	sb.WriteString("WORK SESSION CONTEXT:\n")
	fmt.Fprintf(&sb, "  Scope: %s\n", session.Scope)
	if session.Description != "" {
		fmt.Fprintf(&sb, "  Description: %s\n", session.Description)
	}
	sb.WriteString("  Instructions: Commands that clearly fall within the declared scope should be ")
	sb.WriteString("allowed without further analysis. Only escalate commands that seem outside the ")
	sb.WriteString("scope or potentially dangerous beyond the scope's intent.\n\n")
	return sb.String()
}

// buildPrompt constructs the prompt sent to the LLM. When fast is true,
// the prompt instructs the model to only decide when highly confident
// and escalate anything uncertain — the deep model will handle those.
func buildPrompt(req *Request, fast bool) string {
	var sb strings.Builder

	sb.WriteString("You are a security gatekeeper for a command execution broker. ")
	sb.WriteString("Evaluate whether this command should be allowed, denied, or escalated.\n\n")

	if fast {
		sb.WriteString("IMPORTANT: You are the fast triage tier. Only decide (allow or deny) ")
		sb.WriteString("when you are highly confident. If there is any ambiguity, nuance, or ")
		sb.WriteString("context-dependence, respond with escalate — a more capable model will ")
		sb.WriteString("handle the decision. Err on the side of escalating.\n\n")
	}

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
	if req.Cwd != "" {
		fmt.Fprintf(&sb, "  Working directory: %s\n", req.Cwd)
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
