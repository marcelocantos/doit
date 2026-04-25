// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package audit

import "time"

// L3Evidence records the chain-of-evidence for a single L3 LLM invocation.
type L3Evidence struct {
	Model                 string  `json:"model"`
	Prompt                string  `json:"prompt"`
	Response              string  `json:"response"`
	LatencyMs             float64 `json:"latency_ms"`
	Decision              string  `json:"decision"`
	Reason                string  `json:"reason,omitempty"`
	Truncated             bool    `json:"truncated,omitempty"`
	OriginalPromptBytes   int     `json:"original_prompt_bytes,omitempty"`
	OriginalResponseBytes int     `json:"original_response_bytes,omitempty"`
}

// Entry represents a single audit log record.
type Entry struct {
	Seq              uint64    `json:"seq"`
	Time             time.Time `json:"ts"`
	PrevHash         string    `json:"prev_hash"`
	Pipeline         string    `json:"pipeline"`                       // raw pipeline description
	Segments         []string  `json:"segments"`                       // capability names
	Tiers            []string  `json:"tiers"`                          // tier of each segment
	Retry            bool      `json:"retry,omitempty"`                // true if --retry was used
	ExitCode         int       `json:"exit_code"`                      // 0 = success
	Error            string    `json:"error,omitempty"`                // error message if failed
	Duration         float64   `json:"duration_ms"`                    // execution time in milliseconds
	ExpectedDuration float64   `json:"expected_duration_ms,omitempty"` // agent's estimated duration (0 = unspecified)
	TimedOut         bool      `json:"timed_out,omitempty"`            // true when the process was killed by timeout
	Cwd              string    `json:"cwd"`                            // working directory
	ProjectRoot      string    `json:"project_root,omitempty"`         // normalised project root path (for duration keying)
	PolicyLevel      int       `json:"policy_level,omitempty"`         // 1, 2, or 3
	PolicyResult     string    `json:"policy_result,omitempty"`        // "allow", "deny", "escalate", or elicitation choice
	PolicyRuleID     string    `json:"policy_rule_id,omitempty"`       // which rule matched
	Justification    string    `json:"justification,omitempty"`        // worker's justification
	SafetyArg        string    `json:"safety_arg,omitempty"`           // worker's safety argument
	ScriptHash       string    `json:"script_hash,omitempty"`          // sha256:... when gated by script-hash approval
	ScriptPath       string    `json:"script_path,omitempty"`          // resolved script path for script-hash events

	L3Fast *L3Evidence `json:"l3_fast,omitempty"` // chain-of-evidence for fast-tier L3 invocation
	L3Deep *L3Evidence `json:"l3_deep,omitempty"` // chain-of-evidence for deep-tier L3 invocation (when cascade fires)

	// Elicitation fields. Phase 1 entries record the policy decision shown
	// to the user; Phase 2 entries record the rule promotion offered after
	// an "always" choice. Both link back to the originating command via
	// ParentSeq.
	ParentSeq              uint64  `json:"parent_seq,omitempty"`
	ElicitationPrompt      string  `json:"elicitation_prompt,omitempty"`
	ElicitationChoice      string  `json:"elicitation_choice,omitempty"`
	ElicitationLatencyMs   float64 `json:"elicitation_latency_ms,omitempty"`
	ProposedRuleSource     string  `json:"proposed_rule_source,omitempty"`
	ProposedRuleGenerality string  `json:"proposed_rule_generality,omitempty"`
	ProposedRuleID         string  `json:"proposed_rule_id,omitempty"`

	Hash string `json:"hash"` // SHA-256 of this entry (with hash field empty)
}

// LogOptions carries optional metadata for audit entries.
type LogOptions struct {
	PolicyLevel      int
	PolicyResult     string
	PolicyRuleID     string
	Justification    string
	SafetyArg        string
	ScriptHash       string
	ScriptPath       string
	ExpectedDuration float64 // milliseconds; 0 = unspecified
	TimedOut         bool
	ProjectRoot      string  // normalised project root path (for duration keying)

	L3Fast *L3Evidence
	L3Deep *L3Evidence

	ParentSeq              uint64
	ElicitationPrompt      string
	ElicitationChoice      string
	ElicitationLatencyMs   float64
	ProposedRuleSource     string
	ProposedRuleGenerality string
	ProposedRuleID         string
}
