// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package audit

import "time"

// Entry represents a single audit log record.
type Entry struct {
	Seq           uint64    `json:"seq"`
	Time          time.Time `json:"ts"`
	PrevHash      string    `json:"prev_hash"`
	Pipeline      string    `json:"pipeline"`                  // raw pipeline description
	Segments      []string  `json:"segments"`                  // capability names
	Tiers         []string  `json:"tiers"`                     // tier of each segment
	Retry         bool      `json:"retry,omitempty"`           // true if --retry was used
	ExitCode      int       `json:"exit_code"`                 // 0 = success
	Error         string    `json:"error,omitempty"`           // error message if failed
	Duration      float64   `json:"duration_ms"`               // execution time in milliseconds
	ExpectedDuration float64 `json:"expected_duration_ms,omitempty"` // agent's estimated duration (0 = unspecified)
	TimedOut      bool      `json:"timed_out,omitempty"`       // true when the process was killed by timeout
	Cwd           string    `json:"cwd"`                       // working directory
	PolicyLevel   int       `json:"policy_level,omitempty"`    // 1, 2, or 3
	PolicyResult  string    `json:"policy_result,omitempty"`   // "allow", "deny", "escalate"
	PolicyRuleID  string    `json:"policy_rule_id,omitempty"`  // which rule matched
	Justification string    `json:"justification,omitempty"`   // worker's justification
	SafetyArg     string    `json:"safety_arg,omitempty"`      // worker's safety argument
	ScriptHash    string    `json:"script_hash,omitempty"`     // sha256:... when gated by script-hash approval
	ScriptPath    string    `json:"script_path,omitempty"`     // resolved script path for script-hash events
	Hash          string    `json:"hash"`                      // SHA-256 of this entry (with hash field empty)
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
}
