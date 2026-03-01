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
	Cwd           string    `json:"cwd"`                       // working directory
	PolicyLevel   int       `json:"policy_level,omitempty"`    // 1, 2, or 3
	PolicyResult  string    `json:"policy_result,omitempty"`   // "allow", "deny", "escalate"
	PolicyRuleID  string    `json:"policy_rule_id,omitempty"`  // which rule matched
	Justification string    `json:"justification,omitempty"`   // worker's justification
	SafetyArg     string    `json:"safety_arg,omitempty"`      // worker's safety argument
	Hash          string    `json:"hash"`                      // SHA-256 of this entry (with hash field empty)
}

// LogOptions carries optional metadata for audit entries.
type LogOptions struct {
	PolicyLevel   int
	PolicyResult  string
	PolicyRuleID  string
	Justification string
	SafetyArg     string
}
