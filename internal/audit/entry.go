package audit

import "time"

// Entry represents a single audit log record.
type Entry struct {
	Seq      uint64    `json:"seq"`
	Time     time.Time `json:"ts"`
	PrevHash string    `json:"prev_hash"`
	Pipeline string    `json:"pipeline"`           // raw pipeline description
	Segments []string  `json:"segments"`            // capability names
	Tiers    []string  `json:"tiers"`               // tier of each segment
	ExitCode int       `json:"exit_code"`           // 0 = success
	Error    string    `json:"error,omitempty"`      // error message if failed
	Duration float64   `json:"duration_ms"`          // execution time in milliseconds
	Cwd      string    `json:"cwd"`                 // working directory
	Hash     string    `json:"hash"`                // SHA-256 of this entry (with hash field empty)
}
