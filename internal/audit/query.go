// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// Filter defines criteria for selecting audit log entries. Zero-value fields
// are ignored (i.e. all entries match on that field).
type Filter struct {
	PolicyLevel      int
	PolicyResult     string
	RuleID           string
	CwdSubstring     string
	ProjectRoot      string
	After            time.Time
	Before           time.Time
	ExitCode         *int   // nil = any
	Nonzero          bool   // exit_code != 0
	Cap              string // matches any element of segments
	CommandSubstring string // matches against pipeline field
	ParentSeq        uint64 // 0 = any
	Limit            int    // 0 = no limit
}

// Query reads the audit log at path and returns entries matching f. If f is
// nil, all entries are returned. If the file does not exist, nil, nil is
// returned.
//
// v1 implementation note: reads the entire file into memory and filters.
// The audit log is capped at max_size_mb (default 100 MB) so this is
// acceptable. A streaming-backward implementation can replace this if the
// file grows beyond the default cap or if startup latency becomes a concern.
func Query(path string, f *Filter) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	lines := splitLines(data)
	var entries []Entry
	for _, line := range lines {
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if f == nil || matches(entry, f) {
			entries = append(entries, entry)
		}
	}

	if f != nil && f.Limit > 0 && len(entries) > f.Limit {
		// Return the most recent `Limit` entries (tail of the slice, since
		// entries are already in oldest-first order).
		entries = entries[len(entries)-f.Limit:]
	}

	return entries, nil
}

// QueryLatest returns the single most recent entry matching f, or nil if none
// match. The filter's Limit field is ignored — this always returns at most
// one entry.
func QueryLatest(path string, f *Filter) (*Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	lines := splitLines(data)
	// Walk backwards to find the latest matching entry.
	for i := len(lines) - 1; i >= 0; i-- {
		var entry Entry
		if err := json.Unmarshal(lines[i], &entry); err != nil {
			continue
		}
		if f == nil || matches(entry, f) {
			return &entry, nil
		}
	}
	return nil, nil
}

func matches(e Entry, f *Filter) bool {
	if f.PolicyLevel != 0 && e.PolicyLevel != f.PolicyLevel {
		return false
	}
	if f.PolicyResult != "" && e.PolicyResult != f.PolicyResult {
		return false
	}
	if f.RuleID != "" && e.PolicyRuleID != f.RuleID {
		return false
	}
	if f.CwdSubstring != "" && !strings.Contains(e.Cwd, f.CwdSubstring) {
		return false
	}
	if f.ProjectRoot != "" && e.ProjectRoot != f.ProjectRoot {
		return false
	}
	if !f.After.IsZero() && !e.Time.After(f.After) {
		return false
	}
	if !f.Before.IsZero() && !e.Time.Before(f.Before) {
		return false
	}
	if f.ExitCode != nil && e.ExitCode != *f.ExitCode {
		return false
	}
	if f.Nonzero && e.ExitCode == 0 {
		return false
	}
	if f.Cap != "" {
		found := false
		for _, seg := range e.Segments {
			if seg == f.Cap {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.CommandSubstring != "" && !strings.Contains(e.Pipeline, f.CommandSubstring) {
		return false
	}
	if f.ParentSeq != 0 && e.ParentSeq != f.ParentSeq {
		return false
	}
	return true
}
