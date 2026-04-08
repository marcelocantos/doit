// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"os"
	"time"
)

// Filter defines criteria for selecting audit log entries. Zero-value fields
// are ignored (i.e. all entries match on that field).
type Filter struct {
	PolicyLevel  int
	PolicyResult string
	After        time.Time
	Before       time.Time
	Cap          string
}

// Query reads the audit log at path and returns entries matching f. If f is
// nil, all entries are returned. If the file does not exist, nil, nil is
// returned.
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
	return entries, nil
}

func matches(e Entry, f *Filter) bool {
	if f.PolicyLevel != 0 && e.PolicyLevel != f.PolicyLevel {
		return false
	}
	if f.PolicyResult != "" && e.PolicyResult != f.PolicyResult {
		return false
	}
	if !f.After.IsZero() && !e.Time.After(f.After) {
		return false
	}
	if !f.Before.IsZero() && !e.Time.Before(f.Before) {
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
	return true
}
