// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"fmt"
	"os"
)

// Verify reads the audit log and checks the hash chain integrity.
// Returns nil if the chain is valid, or an error describing the first violation.
func Verify(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}

	lines := splitLines(data)
	if len(lines) == 0 {
		return nil // empty log is valid
	}

	expectedPrev := genesisHash()
	var prevSeq uint64

	for i, line := range lines {
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			return fmt.Errorf("line %d: invalid JSON: %w", i+1, err)
		}

		// Check sequence.
		if entry.Seq != prevSeq+1 {
			return fmt.Errorf("line %d: sequence gap: expected %d, got %d", i+1, prevSeq+1, entry.Seq)
		}

		// Check prev_hash chain.
		if entry.PrevHash != expectedPrev {
			return fmt.Errorf("line %d: prev_hash mismatch: expected %s, got %s", i+1, hashPrefix(expectedPrev), hashPrefix(entry.PrevHash))
		}

		// Recompute and check hash.
		computed := computeHash(entry)
		if entry.Hash != computed {
			return fmt.Errorf("line %d: hash mismatch: expected %s, got %s", i+1, hashPrefix(computed), hashPrefix(entry.Hash))
		}

		expectedPrev = entry.Hash
		prevSeq = entry.Seq
	}

	return nil
}

// hashPrefixLen is how many hex characters of a hash are shown in
// Verify's error messages.
const hashPrefixLen = 16

// hashPrefix abbreviates a hash for display. Hash fields come from
// untrusted log lines and may be empty or short, so never slice them
// blindly (🎯T42).
func hashPrefix(h string) string {
	if h == "" {
		return "<empty>"
	}
	if len(h) <= hashPrefixLen {
		return h
	}
	return h[:hashPrefixLen] + "..."
}

// Tail returns the last n entries from the audit log.
// Malformed entries are skipped; a non-nil error is returned if any were
// encountered, allowing callers to surface a warning to the user.
func Tail(path string, n int) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	lines := splitLines(data)
	if n > len(lines) {
		n = len(lines)
	}

	var skipped int
	entries := make([]Entry, 0, n)
	for _, line := range lines[len(lines)-n:] {
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			skipped++
			continue
		}
		entries = append(entries, entry)
	}
	if skipped > 0 {
		return entries, fmt.Errorf("skipped %d malformed audit log entries", skipped)
	}
	return entries, nil
}
