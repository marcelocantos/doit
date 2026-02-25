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
			return fmt.Errorf("line %d: prev_hash mismatch: expected %s, got %s", i+1, expectedPrev[:16]+"...", entry.PrevHash[:16]+"...")
		}

		// Recompute and check hash.
		computed := computeHash(entry)
		if entry.Hash != computed {
			return fmt.Errorf("line %d: hash mismatch: expected %s, got %s", i+1, computed[:16]+"...", entry.Hash[:16]+"...")
		}

		expectedPrev = entry.Hash
		prevSeq = entry.Seq
	}

	return nil
}

// Tail returns the last n entries from the audit log.
func Tail(path string, n int) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	lines := splitLines(data)
	if n > len(lines) {
		n = len(lines)
	}

	entries := make([]Entry, 0, n)
	for _, line := range lines[len(lines)-n:] {
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
