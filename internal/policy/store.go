// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// storeMu serializes in-process read-modify-write of the learned-policy store.
// AppendEntries/UpdateEntry/DeleteEntry each do LoadStore -> mutate -> SaveStore;
// SaveStore's temp-file+atomic-rename prevents torn files but NOT lost updates —
// two concurrent writers each rename their own stale snapshot and the last one
// wins, silently dropping the other's entry (Fable-5 F7 / 🎯T44). A single
// process-wide mutex plus an advisory file lock (see flockStore) closes both the
// in-process and cross-process races.
var storeMu sync.Mutex

// withStoreLock runs fn while holding both the in-process store mutex and a
// cross-process advisory file lock, so the enclosed LoadStore+SaveStore span is
// atomic with respect to every other store mutation.
func withStoreLock(path string, fn func() error) error {
	storeMu.Lock()
	defer storeMu.Unlock()

	unlock, err := flockStore(path)
	if err != nil {
		return err
	}
	defer unlock()

	return fn()
}

// PolicyEntry is a single learned policy rule.
type PolicyEntry struct {
	ID          string        `yaml:"id"`
	Description string        `yaml:"description"`
	Match       MatchCriteria `yaml:"match"`
	Decision    string        `yaml:"decision"`    // "allow", "deny", "escalate"
	Reasoning   string        `yaml:"reasoning"`   // why this decision was made
	Confidence  string        `yaml:"confidence"`   // "high", "medium", "low"
	Provenance  string        `yaml:"provenance"`   // "human", "gatekeeper"
	Approved    bool          `yaml:"approved"`
	Review      ReviewSchedule `yaml:"review"`
}

// MatchCriteria defines what a policy entry matches against.
type MatchCriteria struct {
	Cap      string   `yaml:"cap"`
	Subcmd   string   `yaml:"subcmd,omitempty"`
	HasFlags []string `yaml:"has_flags,omitempty"`
	NoFlags  []string `yaml:"no_flags,omitempty"`
	ArgsGlob []string `yaml:"args_glob,omitempty"`
}

// ReviewSchedule tracks spaced repetition review state.
type ReviewSchedule struct {
	Created      time.Time `yaml:"created"`
	LastReviewed time.Time `yaml:"last_reviewed"`
	ReviewCount  int       `yaml:"review_count"`
	NextReview   time.Time `yaml:"next_review"`
}

// storeFile is the top-level YAML structure.
type storeFile struct {
	Entries []PolicyEntry `yaml:"entries"`
}

// DefaultStorePath returns the default path for the learned policy store.
func DefaultStorePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "doit", "learned-policy.yaml")
}

// LoadStore reads policy entries from YAML. Returns an empty slice (not error)
// if the file doesn't exist.
func LoadStore(path string) ([]PolicyEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read learned policy: %w", err)
	}

	var sf storeFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parse learned policy %s: %w", path, err)
	}

	for i, e := range sf.Entries {
		if e.ID == "" {
			return nil, fmt.Errorf("learned policy %s: entry %d: missing id", path, i)
		}
		if e.Match.Cap == "" {
			return nil, fmt.Errorf("learned policy %s: entry %q: match.cap is required", path, e.ID)
		}
		if err := validateDecision(e.Decision); err != nil {
			return nil, fmt.Errorf("learned policy %s: entry %q: %w", path, e.ID, err)
		}
	}

	return sf.Entries, nil
}

func validateDecision(s string) error {
	switch s {
	case "allow", "deny", "escalate":
		return nil
	default:
		return fmt.Errorf("invalid decision %q (want allow, deny, or escalate)", s)
	}
}

// SaveStore writes policy entries to path atomically using a temp file + rename.
// Parent directories are created if they don't exist.
func SaveStore(path string, entries []PolicyEntry) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create policy store dir: %w", err)
	}

	data, err := yaml.Marshal(storeFile{Entries: entries})
	if err != nil {
		return fmt.Errorf("marshal policy store: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".learned-policy-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp policy file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp policy file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp policy file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp policy file: %w", err)
	}
	return nil
}

// AppendEntries adds newEntries to the store at path, skipping any whose ID
// already exists. Returns the count of entries actually added.
func AppendEntries(path string, newEntries []PolicyEntry) (int, error) {
	var added int
	err := withStoreLock(path, func() error {
		existing, err := LoadStore(path)
		if err != nil {
			return err
		}

		seen := make(map[string]bool, len(existing))
		for _, e := range existing {
			seen[e.ID] = true
		}

		added = 0
		for _, e := range newEntries {
			if !seen[e.ID] {
				existing = append(existing, e)
				seen[e.ID] = true
				added++
			}
		}

		return SaveStore(path, existing)
	})
	if err != nil {
		return 0, err
	}
	return added, nil
}

// UpdateEntry loads the store, applies fn to the entry with the given id, and
// saves. Returns an error if the id is not found.
func UpdateEntry(path string, id string, fn func(*PolicyEntry)) error {
	return withStoreLock(path, func() error {
		entries, err := LoadStore(path)
		if err != nil {
			return err
		}

		for i := range entries {
			if entries[i].ID == id {
				fn(&entries[i])
				return SaveStore(path, entries)
			}
		}
		return fmt.Errorf("policy entry %q: not found", id)
	})
}

// DeleteEntry removes the entry with the given id from the store. Returns an
// error if the id is not found.
func DeleteEntry(path string, id string) error {
	return withStoreLock(path, func() error {
		entries, err := LoadStore(path)
		if err != nil {
			return err
		}

		for i, e := range entries {
			if e.ID == id {
				remaining := append(entries[:i:i], entries[i+1:]...)
				return SaveStore(path, remaining)
			}
		}
		return fmt.Errorf("policy entry %q: not found", id)
	})
}

// ParseDecision converts a decision string to a Decision enum.
func ParseDecision(s string) (Decision, error) {
	switch s {
	case "allow":
		return Allow, nil
	case "deny":
		return Deny, nil
	case "escalate":
		return Escalate, nil
	default:
		return 0, fmt.Errorf("invalid decision %q", s)
	}
}
