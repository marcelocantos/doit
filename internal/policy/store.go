// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

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
