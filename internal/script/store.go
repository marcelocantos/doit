// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package script

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Approval records a user-approved script hash. Identity is by Hash alone;
// PathHint is stored for display and audit context only.
type Approval struct {
	Hash          string    `yaml:"hash"`
	PathHint      string    `yaml:"path_hint,omitempty"`
	ApprovedAt    time.Time `yaml:"approved_at"`
	LastUsedAt    time.Time `yaml:"last_used_at,omitempty"`
	UsageCount    int       `yaml:"usage_count"`
	Justification string    `yaml:"justification,omitempty"`
}

type storeFile struct {
	Approvals []Approval `yaml:"approvals"`
}

// Store is a file-backed set of approved script hashes. It is safe for
// concurrent use within a single process; concurrent modification from
// multiple processes is avoided by atomic replace on save, but a lost
// update is possible across processes (acceptable: approvals are rare).
type Store struct {
	path string
	mu   sync.Mutex
}

// DefaultStorePath returns the default path for the approval store.
func DefaultStorePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "doit", "script-approvals.yaml")
}

// NewStore returns a Store backed by path. The file need not exist yet;
// it will be created on first write.
func NewStore(path string) *Store {
	if path == "" {
		path = DefaultStorePath()
	}
	return &Store{path: path}
}

// Path returns the backing file path.
func (s *Store) Path() string { return s.path }

// Load reads all approvals from disk. Returns an empty slice if the
// store file does not yet exist.
func (s *Store) Load() ([]Approval, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read approval store: %w", err)
	}
	var sf storeFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parse approval store %s: %w", s.path, err)
	}
	return sf.Approvals, nil
}

// Lookup returns the approval for hash, or nil if none exists.
func (s *Store) Lookup(hash string) (*Approval, error) {
	entries, err := s.Load()
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].Hash == hash {
			return &entries[i], nil
		}
	}
	return nil, nil
}

// Approve records an approval for hash, upserting if an entry already
// exists (which can happen if the caller races two approvals for the
// same content). Returns the persisted entry.
func (s *Store) Approve(hash, pathHint, justification string) (*Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.Load()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	for i := range entries {
		if entries[i].Hash == hash {
			entries[i].PathHint = pathHint
			if justification != "" {
				entries[i].Justification = justification
			}
			if entries[i].ApprovedAt.IsZero() {
				entries[i].ApprovedAt = now
			}
			if err := s.save(entries); err != nil {
				return nil, err
			}
			result := entries[i]
			return &result, nil
		}
	}

	entry := Approval{
		Hash:          hash,
		PathHint:      pathHint,
		ApprovedAt:    now,
		Justification: justification,
	}
	entries = append(entries, entry)
	if err := s.save(entries); err != nil {
		return nil, err
	}
	return &entry, nil
}

// RecordUse increments the usage counter and updates LastUsedAt for an
// approval. Silently succeeds if the approval is not found — the caller
// has already decided to let the command run, and a missing entry
// should not block execution.
func (s *Store) RecordUse(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.Load()
	if err != nil {
		return err
	}
	for i := range entries {
		if entries[i].Hash == hash {
			entries[i].LastUsedAt = time.Now().UTC()
			entries[i].UsageCount++
			return s.save(entries)
		}
	}
	return nil
}

// Revoke removes the approval with the given hash. Returns an error if
// no such approval exists.
func (s *Store) Revoke(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.Load()
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.Hash == hash {
			remaining := append(entries[:i:i], entries[i+1:]...)
			return s.save(remaining)
		}
	}
	return fmt.Errorf("no approval for hash %s", hash)
}

// List returns all approvals in approval-time order.
func (s *Store) List() ([]Approval, error) {
	return s.Load()
}

func (s *Store) save(entries []Approval) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create approval store dir: %w", err)
	}
	data, err := yaml.Marshal(storeFile{Approvals: entries})
	if err != nil {
		return fmt.Errorf("marshal approval store: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".script-approvals-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp approval file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp approval file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp approval file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp approval file: %w", err)
	}
	return nil
}
