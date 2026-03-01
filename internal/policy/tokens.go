// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"
)

const DefaultTokenTTL = 10 * time.Minute

// TokenEntry holds metadata for an issued approval token.
type TokenEntry struct {
	Command   string
	Args      []string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// TokenStore manages time-limited, single-use approval tokens.
type TokenStore struct {
	mu     sync.Mutex
	tokens map[string]*TokenEntry
	ttl    time.Duration
}

func NewTokenStore(ttl time.Duration) *TokenStore {
	return &TokenStore{
		tokens: make(map[string]*TokenEntry),
		ttl:    ttl,
	}
}

// Issue generates a new approval token for the given command and args.
// Returns a hex-encoded 128-bit random token string.
func (s *TokenStore) Issue(command string, args []string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw[:])

	now := time.Now()
	s.mu.Lock()
	s.tokens[token] = &TokenEntry{
		Command:   command,
		Args:      args,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.mu.Unlock()

	return token, nil
}

// Validate checks the token and consumes it (single-use). Returns the entry on success.
func (s *TokenStore) Validate(token string, args []string) (*TokenEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.tokens[token]
	if !ok {
		return nil, errors.New("unknown or expired approval token")
	}

	// Delete immediately — single use regardless of outcome.
	delete(s.tokens, token)

	if time.Now().After(entry.ExpiresAt) {
		return nil, errors.New("approval token expired")
	}

	if !slices.Equal(args, entry.Args) {
		return nil, errors.New("approval token args mismatch")
	}

	return entry, nil
}

// Purge removes all expired tokens from the store.
func (s *TokenStore) Purge() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, entry := range s.tokens {
		if now.After(entry.ExpiresAt) {
			delete(s.tokens, token)
		}
	}
}
