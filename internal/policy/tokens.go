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
//
// Approved is false for a freshly issued token. Issuing a token is doit
// telling the caller "a human must decide this"; it is a receipt, not a
// capability. Only Approve — driven by a human confirmation outside the
// agent's control — turns the receipt into something Consume will honour
// (ENT-003, 🎯T41).
type TokenEntry struct {
	Command   string
	Args      []string
	CreatedAt time.Time
	ExpiresAt time.Time
	Approved  bool
}

// ErrAwaitingApproval is returned for a token that exists and matches its
// command but that no human has approved yet.
var ErrAwaitingApproval = errors.New("approval token is awaiting human approval")

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

// Approve records the human decision that authorises a token. It is the
// only transition from receipt to capability, and callers must drive it
// from a confirmation the agent cannot forge.
func (s *TokenStore) Approve(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.purgeLocked(time.Now())
	entry, ok := s.tokens[token]
	if !ok {
		return errors.New("unknown or expired approval token")
	}
	entry.Approved = true
	return nil
}

// Check validates a token without consuming it. Dry-run evaluation and
// the doit_approve confirmation both need to know whether a token is
// good without burning the single use the real execution needs
// (ENT-003, 🎯T46/🎯T47).
func (s *TokenStore) Check(token string, args []string) (*TokenEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkLocked(token, args)
}

// Consume validates a token and, only when it is valid and approved,
// spends it. A rejected token is left in place so that a replay reports
// the same reason rather than degrading to "unknown token".
func (s *TokenStore) Consume(token string, args []string) (*TokenEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, err := s.checkLocked(token, args)
	if err != nil {
		return nil, err
	}
	delete(s.tokens, token)
	return entry, nil
}

// checkLocked implements Check. The caller holds s.mu.
func (s *TokenStore) checkLocked(token string, args []string) (*TokenEntry, error) {
	now := time.Now()
	s.purgeLocked(now)

	entry, ok := s.tokens[token]
	if !ok {
		return nil, errors.New("unknown or expired approval token")
	}
	if now.After(entry.ExpiresAt) {
		delete(s.tokens, token)
		return nil, errors.New("approval token expired")
	}
	if !slices.Equal(args, entry.Args) {
		return nil, errors.New("approval token args mismatch")
	}
	if !entry.Approved {
		return nil, ErrAwaitingApproval
	}
	return entry, nil
}

// Purge removes all expired tokens from the store.
func (s *TokenStore) Purge() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(time.Now())
}

// purgeLocked drops expired tokens. The caller holds s.mu.
func (s *TokenStore) purgeLocked(now time.Time) {
	for token, entry := range s.tokens {
		if now.After(entry.ExpiresAt) {
			delete(s.tokens, token)
		}
	}
}
