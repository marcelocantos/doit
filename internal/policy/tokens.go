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
	// HumanApproved is true only for tokens minted as the result of a human
	// approval decision (IssueApproved). Engine-self-issued escalation tokens
	// (Issue) carry false, so the agent that requested the escalated command
	// cannot replay the very token it was handed to self-approve it
	// (Fable-5 F3 / 🎯T41).
	HumanApproved bool
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

// Issue generates a new NON-human-approved token for the given command and
// args (used by the engine's escalation path, which has no human in the loop).
// A token issued here cannot authorise execution on its own — see the provenance
// check in engine.evaluatePolicy. Returns a hex-encoded 128-bit token string.
func (s *TokenStore) Issue(command string, args []string) (string, error) {
	return s.issue(command, args, false)
}

// IssueApproved generates a token carrying human-approval provenance. Only these
// tokens authorise execution when replayed via the approval flow.
func (s *TokenStore) IssueApproved(command string, args []string) (string, error) {
	return s.issue(command, args, true)
}

func (s *TokenStore) issue(command string, args []string, humanApproved bool) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw[:])

	now := time.Now()
	s.mu.Lock()
	s.tokens[token] = &TokenEntry{
		Command:       command,
		Args:          args,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.ttl),
		HumanApproved: humanApproved,
	}
	s.mu.Unlock()

	return token, nil
}

// Validate checks the token and consumes it (single-use). Returns the entry on success.
// It also purges any expired tokens to keep the store bounded.
func (s *TokenStore) Validate(token string, args []string) (*TokenEntry, error) {
	return s.check(token, args, true)
}

// Peek checks the token WITHOUT consuming it, so a dry-run policy evaluation can
// inspect the same token that the real execution will later consume exactly once
// (Fable-5 F2/F8 · 🎯T46/🎯T47). Returns the entry on success.
func (s *TokenStore) Peek(token string, args []string) (*TokenEntry, error) {
	return s.check(token, args, false)
}

func (s *TokenStore) check(token string, args []string, consume bool) (*TokenEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Purge expired tokens inline (lock already held).
	now := time.Now()
	for tok, entry := range s.tokens {
		if now.After(entry.ExpiresAt) {
			delete(s.tokens, tok)
		}
	}

	entry, ok := s.tokens[token]
	if !ok {
		return nil, errors.New("unknown or expired approval token")
	}

	// A consuming check is single-use regardless of outcome (historical
	// Validate semantics). Peek (consume=false) never deletes, so the token
	// survives a dry-run evaluation to authorise the subsequent execution.
	if consume {
		delete(s.tokens, token)
	}

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
