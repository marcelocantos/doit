// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTokenIssueAndValidate(t *testing.T) {
	store := NewTokenStore(DefaultTokenTTL)
	args := []string{"push", "--force"}
	token, err := store.Issue("git push", args)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Approve(token); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	entry, err := store.Consume(token, args)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if entry.Command != "git push" {
		t.Errorf("Command = %q, want %q", entry.Command, "git push")
	}
	if len(entry.Args) != 2 || entry.Args[0] != "push" || entry.Args[1] != "--force" {
		t.Errorf("Args = %v, want [push --force]", entry.Args)
	}
}

func TestTokenSingleUse(t *testing.T) {
	store := NewTokenStore(DefaultTokenTTL)
	args := []string{"push", "--force"}
	token, err := store.Issue("git push", args)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Approve(token); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := store.Consume(token, args); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	_, err = store.Consume(token, args)
	if err == nil {
		t.Fatal("second Consume: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown or expired") {
		t.Errorf("second Consume error = %q, want 'unknown or expired'", err)
	}
}

func TestTokenExpired(t *testing.T) {
	store := NewTokenStore(1 * time.Millisecond)
	args := []string{"push"}
	token, err := store.Issue("git push", args)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Approve(token); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	_, err = store.Consume(token, args)
	if err == nil {
		t.Fatal("Consume: expected error for expired token, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("Consume error = %q, want 'expired'", err)
	}
}

func TestTokenArgsMismatch(t *testing.T) {
	store := NewTokenStore(DefaultTokenTTL)
	token, err := store.Issue("git push", []string{"push", "--force"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Approve(token); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	_, err = store.Consume(token, []string{"push"})
	if err == nil {
		t.Fatal("Consume: expected error for args mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("Consume error = %q, want 'mismatch'", err)
	}
}

func TestTokenUnknown(t *testing.T) {
	store := NewTokenStore(DefaultTokenTTL)
	_, err := store.Consume("deadbeefdeadbeefdeadbeefdeadbeef", []string{})
	if err == nil {
		t.Fatal("Consume: expected error for unknown token, got nil")
	}
	if !strings.Contains(err.Error(), "unknown or expired") {
		t.Errorf("Consume error = %q, want 'unknown or expired'", err)
	}
}

func TestTokenPurge(t *testing.T) {
	store := NewTokenStore(5 * time.Millisecond)

	tok1, err := store.Issue("cmd1", []string{"a"})
	if err != nil {
		t.Fatalf("Issue tok1: %v", err)
	}
	tok2, err := store.Issue("cmd2", []string{"b"})
	if err != nil {
		t.Fatalf("Issue tok2: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	// Issue a fresh token with a new store TTL isn't adjustable per-token, so create
	// a new store with longer TTL for the fresh token.
	freshStore := NewTokenStore(DefaultTokenTTL)
	tok3, err := freshStore.Issue("cmd3", []string{"c"})
	if err != nil {
		t.Fatalf("Issue tok3: %v", err)
	}

	// Purge expired tokens from the short-TTL store.
	store.Purge()

	// tok1 and tok2 should be gone.
	if _, err := store.Consume(tok1, []string{"a"}); err == nil {
		t.Error("tok1 should have been purged but validated successfully")
	}
	if _, err := store.Consume(tok2, []string{"b"}); err == nil {
		t.Error("tok2 should have been purged but validated successfully")
	}

	// tok3 in freshStore should still be valid once a human approves it.
	if err := freshStore.Approve(tok3); err != nil {
		t.Fatalf("Approve tok3: %v", err)
	}
	if _, err := freshStore.Consume(tok3, []string{"c"}); err != nil {
		t.Errorf("tok3 should still be valid: %v", err)
	}
}

func TestTokenIssueUniqueness(t *testing.T) {
	store := NewTokenStore(DefaultTokenTTL)
	tok1, err := store.Issue("cmd", []string{})
	if err != nil {
		t.Fatalf("Issue tok1: %v", err)
	}
	tok2, err := store.Issue("cmd", []string{})
	if err != nil {
		t.Fatalf("Issue tok2: %v", err)
	}
	if tok1 == tok2 {
		t.Errorf("tokens are identical: %q", tok1)
	}
}

// TestTokenIssuedIsNotApproved is the ENT-003 unit-level regression: the
// token doit mints on escalation authorises nothing until a human
// approves it, and a rejected attempt leaves the token in place so the
// replay reports the same reason (🎯T41).
func TestTokenIssuedIsNotApproved(t *testing.T) {
	store := NewTokenStore(DefaultTokenTTL)
	args := []string{"rm", "-rf", "/"}
	token, err := store.Issue("rm -rf /", args)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := store.Consume(token, args); !errors.Is(err, ErrAwaitingApproval) {
			t.Fatalf("attempt %d: Consume = %v, want ErrAwaitingApproval", attempt, err)
		}
		if _, err := store.Check(token, args); !errors.Is(err, ErrAwaitingApproval) {
			t.Fatalf("attempt %d: Check = %v, want ErrAwaitingApproval", attempt, err)
		}
	}
}

// TestTokenCheckDoesNotConsume: the non-consuming check leaves the single
// use for the execution that follows (🎯T46/🎯T47).
func TestTokenCheckDoesNotConsume(t *testing.T) {
	store := NewTokenStore(DefaultTokenTTL)
	args := []string{"git", "push"}
	token, err := store.Issue("git push", args)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Approve(token); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := store.Check(token, args); err != nil {
			t.Fatalf("Check %d: %v", i, err)
		}
	}
	if _, err := store.Consume(token, args); err != nil {
		t.Fatalf("Consume after Check: %v", err)
	}
	if _, err := store.Consume(token, args); err == nil {
		t.Fatal("Consume should be single-use")
	}
}
