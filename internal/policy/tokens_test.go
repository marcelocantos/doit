// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
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
	entry, err := store.Validate(token, args)
	if err != nil {
		t.Fatalf("Validate: %v", err)
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
	if _, err := store.Validate(token, args); err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	_, err = store.Validate(token, args)
	if err == nil {
		t.Fatal("second Validate: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown or expired") {
		t.Errorf("second Validate error = %q, want 'unknown or expired'", err)
	}
}

func TestTokenExpired(t *testing.T) {
	store := NewTokenStore(1 * time.Millisecond)
	args := []string{"push"}
	token, err := store.Issue("git push", args)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	_, err = store.Validate(token, args)
	if err == nil {
		t.Fatal("Validate: expected error for expired token, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("Validate error = %q, want 'expired'", err)
	}
}

func TestTokenArgsMismatch(t *testing.T) {
	store := NewTokenStore(DefaultTokenTTL)
	token, err := store.Issue("git push", []string{"push", "--force"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = store.Validate(token, []string{"push"})
	if err == nil {
		t.Fatal("Validate: expected error for args mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("Validate error = %q, want 'mismatch'", err)
	}
}

func TestTokenUnknown(t *testing.T) {
	store := NewTokenStore(DefaultTokenTTL)
	_, err := store.Validate("deadbeefdeadbeefdeadbeefdeadbeef", []string{})
	if err == nil {
		t.Fatal("Validate: expected error for unknown token, got nil")
	}
	if !strings.Contains(err.Error(), "unknown or expired") {
		t.Errorf("Validate error = %q, want 'unknown or expired'", err)
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
	if _, err := store.Validate(tok1, []string{"a"}); err == nil {
		t.Error("tok1 should have been purged but validated successfully")
	}
	if _, err := store.Validate(tok2, []string{"b"}); err == nil {
		t.Error("tok2 should have been purged but validated successfully")
	}

	// tok3 in freshStore should still be valid.
	if _, err := freshStore.Validate(tok3, []string{"c"}); err != nil {
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
