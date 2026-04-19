// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package script

import (
	"path/filepath"
	"testing"
)

func TestStore_ApproveLookupRevoke(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "approvals.yaml"))

	// Empty store returns nil on lookup.
	got, err := s.Lookup("sha256:abc")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil on empty store, got %+v", got)
	}

	// Approve an entry.
	entry, err := s.Approve("sha256:abc", "/tmp/foo.sh", "test")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if entry.Hash != "sha256:abc" {
		t.Errorf("hash: got %q", entry.Hash)
	}
	if entry.ApprovedAt.IsZero() {
		t.Error("ApprovedAt should be set")
	}

	// Lookup finds it.
	got, err = s.Lookup("sha256:abc")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got == nil {
		t.Fatal("expected to find approval")
	}

	// RecordUse bumps counter.
	if err := s.RecordUse("sha256:abc"); err != nil {
		t.Fatalf("RecordUse: %v", err)
	}
	if err := s.RecordUse("sha256:abc"); err != nil {
		t.Fatalf("RecordUse: %v", err)
	}
	got, _ = s.Lookup("sha256:abc")
	if got.UsageCount != 2 {
		t.Errorf("usage count: got %d, want 2", got.UsageCount)
	}
	if got.LastUsedAt.IsZero() {
		t.Error("LastUsedAt should be set after use")
	}

	// Revoke removes it.
	if err := s.Revoke("sha256:abc"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, _ = s.Lookup("sha256:abc")
	if got != nil {
		t.Errorf("expected nil after revoke, got %+v", got)
	}

	// Revoke again returns error.
	if err := s.Revoke("sha256:abc"); err == nil {
		t.Error("expected error on revoke of missing hash")
	}
}

func TestStore_ApproveIdempotent(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "approvals.yaml"))

	first, err := s.Approve("sha256:x", "/one.sh", "")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Re-approving same hash updates path hint but keeps ApprovedAt.
	second, err := s.Approve("sha256:x", "/two.sh", "updated")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !second.ApprovedAt.Equal(first.ApprovedAt) {
		t.Errorf("ApprovedAt changed: %v -> %v", first.ApprovedAt, second.ApprovedAt)
	}
	if second.PathHint != "/two.sh" {
		t.Errorf("PathHint: got %q, want /two.sh", second.PathHint)
	}

	entries, _ := s.List()
	if len(entries) != 1 {
		t.Errorf("expected 1 entry after idempotent approve, got %d", len(entries))
	}
}

func TestStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.yaml")

	s1 := NewStore(path)
	if _, err := s1.Approve("sha256:persist", "/p.sh", ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Second store instance reads the same file.
	s2 := NewStore(path)
	got, err := s2.Lookup("sha256:persist")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got == nil {
		t.Fatal("expected approval to persist across store instances")
	}
}
