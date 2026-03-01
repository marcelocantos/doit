// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadStoreMissingFile(t *testing.T) {
	entries, err := LoadStore("/nonexistent/path/learned-policy.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries != nil {
		t.Fatalf("want nil, got %d entries", len(entries))
	}
}

func TestLoadStoreValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")
	yaml := `entries:
  - id: allow-go-test
    description: "go test with any flags"
    match:
      cap: go
      subcmd: test
    decision: allow
    reasoning: "safe build-time operation"
    confidence: high
    provenance: human
    approved: true
    review:
      created: 2026-03-01T00:00:00Z
      last_reviewed: 2026-03-01T00:00:00Z
      review_count: 0
      next_review: 2026-03-08T00:00:00Z
  - id: allow-git-rm-build
    description: "git rm of build artifacts"
    match:
      cap: git
      subcmd: rm
      args_glob: ["build/*", "dist/*"]
    decision: allow
    reasoning: "Build artifacts are regenerated"
    confidence: high
    provenance: human
    approved: true
    review:
      created: 2026-03-01T00:00:00Z
      last_reviewed: 2026-03-01T00:00:00Z
      review_count: 1
      next_review: 2026-03-15T00:00:00Z
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadStore(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	// Verify ordering preserved.
	if entries[0].ID != "allow-go-test" {
		t.Errorf("entry[0].ID = %q, want allow-go-test", entries[0].ID)
	}
	if entries[1].ID != "allow-git-rm-build" {
		t.Errorf("entry[1].ID = %q, want allow-git-rm-build", entries[1].ID)
	}
	// Verify match fields.
	if entries[1].Match.Subcmd != "rm" {
		t.Errorf("entry[1].Match.Subcmd = %q, want rm", entries[1].Match.Subcmd)
	}
	if len(entries[1].Match.ArgsGlob) != 2 {
		t.Errorf("entry[1].Match.ArgsGlob len = %d, want 2", len(entries[1].Match.ArgsGlob))
	}
}

func TestLoadStoreMissingID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")
	yaml := `entries:
  - description: "no id"
    match:
      cap: go
    decision: allow
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStore(path)
	if err == nil {
		t.Fatal("want error for missing id")
	}
}

func TestLoadStoreMissingCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")
	yaml := `entries:
  - id: bad-entry
    description: "no cap"
    match: {}
    decision: allow
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStore(path)
	if err == nil {
		t.Fatal("want error for missing cap")
	}
}

func TestLoadStoreInvalidDecision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")
	yaml := `entries:
  - id: bad-decision
    description: "invalid decision"
    match:
      cap: go
    decision: maybe
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStore(path)
	if err == nil {
		t.Fatal("want error for invalid decision")
	}
}

func TestLoadStoreMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")
	if err := os.WriteFile(path, []byte("{{not yaml"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStore(path)
	if err == nil {
		t.Fatal("want error for malformed YAML")
	}
}

func TestParseDecision(t *testing.T) {
	tests := []struct {
		input string
		want  Decision
		err   bool
	}{
		{"allow", Allow, false},
		{"deny", Deny, false},
		{"escalate", Escalate, false},
		{"maybe", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseDecision(tt.input)
		if tt.err {
			if err == nil {
				t.Errorf("ParseDecision(%q) want error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseDecision(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseDecision(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
