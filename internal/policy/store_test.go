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

// makeEntry returns a minimal valid PolicyEntry for use in tests.
func makeEntry(id, cap string) PolicyEntry {
	return PolicyEntry{
		ID:          id,
		Description: id,
		Match:       MatchCriteria{Cap: cap},
		Decision:    "allow",
		Reasoning:   "test",
		Confidence:  "high",
		Provenance:  "human",
	}
}

func TestSaveStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")

	want := []PolicyEntry{
		makeEntry("e1", "go"),
		makeEntry("e2", "git"),
	}
	if err := SaveStore(path, want); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}

	got, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID {
			t.Errorf("entry[%d].ID = %q, want %q", i, got[i].ID, want[i].ID)
		}
		if got[i].Match.Cap != want[i].Match.Cap {
			t.Errorf("entry[%d].Match.Cap = %q, want %q", i, got[i].Match.Cap, want[i].Match.Cap)
		}
	}
}

func TestSaveStoreCreatesDir(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "a", "b", "c", "learned-policy.yaml")

	entries := []PolicyEntry{makeEntry("e1", "go")}
	if err := SaveStore(path, entries); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestAppendEntriesDedup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")

	initial := []PolicyEntry{
		makeEntry("e1", "go"),
		makeEntry("e2", "git"),
	}
	if err := SaveStore(path, initial); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}

	// e2 overlaps; e3 and e4 are new.
	news := []PolicyEntry{
		makeEntry("e2", "git"),
		makeEntry("e3", "make"),
		makeEntry("e4", "go"),
	}
	added, err := AppendEntries(path, news)
	if err != nil {
		t.Fatalf("AppendEntries: %v", err)
	}
	if added != 2 {
		t.Errorf("added = %d, want 2", added)
	}

	got, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("total entries = %d, want 4", len(got))
	}
}

func TestAppendEntriesToNonexistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")

	entries := []PolicyEntry{
		makeEntry("e1", "go"),
		makeEntry("e2", "git"),
	}
	added, err := AppendEntries(path, entries)
	if err != nil {
		t.Fatalf("AppendEntries: %v", err)
	}
	if added != 2 {
		t.Errorf("added = %d, want 2", added)
	}

	got, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("total entries = %d, want 2", len(got))
	}
}

func TestUpdateEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")

	entries := []PolicyEntry{
		makeEntry("e1", "go"),
		makeEntry("e2", "git"),
	}
	if err := SaveStore(path, entries); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}

	if err := UpdateEntry(path, "e1", func(e *PolicyEntry) {
		e.Decision = "deny"
	}); err != nil {
		t.Fatalf("UpdateEntry: %v", err)
	}

	got, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if got[0].Decision != "deny" {
		t.Errorf("entry[0].Decision = %q, want deny", got[0].Decision)
	}
	// Other entry unchanged.
	if got[1].Decision != "allow" {
		t.Errorf("entry[1].Decision = %q, want allow", got[1].Decision)
	}
}

func TestUpdateEntryNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")

	if err := SaveStore(path, []PolicyEntry{makeEntry("e1", "go")}); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}

	err := UpdateEntry(path, "no-such-id", func(e *PolicyEntry) {})
	if err == nil {
		t.Fatal("want error for unknown id")
	}
}

func TestDeleteEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")

	entries := []PolicyEntry{
		makeEntry("e1", "go"),
		makeEntry("e2", "git"),
		makeEntry("e3", "make"),
	}
	if err := SaveStore(path, entries); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}

	if err := DeleteEntry(path, "e2"); err != nil {
		t.Fatalf("DeleteEntry: %v", err)
	}

	got, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].ID != "e1" || got[1].ID != "e3" {
		t.Errorf("got IDs %q %q, want e1 e3", got[0].ID, got[1].ID)
	}
}

func TestDeleteEntryNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned-policy.yaml")

	if err := SaveStore(path, []PolicyEntry{makeEntry("e1", "go")}); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}

	err := DeleteEntry(path, "no-such-id")
	if err == nil {
		t.Fatal("want error for unknown id")
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
