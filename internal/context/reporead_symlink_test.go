// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadRepoFile_RejectsSymlinkEscape reproduces Fable-5 finding F6 (🎯T45):
// the containment check is purely lexical (filepath.Clean + HasPrefix) and
// os.ReadFile follows symlinks, so an allowlisted name symlinked to a file
// outside the project root exfiltrates that file's contents.
func TestReadRepoFile_RejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "repo")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}

	// A secret that lives OUTSIDE the project root.
	secret := filepath.Join(base, "secret.txt")
	const secretContent = "TOP-SECRET-PRIVATE-KEY"
	if err := os.WriteFile(secret, []byte(secretContent), 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	// An allowlisted filename inside the root that points at the secret.
	link := filepath.Join(root, "go.mod")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	data, err := ReadRepoFile(root, "go.mod")
	if err == nil {
		t.Fatalf("expected a containment error for a symlink escaping the root, got contents %q", string(data))
	}
	if strings.Contains(string(data), secretContent) {
		t.Fatalf("symlink escape leaked secret contents: %q", string(data))
	}
	if !strings.Contains(err.Error(), "escapes project root") {
		t.Errorf("error = %v, want an 'escapes project root' message", err)
	}
}
