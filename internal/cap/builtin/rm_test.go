// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/marcelocantos/doit/internal/cap"
)

// initGitRepo creates a fresh git repo in dir and configures the minimum
// user identity so that git commands succeed in CI environments.
func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	mustRun := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	mustRun("init")
	mustRun("config", "user.email", "test@example.com")
	mustRun("config", "user.name", "Test")
}

// createTrackedFile creates a file in dir, adds it to the index, and
// commits it so that git ls-files reports it as tracked.
func createTrackedFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("content\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	mustGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	mustGit("add", name)
	mustGit("commit", "-m", "add "+name)
	return path
}

// createUntrackedFile creates a file in dir without adding it to git.
func createUntrackedFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("content\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestRmTierTrackedFile verifies that a non-recursive rm of a git-tracked
// file is reclassified from dangerous to write tier.
func TestRmTierTrackedFile(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)
	createTrackedFile(t, dir, "tracked.go")

	r := &Rm{}
	tier := r.TierForArgs([]string{"tracked.go"}, dir)
	if tier != cap.TierWrite {
		t.Errorf("TierForArgs(tracked file) = %v, want write", tier)
	}
}

// TestRmTierUntrackedFile verifies that a non-recursive rm of an untracked
// file keeps the dangerous tier.
func TestRmTierUntrackedFile(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)
	createUntrackedFile(t, dir, "untracked.txt")

	r := &Rm{}
	tier := r.TierForArgs([]string{"untracked.txt"}, dir)
	if tier != cap.TierDangerous {
		t.Errorf("TierForArgs(untracked file) = %v, want dangerous", tier)
	}
}

// TestRmTierRecursiveOnTrackedTree verifies that a recursive rm stays
// dangerous even when the directory tree is fully tracked.
func TestRmTierRecursiveOnTrackedTree(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)
	createTrackedFile(t, dir, "file.go")

	r := &Rm{}
	// -rf on a tracked file: still dangerous because of the -r flag.
	for _, args := range [][]string{
		{"-r", "file.go"},
		{"-rf", "file.go"},
		{"-R", "file.go"},
	} {
		tier := r.TierForArgs(args, dir)
		if tier != cap.TierDangerous {
			t.Errorf("TierForArgs(%v) = %v, want dangerous (recursive)", args, tier)
		}
	}
}

// TestRmTierOutsideRepo verifies that a path outside any git repo falls back
// to dangerous (conservative).
func TestRmTierOutsideRepo(t *testing.T) {
	// Use a temp dir that has not been git-initialised.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	r := &Rm{}
	tier := r.TierForArgs([]string{"file.txt"}, dir)
	if tier != cap.TierDangerous {
		t.Errorf("TierForArgs(outside repo) = %v, want dangerous", tier)
	}
}

// TestRmTierMixedTrackedAndUntracked verifies that any untracked file in the
// argument list keeps the whole command at dangerous tier.
func TestRmTierMixedTrackedAndUntracked(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)
	createTrackedFile(t, dir, "tracked.go")
	createUntrackedFile(t, dir, "untracked.txt")

	r := &Rm{}
	tier := r.TierForArgs([]string{"tracked.go", "untracked.txt"}, dir)
	if tier != cap.TierDangerous {
		t.Errorf("TierForArgs(mixed) = %v, want dangerous", tier)
	}
}

// TestRmTierAbsolutePathTracked verifies that an absolute path to a
// git-tracked file is also reclassified to write tier.
func TestRmTierAbsolutePathTracked(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)
	absPath := createTrackedFile(t, dir, "abs.go")

	r := &Rm{}
	// cwd is unrelated; the absolute path should resolve correctly.
	tier := r.TierForArgs([]string{absPath}, "/tmp")
	if tier != cap.TierWrite {
		t.Errorf("TierForArgs(absolute tracked path) = %v, want write", tier)
	}
}

// TestRmTierNoArgs verifies that rm with no file arguments keeps the dangerous
// tier (the actual Validate would reject it, but Tier must still be safe).
func TestRmTierNoArgs(t *testing.T) {
	r := &Rm{}
	tier := r.TierForArgs([]string{}, "")
	if tier != cap.TierDangerous {
		t.Errorf("TierForArgs(no args) = %v, want dangerous", tier)
	}
}

// TestRmTierFlagsOnly verifies that rm with only flag args (no file paths)
// stays at dangerous tier.
func TestRmTierFlagsOnly(t *testing.T) {
	r := &Rm{}
	tier := r.TierForArgs([]string{"-f"}, "")
	if tier != cap.TierDangerous {
		t.Errorf("TierForArgs(flags only) = %v, want dangerous", tier)
	}
}

// TestRmImplementsTierEvaluator ensures that *Rm satisfies TierEvaluator at
// compile time and that the interface dispatch works via cap.EffectiveTier.
func TestRmImplementsTierEvaluator(t *testing.T) {
	r := &Rm{}

	// Base tier is dangerous.
	if r.Tier() != cap.TierDangerous {
		t.Errorf("Rm.Tier() = %v, want dangerous", r.Tier())
	}

	// EffectiveTier with no args stays dangerous.
	eff := cap.EffectiveTier(r, []string{}, "")
	if eff != cap.TierDangerous {
		t.Errorf("EffectiveTier(Rm, no args) = %v, want dangerous", eff)
	}
}
