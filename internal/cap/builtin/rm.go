// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/rules"
)

// Rm implements the rm capability with reversibility-aware tier evaluation.
// A non-recursive rm targeting a git-tracked file is classified as write-tier
// (recoverable via `git checkout HEAD -- <path>`). All other cases keep the
// default dangerous tier.
type Rm struct{ Base }

var _ cap.Capability = (*Rm)(nil)
var _ cap.TierEvaluator = (*Rm)(nil)

func (r *Rm) Name() string { return "rm" }
func (r *Rm) Description() string {
	return "remove files or directories (write-tier for git-tracked files; dangerous otherwise)"
}

// Tier returns the conservative base tier used when argument context is
// unavailable (e.g. capability listing). The policy engine uses TierForArgs
// to obtain the effective tier at evaluation time.
func (r *Rm) Tier() cap.Tier { return cap.TierDangerous }

// TierForArgs returns the effective tier based on reversibility:
//   - Recursive removes (-r/-R) are always dangerous — blast radius too wide.
//   - Non-recursive removes where every target file is git-tracked → write.
//   - Non-recursive removes with any untracked, missing-repo, or ambiguous
//     file → dangerous (conservative fallback).
func (r *Rm) TierForArgs(args []string, cwd string) cap.Tier {
	// Recursive flag always → dangerous, regardless of tracking.
	if rules.HasAnyFlag(args, "-r", "-R") {
		return cap.TierDangerous
	}

	// Collect positional (non-flag) file arguments.
	paths := nonFlagArgs(args)
	if len(paths) == 0 {
		// No paths — can't determine tracking; stay dangerous.
		return cap.TierDangerous
	}

	// Every path must be git-tracked for the write-tier reclassification.
	for _, p := range paths {
		if !isGitTracked(p, cwd) {
			return cap.TierDangerous
		}
	}
	return cap.TierWrite
}

func (r *Rm) Validate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("rm requires at least one argument")
	}
	return nil
}

// nonFlagArgs returns the positional (non-flag) arguments from args.
// Handles the "--" end-of-flags separator.
func nonFlagArgs(args []string) []string {
	var paths []string
	pastSep := false
	for _, a := range args {
		if pastSep {
			paths = append(paths, a)
			continue
		}
		if a == "--" {
			pastSep = true
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		paths = append(paths, a)
	}
	return paths
}

// isGitTracked reports whether path is tracked by git. It shells out to
// `git ls-files --error-unmatch <path>` in the file's parent directory.
//
// Returns false (conservative/dangerous) when:
//   - The path is not under a git repository.
//   - The path is untracked.
//   - The git invocation fails for any reason (network, bare repo, etc.).
func isGitTracked(path, cwd string) bool {
	// Resolve the path relative to cwd when it's not absolute.
	absPath := path
	if !filepath.IsAbs(path) {
		if cwd != "" {
			absPath = filepath.Join(cwd, path)
		}
	}
	absPath = filepath.Clean(absPath)

	// Run git ls-files --error-unmatch in the file's parent directory so that
	// git resolves the repo from the right location even when the caller's cwd
	// is different from the file's location.
	dir := filepath.Dir(absPath)
	base := filepath.Base(absPath)

	cmd := exec.Command("git", "ls-files", "--error-unmatch", base) // #nosec G204
	cmd.Dir = dir

	// A zero exit means the file is tracked. Any non-zero exit (untracked,
	// not a repo, bare repo, etc.) means fall back to dangerous.
	return cmd.Run() == nil
}
