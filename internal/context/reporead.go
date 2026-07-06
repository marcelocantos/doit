// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AllowedFiles is the hardcoded allowlist of files that the gatekeeper may
// read for claim verification. The list is intentionally narrow: only files
// that are routinely needed to verify agent justifications (generated-dir
// claims, build-system claims, project config) are included.
//
// No executable code files (*.go, *.rs, *.py, …) are allowed — the
// gatekeeper only needs to read configuration and manifests, not source.
var AllowedFiles = []string{
	".gitignore",
	"Makefile",
	"makefile",
	"go.mod",
	"package.json",
	"Cargo.toml",
	"pyproject.toml",
	"CLAUDE.md",
	".doit/config.yaml",
}

// ReadRepoFile reads filename from projectRoot, but only if filename is in
// AllowedFiles. Returns an error if the file is not in the allowlist or
// cannot be read.
//
// Security notes:
//   - filename must not contain path separators or ".." components; if it does,
//     the function returns an error rather than silently resolving the path.
//   - The resolved path is verified to remain within projectRoot.
func ReadRepoFile(projectRoot, filename string) ([]byte, error) {
	// Reject filenames with suspicious path components.
	if strings.ContainsRune(filename, os.PathSeparator) && filename != ".doit/config.yaml" {
		return nil, fmt.Errorf("doit: repo read: %q: path separators not allowed (use bare filename)", filename)
	}

	// Validate against allowlist.
	allowed := false
	for _, a := range AllowedFiles {
		if filename == a {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("doit: repo read: %q: not in allowlist", filename)
	}

	// Resolve the full path and confirm it stays within projectRoot.
	full := filepath.Join(projectRoot, filepath.FromSlash(filename))
	clean := filepath.Clean(full)
	rootClean := filepath.Clean(projectRoot)
	if !within(clean, rootClean) {
		return nil, fmt.Errorf("doit: repo read: %q: path escapes project root", filename)
	}

	// Lexical containment is not enough: filepath.Clean never resolves
	// symlinks, and os.ReadFile follows them. An agent that can write the repo
	// could point an allowlisted name (e.g. go.mod) at a file outside the root
	// and exfiltrate it (Fable-5 F6 / 🎯T45). Resolve symlinks on both the root
	// and the target, then re-verify containment against the resolved paths.
	rootResolved, err := filepath.EvalSymlinks(rootClean)
	if err != nil {
		// Root itself does not resolve (missing / broken link); fall back to the
		// lexical root so a legitimately-absent file still yields a read error
		// below rather than a spurious containment pass.
		rootResolved = rootClean
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		// The file is missing or the link is dangling. There is no existing
		// escape target to leak; surface the read error directly (O_NOFOLLOW is
		// unnecessary because a dangling link cannot be read either).
		data, rerr := os.ReadFile(clean)
		if rerr != nil {
			return nil, fmt.Errorf("doit: repo read: %w", rerr)
		}
		return data, nil
	}
	if !within(resolved, rootResolved) {
		return nil, fmt.Errorf("doit: repo read: %q: path escapes project root", filename)
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("doit: repo read: %w", err)
	}
	return data, nil
}

// within reports whether path is rootClean itself or lies beneath it.
func within(path, rootClean string) bool {
	return path == rootClean || strings.HasPrefix(path, rootClean+string(os.PathSeparator))
}

// IsGeneratedDir checks whether dir (relative to projectRoot) is listed in
// the project's .gitignore. It returns true if any gitignore pattern matches
// the directory name exactly or as a directory glob.
//
// This is intentionally simple: it handles the common case of explicit entries
// like "vendor/", "node_modules", or "dist" without full gitignore glob
// semantics.
func IsGeneratedDir(projectRoot, dir string) bool {
	data, err := ReadRepoFile(projectRoot, ".gitignore")
	if err != nil {
		return false
	}

	// Normalise the target: strip leading ./ and trailing /.
	target := strings.TrimPrefix(filepath.ToSlash(dir), "./")
	target = strings.TrimSuffix(target, "/")
	if target == "" {
		return false
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Normalise pattern: strip leading / and trailing /.
		pattern := strings.TrimPrefix(line, "/")
		pattern = strings.TrimSuffix(pattern, "/")
		if pattern == target {
			return true
		}
	}
	return false
}
