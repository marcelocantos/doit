// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Package context provides project context discovery for doit's policy engine.
// It detects project type and build system from well-known marker files,
// and exposes read-only access to a hardcoded allowlist of repo files for
// claim verification.
package context

import (
	"os"
	"path/filepath"
)

// ProjectType identifies the primary language/ecosystem of a project.
type ProjectType string

const (
	TypeUnknown ProjectType = ""
	TypeGo      ProjectType = "go"
	TypeNode    ProjectType = "node"
	TypeRust    ProjectType = "rust"
	TypePython  ProjectType = "python"
)

// ProjectContext describes the discovered context of a project directory.
type ProjectContext struct {
	// Type is the primary project language/ecosystem.
	Type ProjectType

	// BuildSystem is the detected build system (e.g. "make", "cargo", "npm").
	BuildSystem string

	// TestCommand is the idiomatic test invocation for this project type.
	TestCommand string

	// SafeCommands is a list of commands that are considered safe for this
	// project type (e.g. "go test", "go vet" for Go projects).
	SafeCommands []string

	// HasMakefile is true if a Makefile or makefile was found.
	HasMakefile bool

	// CLAUDEMDHints contains any doit-relevant hints extracted from CLAUDE.md.
	// Currently this is the raw content of the file (non-empty if file exists).
	CLAUDEMDContent string
}

// Discover inspects projectRoot and returns a ProjectContext describing the
// project. It reads marker files but never modifies the directory.
func Discover(projectRoot string) *ProjectContext {
	ctx := &ProjectContext{}

	// Detect Makefile.
	if fileExists(filepath.Join(projectRoot, "Makefile")) ||
		fileExists(filepath.Join(projectRoot, "makefile")) {
		ctx.HasMakefile = true
	}

	// Detect project type from primary marker files (highest priority first).
	switch {
	case fileExists(filepath.Join(projectRoot, "go.mod")):
		ctx.Type = TypeGo
		ctx.BuildSystem = "go"
		ctx.TestCommand = "go test ./..."
		ctx.SafeCommands = []string{
			"go test",
			"go vet",
			"go build",
			"go run",
			"go list",
			"go mod tidy",
			"go mod verify",
		}

	case fileExists(filepath.Join(projectRoot, "Cargo.toml")):
		ctx.Type = TypeRust
		ctx.BuildSystem = "cargo"
		ctx.TestCommand = "cargo test"
		ctx.SafeCommands = []string{
			"cargo test",
			"cargo check",
			"cargo build",
			"cargo clippy",
			"cargo fmt",
		}

	case fileExists(filepath.Join(projectRoot, "package.json")):
		ctx.Type = TypeNode
		ctx.BuildSystem = "npm"
		ctx.TestCommand = "npm test"
		ctx.SafeCommands = []string{
			"npm test",
			"npm run",
			"npm install",
			"npx",
		}

	case fileExists(filepath.Join(projectRoot, "pyproject.toml")) ||
		fileExists(filepath.Join(projectRoot, "setup.py")):
		ctx.Type = TypePython
		ctx.BuildSystem = "python"
		ctx.TestCommand = "pytest"
		ctx.SafeCommands = []string{
			"pytest",
			"python -m pytest",
			"python -m unittest",
		}
	}

	// Override build system with make if Makefile is present alongside a
	// recognised project type (e.g. Go + Makefile is very common).
	if ctx.HasMakefile {
		if ctx.BuildSystem == "" {
			ctx.BuildSystem = "make"
		}
		// make targets are project-specific; add "make" as a safe command so
		// that generic make invocations can be allowed.
		ctx.SafeCommands = append(ctx.SafeCommands, "make")
	}

	// Read CLAUDE.md for doit-relevant hints.
	if content, err := os.ReadFile(filepath.Join(projectRoot, "CLAUDE.md")); err == nil {
		ctx.CLAUDEMDContent = string(content)
	}

	return ctx
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
