// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"os"
	"path/filepath"
	"testing"

	doitctx "github.com/marcelocantos/doit/internal/context"
)

func TestDiscover_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	ctx := doitctx.Discover(dir)
	if ctx.Type != doitctx.TypeUnknown {
		t.Errorf("expected TypeUnknown for empty dir, got %q", ctx.Type)
	}
	if ctx.BuildSystem != "" {
		t.Errorf("expected empty BuildSystem, got %q", ctx.BuildSystem)
	}
	if ctx.HasMakefile {
		t.Error("expected HasMakefile=false for empty dir")
	}
}

func TestDiscover_GoProject(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/foo\n\ngo 1.21\n")

	ctx := doitctx.Discover(dir)
	if ctx.Type != doitctx.TypeGo {
		t.Errorf("expected TypeGo, got %q", ctx.Type)
	}
	if ctx.BuildSystem != "go" {
		t.Errorf("expected BuildSystem=go, got %q", ctx.BuildSystem)
	}
	if ctx.TestCommand != "go test ./..." {
		t.Errorf("unexpected TestCommand: %q", ctx.TestCommand)
	}
	if !containsCmd(ctx.SafeCommands, "go test") {
		t.Error("expected 'go test' in SafeCommands")
	}
	if !containsCmd(ctx.SafeCommands, "go vet") {
		t.Error("expected 'go vet' in SafeCommands")
	}
}

func TestDiscover_GoProjectWithMakefile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/foo\n\ngo 1.21\n")
	writeFile(t, dir, "Makefile", "test:\n\tgo test ./...\n")

	ctx := doitctx.Discover(dir)
	if ctx.Type != doitctx.TypeGo {
		t.Errorf("expected TypeGo, got %q", ctx.Type)
	}
	if !ctx.HasMakefile {
		t.Error("expected HasMakefile=true")
	}
	// BuildSystem stays "go" when Makefile accompanies a Go project.
	if ctx.BuildSystem != "go" {
		t.Errorf("expected BuildSystem=go, got %q", ctx.BuildSystem)
	}
	if !containsCmd(ctx.SafeCommands, "make") {
		t.Error("expected 'make' in SafeCommands when Makefile is present")
	}
}

func TestDiscover_NodeProject(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name":"foo","version":"1.0.0"}`)

	ctx := doitctx.Discover(dir)
	if ctx.Type != doitctx.TypeNode {
		t.Errorf("expected TypeNode, got %q", ctx.Type)
	}
	if ctx.BuildSystem != "npm" {
		t.Errorf("expected BuildSystem=npm, got %q", ctx.BuildSystem)
	}
}

func TestDiscover_RustProject(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", "[package]\nname = \"foo\"\n")

	ctx := doitctx.Discover(dir)
	if ctx.Type != doitctx.TypeRust {
		t.Errorf("expected TypeRust, got %q", ctx.Type)
	}
	if ctx.BuildSystem != "cargo" {
		t.Errorf("expected BuildSystem=cargo, got %q", ctx.BuildSystem)
	}
}

func TestDiscover_PythonPyproject(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pyproject.toml", "[tool.poetry]\nname = \"foo\"\n")

	ctx := doitctx.Discover(dir)
	if ctx.Type != doitctx.TypePython {
		t.Errorf("expected TypePython, got %q", ctx.Type)
	}
}

func TestDiscover_PythonSetupPy(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "setup.py", "from setuptools import setup\nsetup(name='foo')\n")

	ctx := doitctx.Discover(dir)
	if ctx.Type != doitctx.TypePython {
		t.Errorf("expected TypePython, got %q", ctx.Type)
	}
}

func TestDiscover_MakefileOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Makefile", "all:\n\t@echo hi\n")

	ctx := doitctx.Discover(dir)
	if ctx.Type != doitctx.TypeUnknown {
		t.Errorf("expected TypeUnknown for Makefile-only dir, got %q", ctx.Type)
	}
	if ctx.BuildSystem != "make" {
		t.Errorf("expected BuildSystem=make, got %q", ctx.BuildSystem)
	}
	if !ctx.HasMakefile {
		t.Error("expected HasMakefile=true")
	}
}

func TestDiscover_CLAUDEMDContent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "CLAUDE.md", "# My Project\nSome hints here.\n")

	ctx := doitctx.Discover(dir)
	if ctx.CLAUDEMDContent == "" {
		t.Error("expected CLAUDEMDContent to be non-empty")
	}
	if ctx.CLAUDEMDContent != "# My Project\nSome hints here.\n" {
		t.Errorf("unexpected CLAUDEMDContent: %q", ctx.CLAUDEMDContent)
	}
}

func TestDiscover_NoCLAUDEMD(t *testing.T) {
	dir := t.TempDir()
	ctx := doitctx.Discover(dir)
	if ctx.CLAUDEMDContent != "" {
		t.Errorf("expected empty CLAUDEMDContent when no CLAUDE.md exists")
	}
}

// --- helpers ---

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile %s: %v", name, err)
	}
}

func containsCmd(cmds []string, cmd string) bool {
	for _, c := range cmds {
		if c == cmd {
			return true
		}
	}
	return false
}
