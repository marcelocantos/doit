// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package context_test

import (
	"os"
	"path/filepath"
	"testing"

	doitctx "github.com/marcelocantos/doit/internal/context"
)

func TestReadRepoFile_AllowedFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/foo\n\ngo 1.21\n")

	data, err := doitctx.ReadRepoFile(dir, "go.mod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "module example.com/foo\n\ngo 1.21\n" {
		t.Errorf("unexpected content: %q", string(data))
	}
}

func TestReadRepoFile_NotInAllowlist(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n")

	_, err := doitctx.ReadRepoFile(dir, "main.go")
	if err == nil {
		t.Fatal("expected error for file not in allowlist")
	}
}

func TestReadRepoFile_PathTraversal(t *testing.T) {
	dir := t.TempDir()

	_, err := doitctx.ReadRepoFile(dir, "../etc/passwd")
	if err == nil {
		t.Fatal("expected error for path traversal attempt")
	}
}

func TestReadRepoFile_FileNotExist(t *testing.T) {
	dir := t.TempDir()

	_, err := doitctx.ReadRepoFile(dir, "go.mod")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestReadRepoFile_DotDoitConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".doit"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, ".doit/config.yaml", "policy:\n  level1_enabled: true\n")

	data, err := doitctx.ReadRepoFile(dir, ".doit/config.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "policy:\n  level1_enabled: true\n" {
		t.Errorf("unexpected content: %q", string(data))
	}
}

func TestReadRepoFile_Gitignore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".gitignore", "vendor/\nnode_modules\ndist\n")

	data, err := doitctx.ReadRepoFile(dir, ".gitignore")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty .gitignore content")
	}
}

func TestIsGeneratedDir_Match(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".gitignore", "vendor/\nnode_modules\ndist\n# comment\n")

	cases := []struct {
		target string
		want   bool
	}{
		{"vendor", true},
		{"node_modules", true},
		{"dist", true},
		{"src", false},
		{"", false},
	}

	for _, tc := range cases {
		got := doitctx.IsGeneratedDir(dir, tc.target)
		if got != tc.want {
			t.Errorf("IsGeneratedDir(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

func TestIsGeneratedDir_NoGitignore(t *testing.T) {
	dir := t.TempDir()
	if doitctx.IsGeneratedDir(dir, "vendor") {
		t.Error("expected false when .gitignore does not exist")
	}
}

func TestIsGeneratedDir_TrailingSlash(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".gitignore", "dist/\n")

	if !doitctx.IsGeneratedDir(dir, "dist") {
		t.Error("expected true for directory with trailing slash in gitignore")
	}
}

func TestIsGeneratedDir_WithDotSlashPrefix(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".gitignore", "dist\n")

	if !doitctx.IsGeneratedDir(dir, "./dist") {
		t.Error("expected true for directory with ./ prefix")
	}
}

func TestAllowedFiles_ContainsExpected(t *testing.T) {
	required := []string{".gitignore", "Makefile", "go.mod", "package.json", "CLAUDE.md"}
	for _, f := range required {
		found := false
		for _, a := range doitctx.AllowedFiles {
			if a == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AllowedFiles is missing %q", f)
		}
	}
}
