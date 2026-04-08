// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/marcelocantos/doit/internal/cap"
)

func TestRegisterAll(t *testing.T) {
	r := cap.NewRegistry()
	RegisterAll(r)

	caps := r.All()
	const expectedCount = 19
	if len(caps) != expectedCount {
		t.Fatalf("expected %d capabilities, got %d", expectedCount, len(caps))
	}

	for _, c := range caps {
		if c.Name() == "" {
			t.Error("capability has empty Name()")
		}
		if c.Description() == "" {
			t.Errorf("capability %q has empty Description()", c.Name())
		}
		// Tier() should be a valid tier (0-3).
		tier := c.Tier()
		if tier < cap.TierRead || tier > cap.TierDangerous {
			t.Errorf("capability %q has invalid tier %d", c.Name(), tier)
		}
	}
}

func TestGitSubcommandTier(t *testing.T) {
	tests := []struct {
		subcmd string
		want   cap.Tier
	}{
		// Read subcommands.
		{"status", cap.TierRead},
		{"log", cap.TierRead},
		{"diff", cap.TierRead},
		{"blame", cap.TierRead},
		{"show", cap.TierRead},
		{"branch", cap.TierRead},
		{"ls-files", cap.TierRead},

		// Write subcommands.
		{"add", cap.TierWrite},
		{"commit", cap.TierWrite},
		{"merge", cap.TierWrite},
		{"checkout", cap.TierWrite},
		{"rebase", cap.TierWrite},
		{"fetch", cap.TierWrite},
		{"pull", cap.TierWrite},

		// Dangerous subcommands.
		{"push", cap.TierDangerous},
		{"reset", cap.TierDangerous},
		{"filter-branch", cap.TierDangerous},
		{"clean", cap.TierDangerous},

		// Unknown defaults to dangerous.
		{"unknown-subcmd", cap.TierDangerous},
		{"bisect", cap.TierDangerous},
	}

	for _, tt := range tests {
		t.Run(tt.subcmd, func(t *testing.T) {
			got := gitSubcommandTier(tt.subcmd)
			if got != tt.want {
				t.Errorf("gitSubcommandTier(%q) = %v, want %v", tt.subcmd, got, tt.want)
			}
		})
	}
}

func TestExitError(t *testing.T) {
	e := &ExitError{Code: 42}
	if msg := e.Error(); msg != "" {
		t.Errorf("ExitError.Error() = %q, want empty string", msg)
	}

	// Verify it satisfies the error interface.
	var err error = e
	if err == nil {
		t.Error("ExitError should be non-nil as error")
	}
}

func TestRunExternalSuccess(t *testing.T) {
	var stdout bytes.Buffer
	ctx := context.Background()

	err := runExternal(ctx, "echo", []string{"hello"}, nil, &stdout, nil)
	if err != nil {
		t.Fatalf("runExternal(echo hello) returned error: %v", err)
	}

	got := strings.TrimSpace(stdout.String())
	if got != "hello" {
		t.Errorf("stdout = %q, want %q", got, "hello")
	}
}

func TestRunExternalNonZeroExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	ctx := context.Background()

	err := runExternal(ctx, "sh", []string{"-c", "exit 42"}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for non-zero exit, got nil")
	}

	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *ExitError, got %T: %v", err, err)
	}
	if exitErr.Code != 42 {
		t.Errorf("ExitError.Code = %d, want 42", exitErr.Code)
	}
}

func TestRunExternalWithCwd(t *testing.T) {
	var stdout bytes.Buffer
	ctx := cap.NewCwdContext(context.Background(), "/tmp")

	err := runExternal(ctx, "pwd", nil, nil, &stdout, nil)
	if err != nil {
		t.Fatalf("runExternal(pwd) returned error: %v", err)
	}

	// On macOS /tmp is a symlink to /private/tmp.
	got := strings.TrimSpace(stdout.String())
	if got != "/tmp" && got != "/private/tmp" {
		t.Errorf("pwd output = %q, want /tmp or /private/tmp", got)
	}
}

func TestRunExternalWithEnv(t *testing.T) {
	var stdout bytes.Buffer
	env := map[string]string{
		"DOIT_TEST_VAR": "test_value_42",
	}
	ctx := cap.NewEnvContext(context.Background(), env)

	err := runExternal(ctx, "sh", []string{"-c", "echo $DOIT_TEST_VAR"}, nil, &stdout, nil)
	if err != nil {
		t.Fatalf("runExternal returned error: %v", err)
	}

	got := strings.TrimSpace(stdout.String())
	if got != "test_value_42" {
		t.Errorf("env var output = %q, want %q", got, "test_value_42")
	}
}

func TestGitValidate(t *testing.T) {
	g := &Git{}

	if err := g.Validate(nil); err == nil {
		t.Error("Git.Validate(nil) should return error")
	}

	if err := g.Validate([]string{}); err == nil {
		t.Error("Git.Validate([]) should return error")
	}

	if err := g.Validate([]string{"status"}); err != nil {
		t.Errorf("Git.Validate([status]) returned unexpected error: %v", err)
	}
}

func TestMakeValidate(t *testing.T) {
	m := &Make{}

	// Valid args should pass.
	if err := m.Validate([]string{"all"}); err != nil {
		t.Errorf("Make.Validate([all]) returned unexpected error: %v", err)
	}
	if err := m.Validate(nil); err != nil {
		t.Errorf("Make.Validate(nil) returned unexpected error: %v", err)
	}

	// Rejected flags.
	rejected := []struct {
		arg  string
		desc string
	}{
		{"-f", "custom makefile short flag"},
		{"--file", "custom makefile long flag"},
		{"--makefile", "custom makefile alias"},
		{"-f=Makefile.custom", "custom makefile with value"},
		{"--file=other", "custom file with value"},
		{"--makefile=other", "custom makefile with value"},
		{"-C", "directory short flag"},
		{"--directory", "directory long flag"},
		{"-C=/other", "directory with value"},
		{"--directory=/other", "directory with value"},
	}
	for _, tt := range rejected {
		t.Run(tt.desc, func(t *testing.T) {
			if err := m.Validate([]string{tt.arg}); err == nil {
				t.Errorf("Make.Validate([%s]) should return error", tt.arg)
			}
		})
	}
}

func TestRmValidate(t *testing.T) {
	r := &Rm{}

	if err := r.Validate(nil); err == nil {
		t.Error("Rm.Validate(nil) should return error")
	}

	if err := r.Validate([]string{}); err == nil {
		t.Error("Rm.Validate([]) should return error")
	}

	if err := r.Validate([]string{"file.txt"}); err != nil {
		t.Errorf("Rm.Validate([file.txt]) returned unexpected error: %v", err)
	}

	if err := r.Validate([]string{"-rf", "dir/"}); err != nil {
		t.Errorf("Rm.Validate([-rf dir/]) returned unexpected error: %v", err)
	}
}
