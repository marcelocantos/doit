// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestFilterEnv(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "strips CLAUDECODE prefix",
			input: []string{"CLAUDECODE_SESSION=abc", "HOME=/home/user", "CLAUDECODETOKEN=xyz"},
			want:  []string{"HOME=/home/user"},
		},
		{
			name:  "preserves non-CLAUDECODE vars",
			input: []string{"PATH=/usr/bin", "GOPATH=/go", "USER=marcelo"},
			want:  []string{"PATH=/usr/bin", "GOPATH=/go", "USER=marcelo"},
		},
		{
			name:  "empty input",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "all stripped",
			input: []string{"CLAUDECODE=1", "CLAUDECODEFOO=bar"},
			want:  []string{},
		},
		{
			name:  "case-sensitive: CLAUDE alone not stripped",
			input: []string{"CLAUDE=1", "claudecode=lower"},
			want:  []string{"CLAUDE=1", "claudecode=lower"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterEnv(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v (len %d), want %v (len %d)", got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestPromptArgsConstruction(t *testing.T) {
	tests := []struct {
		name     string
		model    string
		prompt   string
		wantArgs []string
	}{
		{
			name:     "no model",
			model:    "",
			prompt:   "hello",
			wantArgs: []string{"claude", "-p", "hello"},
		},
		{
			name:     "with model",
			model:    "sonnet",
			prompt:   "hello",
			wantArgs: []string{"claude", "-p", "--model", "sonnet", "hello"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotName string
			var gotArgs []string

			c := &Client{
				Model: tt.model,
				CommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
					gotName = name
					gotArgs = append([]string{name}, args...)
					// Return a command that outputs something so Prompt succeeds.
					return exec.CommandContext(ctx, "echo", "ok")
				},
			}

			_, _ = c.Prompt(context.Background(), tt.prompt)

			_ = gotName
			if len(gotArgs) != len(tt.wantArgs) {
				t.Fatalf("args = %v, want %v", gotArgs, tt.wantArgs)
			}
			for i := range gotArgs {
				if gotArgs[i] != tt.wantArgs[i] {
					t.Errorf("args[%d] = %q, want %q", i, gotArgs[i], tt.wantArgs[i])
				}
			}
		})
	}
}

func TestPromptSuccess(t *testing.T) {
	c := &Client{
		CommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "echo", "  canned output  ")
		},
	}
	got, err := c.Prompt(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "canned output" {
		t.Errorf("got %q, want %q", got, "canned output")
	}
}

func TestPromptError(t *testing.T) {
	c := &Client{
		CommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "false")
		},
	}
	_, err := c.Prompt(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestPromptEmptyResponse(t *testing.T) {
	c := &Client{
		CommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			// echo with no args outputs a newline, which trims to empty.
			return exec.CommandContext(ctx, "echo", "")
		},
	}
	_, err := c.Prompt(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for empty response, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got: %v", err)
	}
}

func TestPromptTimeout(t *testing.T) {
	c := &Client{
		Timeout: 50 * time.Millisecond,
		CommandFunc: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "sleep", "10")
		},
	}
	_, err := c.Prompt(context.Background(), "test")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}
