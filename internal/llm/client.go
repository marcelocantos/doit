// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Client invokes `claude -p` as a one-shot subprocess and returns the
// response. Each call spawns a fresh claude process — there is no
// persistent session, no conversation history between calls, and no
// /clear required to reset state. This sidesteps the whole class of
// bugs that come from driving Claude Code's interactive TUI through
// a PTY wrapper (see the claudia v0.4.0/v0.5.0 debugging history and
// the separately-documented /clear session-ID rollover for context).
type Client struct {
	// Model is the Claude model name, e.g. "sonnet" or "opus". Empty
	// leaves the claude CLI to pick its default.
	Model string

	// Timeout is the per-prompt deadline. Zero defaults to 60s.
	Timeout time.Duration

	// WorkDir is the working directory for the spawned claude process,
	// used for CLAUDE.md discovery and any other cwd-relative context.
	// Empty inherits the caller's cwd.
	WorkDir string

	// DisallowTools is a comma-separated list passed to --disallowedTools.
	// Empty omits the flag.
	DisallowTools string

	// SkipPermissions passes --dangerously-skip-permissions when true,
	// matching claudia Task mode's default. doit's gatekeeper prompts
	// never ask claude to run tools, so this is safe here.
	SkipPermissions bool

	// CommandFunc is an injection point for tests. Production code
	// leaves it nil, which uses exec.CommandContext.
	CommandFunc func(ctx context.Context, name string, args ...string) *exec.Cmd
}

// Prompt sends the given prompt to the LLM and returns the trimmed response.
func (c *Client) Prompt(ctx context.Context, prompt string) (string, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"-p"}
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}
	if c.DisallowTools != "" {
		args = append(args, "--disallowedTools", c.DisallowTools)
	}
	if c.SkipPermissions {
		args = append(args, "--dangerously-skip-permissions")
	}
	args = append(args, prompt)

	cmdFn := c.CommandFunc
	if cmdFn == nil {
		cmdFn = exec.CommandContext
	}
	cmd := cmdFn(ctx, "claude", args...)
	cmd.Env = filterEnv(os.Environ())
	if c.WorkDir != "" {
		cmd.Dir = c.WorkDir
	}

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("LLM call timed out after %v", timeout)
		}
		return "", fmt.Errorf("LLM call failed: %w", err)
	}

	result := strings.TrimSpace(string(out))
	if result == "" {
		return "", fmt.Errorf("LLM returned empty response")
	}
	return result, nil
}

// filterEnv strips any environment variables whose names begin with CLAUDECODE.
func filterEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, "CLAUDECODE") {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}
