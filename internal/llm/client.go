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

// Client invokes claude -p as a subprocess and returns the response.
type Client struct {
	Model       string
	Timeout     time.Duration
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
	args = append(args, prompt)

	cmdFn := c.CommandFunc
	if cmdFn == nil {
		cmdFn = exec.CommandContext
	}
	cmd := cmdFn(ctx, "claude", args...)
	cmd.Env = filterEnv(os.Environ())

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
