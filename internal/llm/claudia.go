// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/marcelocantos/claudia"
)

const systemPrompt = `You are a security gatekeeper for a command execution broker called doit.
Your sole job is to evaluate commands and respond with a JSON verdict.
You receive structured command descriptions and respond with ONLY a JSON object.
Never use tools. Never execute commands. Just evaluate and respond with JSON.
Respond with exactly: {"decision": "allow"|"deny"|"escalate", "reasoning": "brief explanation"}`

// ClaudiaClient wraps a persistent claudia session to implement the Prompter interface.
type ClaudiaClient struct {
	model   string
	timeout time.Duration
	workDir string

	mu    sync.Mutex
	agent *claudia.Agent
}

// NewClaudiaClient creates a new claudia-backed prompter. Call Start to
// spawn the persistent session.
func NewClaudiaClient(model, workDir string, timeout time.Duration) *ClaudiaClient {
	return &ClaudiaClient{
		model:   model,
		workDir: workDir,
		timeout: timeout,
	}
}

// Start spawns the persistent claudia session. Returns an error if the
// claude binary is not found.
func (c *ClaudiaClient) Start() error {
	// Check that claude is available before spawning.
	if _, err := exec.LookPath("claude"); err != nil {
		return fmt.Errorf("claude binary not found: %w", err)
	}

	cfg := claudia.Config{
		WorkDir:        c.workDir,
		Model:          c.model,
		PermissionMode: "bypassPermissions",
		DisallowTools:  "Bash,Read,Write,Edit,Glob,Grep",
	}

	agent, err := claudia.Start(cfg)
	if err != nil {
		return fmt.Errorf("start claudia session: %w", err)
	}

	c.mu.Lock()
	c.agent = agent
	c.mu.Unlock()

	// Send the system prompt as the first message to establish the role.
	if err := agent.Send(systemPrompt); err != nil {
		agent.Stop()
		return fmt.Errorf("send system prompt: %w", err)
	}

	timeout := c.timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Wait for the acknowledgement of the system prompt.
	if _, err := agent.WaitForResponse(ctx); err != nil {
		agent.Stop()
		return fmt.Errorf("system prompt response: %w", err)
	}

	// Clear context after the system prompt exchange so each evaluation
	// starts clean (the system prompt is re-sent in buildPrompt context).
	if err := agent.Send("/clear"); err != nil {
		log.Printf("doit: claudia: failed to /clear after system prompt: %v", err)
	} else {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel2()
		// Wait for the /clear to take effect.
		_, _ = agent.WaitForResponse(ctx2)
	}

	return nil
}

// Prompt sends a prompt to the persistent claudia session and returns the
// trimmed response. It sends /clear after each evaluation to prevent
// cross-contamination between evaluations.
func (c *ClaudiaClient) Prompt(ctx context.Context, prompt string) (string, error) {
	c.mu.Lock()
	agent := c.agent
	c.mu.Unlock()

	if agent == nil {
		return "", fmt.Errorf("claudia session not started")
	}

	if !agent.Alive() {
		return "", fmt.Errorf("claudia session is dead")
	}

	timeout := c.timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := agent.Send(prompt); err != nil {
		return "", fmt.Errorf("send prompt: %w", err)
	}

	response, err := agent.WaitForResponse(ctx)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("claudia call timed out after %v", timeout)
		}
		return "", fmt.Errorf("claudia call failed: %w", err)
	}

	// Clear context after each evaluation to prevent cross-contamination.
	go func() {
		if sendErr := agent.Send("/clear"); sendErr != nil {
			log.Printf("doit: claudia: failed to /clear: %v", sendErr)
			return
		}
		clearCtx, clearCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer clearCancel()
		_, _ = agent.WaitForResponse(clearCtx)
	}()

	result := strings.TrimSpace(response)
	if result == "" {
		return "", fmt.Errorf("claudia returned empty response")
	}
	return result, nil
}

// Close gracefully shuts down the claudia session.
func (c *ClaudiaClient) Close() {
	c.mu.Lock()
	agent := c.agent
	c.agent = nil
	c.mu.Unlock()

	if agent != nil {
		agent.Stop()
	}
}
