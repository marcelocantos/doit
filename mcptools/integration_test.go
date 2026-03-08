// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// newMCPClient creates an in-process MCP client connected to a doit MCP server.
func newMCPClient(t *testing.T) *mcpclient.Client {
	t.Helper()
	eng := newTestEngine(t)
	srv := server.NewMCPServer("doit-test", "0.0.1")
	Register(srv, eng)

	c, err := mcpclient.NewInProcessClient(srv)
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	ctx := context.Background()
	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: "test", Version: "0.0.1"},
		},
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return c
}

func TestIntegration_ListTools(t *testing.T) {
	c := newMCPClient(t)
	ctx := context.Background()

	result, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	names := make(map[string]bool)
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}

	for _, want := range []string{"doit_execute", "doit_dry_run", "doit_policy_status", "doit_approve"} {
		if !names[want] {
			t.Errorf("missing tool %q in %v", want, names)
		}
	}
}

func TestIntegration_DryRun_ReadOnly(t *testing.T) {
	c := newMCPClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "doit_dry_run",
			Arguments: map[string]any{"command": "cat foo.txt"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Error("expected non-error for read-only dry run")
	}
	text := extractText(t, result)
	if !strings.Contains(text, "allow") {
		t.Errorf("expected 'allow' in dry run result, got:\n%s", text)
	}
}

func TestIntegration_DryRun_Deny(t *testing.T) {
	c := newMCPClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "doit_dry_run",
			Arguments: map[string]any{"command": "rm -rf /"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text := extractText(t, result)
	if !strings.Contains(text, "deny") {
		t.Errorf("expected 'deny' in dry run result, got:\n%s", text)
	}
}

func TestIntegration_Execute_ReadOnly(t *testing.T) {
	c := newMCPClient(t)
	ctx := context.Background()

	// Create a temp file to cat.
	dir := t.TempDir()
	testFile := filepath.Join(dir, "hello.txt")
	os.WriteFile(testFile, []byte("hello doit\n"), 0644)

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "doit_execute",
			Arguments: map[string]any{
				"command": "cat " + testFile,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Errorf("expected success, got error")
	}

	text := extractText(t, result)
	var resp map[string]any
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if code, _ := resp["exit_code"].(float64); code != 0 {
		t.Errorf("expected exit_code 0, got %v", resp["exit_code"])
	}
	stdout, _ := resp["stdout"].(string)
	if !strings.Contains(stdout, "hello doit") {
		t.Errorf("expected 'hello doit' in stdout, got: %q", stdout)
	}
}

func TestIntegration_Execute_PolicyDeny(t *testing.T) {
	c := newMCPClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "doit_execute",
			Arguments: map[string]any{"command": "rm -rf /"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for denied command")
	}

	text := extractText(t, result)
	var resp map[string]any
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pol, ok := resp["policy"].(map[string]any)
	if !ok {
		t.Fatal("expected policy in response")
	}
	if pol["decision"] != "deny" {
		t.Errorf("expected deny, got %v", pol["decision"])
	}
}

func TestIntegration_Execute_ConfigRuleDeny(t *testing.T) {
	c := newMCPClient(t)
	ctx := context.Background()

	// make -j is blocked by default config rules.
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "doit_dry_run",
			Arguments: map[string]any{"command": "make -j4"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text := extractText(t, result)
	if !strings.Contains(text, "deny") {
		t.Errorf("expected 'deny' for make -j, got:\n%s", text)
	}
}

func TestIntegration_PolicyStatus(t *testing.T) {
	c := newMCPClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "doit_policy_status",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Error("expected non-error")
	}

	text := extractText(t, result)
	var status map[string]any
	if err := json.Unmarshal([]byte(text), &status); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if status["l1_enabled"] != true {
		t.Errorf("expected l1_enabled=true, got %v", status["l1_enabled"])
	}
	if _, ok := status["l1_rules"]; !ok {
		t.Error("expected l1_rules in status")
	}
}

func TestIntegration_Approve_MissingParams(t *testing.T) {
	c := newMCPClient(t)
	ctx := context.Background()

	// Missing token.
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "doit_approve",
			Arguments: map[string]any{"command": "git push"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for missing token")
	}

	// Missing command.
	result, err = c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "doit_approve",
			Arguments: map[string]any{"token": "fake"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for missing command")
	}
}

func TestIntegration_Execute_WithJustification(t *testing.T) {
	c := newMCPClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "doit_dry_run",
			Arguments: map[string]any{
				"command":       "cat /etc/hostname",
				"justification": "need hostname for config generation",
				"safety_arg":    "read-only file, no side effects",
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Error("expected non-error for read-only with justification")
	}
	text := extractText(t, result)
	if !strings.Contains(text, "allow") {
		t.Errorf("expected 'allow', got:\n%s", text)
	}
}

// --- helpers ---

func extractText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("no content in result")
	}
	tc, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	return tc.Text
}
