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

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/marcelocantos/doit/engine"
)

func TestRegister_AddsTools(t *testing.T) {
	eng := newTestEngine(t)
	srv := server.NewMCPServer("test", "0.0.1")
	Register(srv, eng)

	tools := srv.ListTools()
	expected := []string{"doit_execute", "doit_dry_run", "doit_policy_status", "doit_approve"}
	for _, name := range expected {
		if _, ok := tools[name]; !ok {
			t.Errorf("missing tool: %s", name)
		}
	}
	if len(tools) != 9 {
		t.Errorf("expected 9 tools, got %d", len(tools))
	}
}

func TestDryRun_ReadOnly(t *testing.T) {
	eng := newTestEngine(t)
	handler := handleDryRun(eng)

	result, err := handler(context.Background(), newCallReq("doit_dry_run", map[string]any{
		"command": "cat foo.txt",
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if result.IsError {
		t.Error("expected non-error result")
	}
	text := textContent(t, result)
	if !strings.Contains(text, "allow") {
		t.Errorf("expected 'allow' in result, got: %s", text)
	}
}

func TestDryRun_DangerousCommand(t *testing.T) {
	eng := newTestEngine(t)
	handler := handleDryRun(eng)

	result, err := handler(context.Background(), newCallReq("doit_dry_run", map[string]any{
		"command": "rm -rf /",
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	text := textContent(t, result)
	if !strings.Contains(text, "deny") {
		t.Errorf("expected 'deny' in result, got: %s", text)
	}
}

func TestExecute_PolicyDeny(t *testing.T) {
	eng := newTestEngine(t)
	srv := server.NewMCPServer("test", "0.0.1", server.WithElicitation())
	handler := handleExecute(srv, eng)

	result, err := handler(context.Background(), newCallReq("doit_execute", map[string]any{
		"command": "rm -rf /",
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for denied command")
	}
	text := textContent(t, result)
	if !strings.Contains(text, "Denied by policy") {
		t.Errorf("expected denial message, got %q", text)
	}
}

func TestExecute_MissingCommand(t *testing.T) {
	eng := newTestEngine(t)
	srv := server.NewMCPServer("test", "0.0.1", server.WithElicitation())
	handler := handleExecute(srv, eng)

	result, err := handler(context.Background(), newCallReq("doit_execute", map[string]any{}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for missing command")
	}
}

func TestPolicyStatus(t *testing.T) {
	eng := newTestEngine(t)
	handler := handlePolicyStatus(eng)

	result, err := handler(context.Background(), newCallReq("doit_policy_status", nil))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if result.IsError {
		t.Error("expected non-error result")
	}
	text := textContent(t, result)
	var status map[string]any
	if err := json.Unmarshal([]byte(text), &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if status["l1_enabled"] != true {
		t.Errorf("expected l1_enabled=true, got %v", status["l1_enabled"])
	}
}

func TestApprove_NoTokenStore(t *testing.T) {
	eng := newTestEngine(t) // L3 disabled = no token store
	handler := handleApprove(eng)

	result, err := handler(context.Background(), newCallReq("doit_approve", map[string]any{
		"token":   "fake-token",
		"command": "git push",
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when token store is disabled")
	}
}

// --- helpers ---

func newCallReq(name string, args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	}
}

func textContent(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
	tc, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	return tc.Text
}

func newTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(cfgPath, []byte(
		"tiers:\n  read: true\n  build: true\n  write: true\n  dangerous: true\n"+
			"audit:\n  path: "+auditPath+"\n"+
			"policy:\n  level1_enabled: true\n  level2_enabled: false\n  level3_enabled: false\n",
	), 0600)

	eng, err := engine.New(engine.Options{ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("newTestEngine: %v", err)
	}
	return eng
}
