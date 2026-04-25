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
	"github.com/marcelocantos/doit/internal/mcpinventory"
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
	if len(tools) != 19 {
		t.Errorf("expected 19 tools, got %d", len(tools))
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
	// Read-only commands are treated as opaque strings — they escalate to
	// L2/L3 rather than being auto-allowed at L1. In the unit test engine
	// L3 is disabled, so the result is "escalate", not "allow".
	// The command must NOT be denied.
	if strings.Contains(text, "deny") {
		t.Errorf("read-only command should not be denied, got: %s", text)
	}
	if !strings.Contains(text, "escalate") && !strings.Contains(text, "allow") {
		t.Errorf("expected 'escalate' or 'allow' in result, got: %s", text)
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

func TestCheckConfig_BaselineProducesNoWarnings(t *testing.T) {
	dir := t.TempDir()

	settings := filepath.Join(dir, "settings.json")
	os.WriteFile(settings, []byte(`{"permissions":{"deny":["Bash"]}}`), 0600)

	claudeJSON := filepath.Join(dir, ".claude.json")
	os.WriteFile(claudeJSON, []byte(`{"mcpServers":{"doit":{"command":"doit"}}}`), 0600)

	eng := newTestEngineWithDangerous(t, false)
	out := runCheckConfigWith(t, eng, settings, claudeJSON, dir)

	for _, section := range []string{"§1", "§2", "§3", "§4", "§5", "§6", "§7"} {
		if !strings.Contains(out, section) {
			t.Errorf("expected %s in output, got:\n%s", section, out)
		}
	}
	if strings.Contains(out, "[FAIL]") {
		t.Errorf("baseline produced FAIL items:\n%s", out)
	}
	if strings.Contains(out, "[WARN]") {
		t.Errorf("baseline produced WARN items:\n%s", out)
	}
	if !strings.Contains(out, "doit is correctly configured against the safety contract") {
		t.Errorf("expected baseline-OK summary, got:\n%s", out)
	}
}

func TestCheckConfig_DangerousTierEnabledWarns(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	os.WriteFile(settings, []byte(`{"permissions":{"deny":["Bash"]}}`), 0600)
	claudeJSON := filepath.Join(dir, ".claude.json")
	os.WriteFile(claudeJSON, []byte(`{"mcpServers":{"doit":{"command":"doit"}}}`), 0600)

	eng := newTestEngineWithDangerous(t, true)
	out := runCheckConfigWith(t, eng, settings, claudeJSON, dir)

	if !strings.Contains(out, "[WARN] §4") {
		t.Errorf("expected [WARN] §4 for dangerous tier, got:\n%s", out)
	}
	if !strings.Contains(out, "Dangerous tier is ENABLED") {
		t.Errorf("expected dangerous-tier warning, got:\n%s", out)
	}
	if !strings.Contains(out, "Configuration weakened from the safety-contract baseline") {
		t.Errorf("expected weakened-baseline summary, got:\n%s", out)
	}
}

func TestCheckConfig_BashNotDeniedFails(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	os.WriteFile(settings, []byte(`{"permissions":{"deny":[]}}`), 0600)
	claudeJSON := filepath.Join(dir, ".claude.json")
	os.WriteFile(claudeJSON, []byte(`{"mcpServers":{"doit":{"command":"doit"}}}`), 0600)

	eng := newTestEngineWithDangerous(t, false)
	out := runCheckConfigWith(t, eng, settings, claudeJSON, dir)

	if !strings.Contains(out, "[FAIL] §1") {
		t.Errorf("expected [FAIL] §1 when Bash is not denied, got:\n%s", out)
	}
}

func TestCheckConfig_ListsSiblingMCPServers(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	os.WriteFile(settings, []byte(`{"permissions":{"deny":["Bash"]}}`), 0600)
	claudeJSON := filepath.Join(dir, ".claude.json")
	os.WriteFile(claudeJSON, []byte(`{"mcpServers":{"doit":{"command":"doit"},"github":{"command":"gh"},"filesystem":{"command":"fs"}}}`), 0600)

	eng := newTestEngineWithDangerous(t, false)
	out := runCheckConfigWith(t, eng, settings, claudeJSON, dir)

	if !strings.Contains(out, "[INFO] §3") {
		t.Errorf("expected [INFO] §3 for sibling servers, got:\n%s", out)
	}
	if !strings.Contains(out, "filesystem, github") {
		t.Errorf("expected sorted sibling list excluding doit, got:\n%s", out)
	}
}

func TestCheckConfig_ProjectConfigPresent(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	os.WriteFile(settings, []byte(`{"permissions":{"deny":["Bash"]}}`), 0600)
	claudeJSON := filepath.Join(dir, ".claude.json")
	os.WriteFile(claudeJSON, []byte(`{"mcpServers":{"doit":{"command":"doit"}}}`), 0600)

	projectDir := filepath.Join(dir, "project")
	doitDir := filepath.Join(projectDir, ".doit")
	if err := os.MkdirAll(doitDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	os.WriteFile(filepath.Join(doitDir, "config.yaml"), []byte("tiers: {}\n"), 0600)

	eng := newTestEngineWithDangerous(t, false)
	out := runCheckConfigWith(t, eng, settings, claudeJSON, projectDir)

	if !strings.Contains(out, "[INFO] §7") {
		t.Errorf("expected [INFO] §7 when project config present, got:\n%s", out)
	}
	if !strings.Contains(out, "Per-project .doit/config.yaml is present") {
		t.Errorf("expected project-config summary, got:\n%s", out)
	}
}

// --- startup sibling-warning integration tests ---

func writeClaudeJSONForTest(t *testing.T, dir string, servers map[string]any) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"mcpServers": servers})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, ".claude.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestStartupWarning_NoSiblings_NoWarning(t *testing.T) {
	dir := t.TempDir()
	path := writeClaudeJSONForTest(t, dir, map[string]any{
		"doit": map[string]any{"command": "doit"},
	})

	var warnings []string
	mcpinventory.WarnAboutSiblings(path, nil, func(msg string) { warnings = append(warnings, msg) })

	if len(warnings) != 0 {
		t.Errorf("expected no warnings with no siblings, got: %v", warnings)
	}
}

func TestStartupWarning_KnownRiskySibling_Warns(t *testing.T) {
	dir := t.TempDir()
	path := writeClaudeJSONForTest(t, dir, map[string]any{
		"doit":       map[string]any{"command": "doit"},
		"filesystem": map[string]any{"command": "npx", "args": []string{"-y", "@modelcontextprotocol/server-filesystem"}},
	})

	var warnings []string
	mcpinventory.WarnAboutSiblings(path, nil, func(msg string) { warnings = append(warnings, msg) })

	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning for risky sibling, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "filesystem") {
		t.Errorf("expected warning to mention 'filesystem', got:\n%s", warnings[0])
	}
}

func TestStartupWarning_AcknowledgedSibling_NoWarning(t *testing.T) {
	dir := t.TempDir()
	path := writeClaudeJSONForTest(t, dir, map[string]any{
		"doit":       map[string]any{"command": "doit"},
		"filesystem": map[string]any{"command": "npx"},
	})

	var warnings []string
	mcpinventory.WarnAboutSiblings(path, []string{"filesystem"}, func(msg string) { warnings = append(warnings, msg) })

	if len(warnings) != 0 {
		t.Errorf("expected no warnings when sibling is acknowledged, got: %v", warnings)
	}
}

// runCheckConfigWith invokes handleCheckConfig with the supplied paths,
// chdir'ing to projectCwd so the §7 check sees the right project directory.
func runCheckConfigWith(t *testing.T, eng *engine.Engine, settingsPath, claudeJSONPath, projectCwd string) string {
	t.Helper()
	prevCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(projectCwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevCwd) })

	// HOME drives ~/.claude.json discovery; redirect it so the test never
	// touches the developer's real config.
	t.Setenv("HOME", filepath.Dir(claudeJSONPath))

	handler := handleCheckConfig(eng)
	result, err := handler(context.Background(), newCallReq("doit_check_config", map[string]any{
		"settings_path": settingsPath,
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return textContent(t, result)
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
	return newTestEngineWithDangerous(t, true)
}

// newTestEngineWithDangerous builds a test engine and lets the caller pin
// whether the dangerous tier is enabled. The check_config tests need both
// states to verify §4 reporting.
func newTestEngineWithDangerous(t *testing.T, dangerous bool) *engine.Engine {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	dangerousVal := "false"
	if dangerous {
		dangerousVal = "true"
	}
	os.WriteFile(cfgPath, []byte(
		"tiers:\n  read: true\n  build: true\n  write: true\n  dangerous: "+dangerousVal+"\n"+
			"audit:\n  path: "+auditPath+"\n"+
			"policy:\n  level1_enabled: true\n  level2_enabled: false\n  level3_enabled: false\n",
	), 0600)

	eng, err := engine.New(engine.Options{ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("newTestEngine: %v", err)
	}
	return eng
}
