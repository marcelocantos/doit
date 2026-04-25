// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package mcpinventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name     string
		wantCat  RiskCategory
		wantHit  bool
	}{
		{"filesystem", FileWriteExec, true},
		{"@modelcontextprotocol/server-filesystem", FileWriteExec, true},
		{"my-fs-server", FileWriteExec, true},
		{"shell-mcp", ShellExec, true},
		{"desktop-commander", ShellExec, true},
		{"bash-runner", ShellExec, true},
		{"python-runner", LanguageRuntime, true},
		{"node-executor", LanguageRuntime, true},
		{"ruby", LanguageRuntime, true},
		{"jupyter", LanguageRuntime, true},
		{"http-client", HTTPLocalhost, true},
		{"fetch-mcp", HTTPLocalhost, true},
		{"playwright-mcp", HTTPLocalhost, true},
		{"docker", ProcessSpawn, true},
		{"ssh-mcp", ProcessSpawn, true},
		{"exec-server", ProcessSpawn, true},
		// Non-risky names
		{"github", "", false},
		{"linear", "", false},
		{"slack", "", false},
		{"doit", "", false},
		{"bullseye", "", false},
		{"mnemo", "", false},
		{"context7", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cat, ok := Classify(tc.name)
			if ok != tc.wantHit {
				t.Errorf("Classify(%q) hit=%v want=%v", tc.name, ok, tc.wantHit)
			}
			if ok && cat != tc.wantCat {
				t.Errorf("Classify(%q) category=%q want=%q", tc.name, cat, tc.wantCat)
			}
		})
	}
}

func writeClaudeJSON(t *testing.T, dir string, servers map[string]any) string {
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

func TestWarnAboutSiblings_NoSiblings(t *testing.T) {
	dir := t.TempDir()
	path := writeClaudeJSON(t, dir, map[string]any{
		"doit": map[string]any{"command": "doit"},
	})

	var warnings []string
	WarnAboutSiblings(path, nil, func(msg string) { warnings = append(warnings, msg) })

	if len(warnings) != 0 {
		t.Errorf("expected no warnings for doit-only config, got: %v", warnings)
	}
}

func TestWarnAboutSiblings_KnownRiskyUnacknowledged(t *testing.T) {
	dir := t.TempDir()
	path := writeClaudeJSON(t, dir, map[string]any{
		"doit":       map[string]any{"command": "doit"},
		"filesystem": map[string]any{"command": "npx"},
		"github":     map[string]any{"command": "gh"},
	})

	var warnings []string
	WarnAboutSiblings(path, nil, func(msg string) { warnings = append(warnings, msg) })

	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	w := warnings[0]
	if !strings.Contains(w, "filesystem") {
		t.Errorf("warning should mention 'filesystem', got:\n%s", w)
	}
	if !strings.Contains(w, string(FileWriteExec)) {
		t.Errorf("warning should mention risk category %q, got:\n%s", FileWriteExec, w)
	}
	if !strings.Contains(w, "doit is trivially bypassed") {
		t.Errorf("warning should quote threat-model text, got:\n%s", w)
	}
	if !strings.Contains(w, "acknowledged_sibling_servers") {
		t.Errorf("warning should include silencing instruction, got:\n%s", w)
	}
	// "github" (the MCP server name) should not appear as a listed risky server
	if strings.Contains(w, "• github") {
		t.Errorf("non-risky server 'github' should not be listed in warning:\n%s", w)
	}
}

func TestWarnAboutSiblings_AcknowledgedServerSilenced(t *testing.T) {
	dir := t.TempDir()
	path := writeClaudeJSON(t, dir, map[string]any{
		"doit":       map[string]any{"command": "doit"},
		"filesystem": map[string]any{"command": "npx"},
	})

	var warnings []string
	WarnAboutSiblings(path, []string{"filesystem"}, func(msg string) { warnings = append(warnings, msg) })

	if len(warnings) != 0 {
		t.Errorf("expected no warnings when server is acknowledged, got: %v", warnings)
	}
}

func TestWarnAboutSiblings_MissingFile(t *testing.T) {
	var warnings []string
	WarnAboutSiblings("/nonexistent/.claude.json", nil, func(msg string) { warnings = append(warnings, msg) })

	if len(warnings) != 0 {
		t.Errorf("expected no warnings when file is missing, got: %v", warnings)
	}
}

func TestWarnAboutSiblings_MultipleRiskyServers(t *testing.T) {
	dir := t.TempDir()
	path := writeClaudeJSON(t, dir, map[string]any{
		"doit":       map[string]any{"command": "doit"},
		"filesystem": map[string]any{"command": "npx"},
		"browser":    map[string]any{"command": "npx"},
		"github":     map[string]any{"command": "gh"},
	})

	var warnings []string
	WarnAboutSiblings(path, nil, func(msg string) { warnings = append(warnings, msg) })

	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning block for multiple risky servers, got %d", len(warnings))
	}
	w := warnings[0]
	if !strings.Contains(w, "filesystem") {
		t.Errorf("missing 'filesystem' in warning:\n%s", w)
	}
	if !strings.Contains(w, "browser") {
		t.Errorf("missing 'browser' in warning:\n%s", w)
	}
}
