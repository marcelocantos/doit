// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNew_DefaultConfig(t *testing.T) {
	eng, err := New(Options{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if eng == nil {
		t.Fatal("New() returned nil engine")
	}
	if eng.reg == nil {
		t.Fatal("engine registry is nil")
	}
}

func TestNew_ExplicitConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte("tiers:\n  read: true\n  build: true\n  write: true\n  dangerous: false\npolicy:\n  level1_enabled: true\n"), 0600)

	eng, err := New(Options{ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("New(ConfigPath) error: %v", err)
	}
	if eng.policyL1 == nil {
		t.Fatal("expected L1 policy to be enabled")
	}
}

func TestEvaluate_ReadOnly(t *testing.T) {
	eng := newTestEngine(t)

	result := eng.Evaluate(context.Background(), Request{
		Command: "cat foo.txt",
	})
	if result.Decision != "allow" {
		t.Errorf("expected allow for read-only command, got %s: %s", result.Decision, result.Reason)
	}
}

func TestEvaluate_DangerousCommand(t *testing.T) {
	eng := newTestEngine(t)

	result := eng.Evaluate(context.Background(), Request{
		Command: "rm -rf /",
	})
	if result.Decision != "deny" {
		t.Errorf("expected deny for rm -rf /, got %s: %s", result.Decision, result.Reason)
	}
}

func TestExecute_SimpleCommand(t *testing.T) {
	eng := newTestEngine(t)

	result := eng.Execute(context.Background(), Request{
		Command: "cat",
		Cwd:     t.TempDir(),
	})
	// cat with no stdin produces exit 0
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", result.ExitCode, result.Stderr)
	}
}

func TestExecute_ShellExec(t *testing.T) {
	eng := newTestEngine(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("shell exec works\n"), 0644)

	result := eng.Execute(context.Background(), Request{
		Command: "cat hello.txt",
		Cwd:     dir,
	})
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "shell exec works") {
		t.Errorf("expected 'shell exec works' in stdout, got: %q", result.Stdout)
	}
}

func TestExecute_ShellExec_Pipeline(t *testing.T) {
	eng := newTestEngine(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "data.txt"), []byte("alpha\nbeta\ngamma\n"), 0644)

	// Shell pipeline — this only works via sh -c, not the pipeline parser.
	result := eng.Execute(context.Background(), Request{
		Command: "cat data.txt | grep beta",
		Cwd:     dir,
	})
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", result.ExitCode, result.Stderr)
	}
	if strings.TrimSpace(result.Stdout) != "beta" {
		t.Errorf("expected 'beta', got: %q", result.Stdout)
	}
}

func TestExecute_ShellExec_ExitCode(t *testing.T) {
	eng := newTestEngine(t)

	result := eng.Execute(context.Background(), Request{
		Command: "exit 42",
	})
	if result.ExitCode != 42 {
		t.Errorf("expected exit code 42, got %d", result.ExitCode)
	}
}

func TestExecute_ShellExec_Env(t *testing.T) {
	eng := newTestEngine(t)

	result := eng.Execute(context.Background(), Request{
		Command: "echo $DOIT_TEST_VAR",
		Env:     map[string]string{"DOIT_TEST_VAR": "hello_doit"},
	})
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", result.ExitCode, result.Stderr)
	}
	if strings.TrimSpace(result.Stdout) != "hello_doit" {
		t.Errorf("expected 'hello_doit', got: %q", result.Stdout)
	}
}

func TestExecute_ArgsUsePipeline(t *testing.T) {
	eng := newTestEngine(t)

	// When Args is set, should use pipeline parser (legacy path), not sh -c.
	result := eng.Execute(context.Background(), Request{
		Args: []string{"cat"},
		Cwd:  t.TempDir(),
	})
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0 via pipeline path, got %d; stderr: %s", result.ExitCode, result.Stderr)
	}
}

func TestExecute_PolicyDeny(t *testing.T) {
	eng := newTestEngine(t)

	result := eng.Execute(context.Background(), Request{
		Command: "rm -rf /",
	})
	if result.ExitCode != 1 {
		t.Errorf("expected exit code 1 for denied command, got %d", result.ExitCode)
	}
	if result.PolicyDecision != "deny" {
		t.Errorf("expected policy deny, got %s", result.PolicyDecision)
	}
}

func TestPolicyStatus(t *testing.T) {
	eng := newTestEngine(t)

	status := eng.PolicyStatus()
	if status["l1_enabled"] != true {
		t.Errorf("expected l1_enabled=true, got %v", status["l1_enabled"])
	}
}

func TestExecuteStreaming(t *testing.T) {
	eng := newTestEngine(t)

	var stdout, stderr strings.Builder
	result := eng.ExecuteStreaming(context.Background(), Request{
		Command: "cat",
		Cwd:     t.TempDir(),
	}, &stdout, &stderr)
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", result.ExitCode, stderr.String())
	}
}

func TestNew_ProjectConfig(t *testing.T) {
	// Global config: dangerous enabled, no extra rules.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(cfgPath, []byte(
		"tiers:\n  read: true\n  build: true\n  write: true\n  dangerous: true\n"+
			"audit:\n  path: "+auditPath+"\n"+
			"policy:\n  level1_enabled: true\n  level2_enabled: false\n  level3_enabled: false\n",
	), 0600)

	// Project config: disable dangerous tier, add npm rule.
	projDir := filepath.Join(dir, "project")
	doitDir := filepath.Join(projDir, ".doit")
	os.MkdirAll(doitDir, 0755)
	os.WriteFile(filepath.Join(doitDir, "config.yaml"), []byte(
		"tiers:\n  dangerous: false\nrules:\n  npm:\n    reject_flags: [\"--unsafe-perm\"]\n",
	), 0644)

	eng, err := New(Options{ConfigPath: cfgPath, ProjectRoot: projDir})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Dangerous tier should be disabled by project config.
	if eng.cfg.Tiers.Dangerous {
		t.Error("expected dangerous tier disabled by project config")
	}

	// npm rule should be present from project config.
	if _, ok := eng.cfg.Rules["npm"]; !ok {
		t.Error("expected npm rule from project config")
	}

	// Global default rules should still be present.
	if _, ok := eng.cfg.Rules["make"]; !ok {
		t.Error("expected make rule preserved from global defaults")
	}
}

func TestNew_ProjectConfigMissing(t *testing.T) {
	// ProjectRoot with no .doit/config.yaml should work fine.
	eng, err := New(Options{ProjectRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantCap    string
		wantSubcmd string
		wantFlags  []string
		wantPaths  []string
	}{
		{
			name:       "git push --force origin master",
			command:    "git push --force origin master",
			wantCap:    "git",
			wantSubcmd: "push",
			wantFlags:  []string{"--force"},
			wantPaths:  nil,
		},
		{
			name:       "make -j4",
			command:    "make -j4",
			wantCap:    "make",
			wantSubcmd: "",
			wantFlags:  []string{"-j"},
			wantPaths:  nil,
		},
		{
			name:       "rm -rf ./build",
			command:    "rm -rf ./build",
			wantCap:    "rm",
			wantSubcmd: "",
			wantFlags:  []string{"-r", "-f"},
			wantPaths:  []string{"./build"},
		},
		{
			name:       "long flag with value",
			command:    "curl --output=file.txt example.com",
			wantCap:    "curl",
			wantSubcmd: "",
			wantFlags:  []string{"--output"},
			wantPaths:  nil,
		},
		{
			name:       "combined short flags",
			command:    "tar -xzf archive.tar.gz",
			wantCap:    "tar",
			wantSubcmd: "",
			wantFlags:  []string{"-x", "-z", "-f"},
			wantPaths:  nil,
		},
		{
			name:       "path argument",
			command:    "rm -rf /tmp/dangerous",
			wantCap:    "rm",
			wantSubcmd: "",
			wantFlags:  []string{"-r", "-f"},
			wantPaths:  []string{"/tmp/dangerous"},
		},
		{
			name:       "subcommand with path",
			command:    "git add src/main.go",
			wantCap:    "git",
			wantSubcmd: "add",
			wantFlags:  nil,
			wantPaths:  []string{"src/main.go"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := parseCommand(tt.command)
			if pc.Cap != tt.wantCap {
				t.Errorf("Cap: got %q, want %q", pc.Cap, tt.wantCap)
			}
			if pc.Subcmd != tt.wantSubcmd {
				t.Errorf("Subcmd: got %q, want %q", pc.Subcmd, tt.wantSubcmd)
			}
			if !slicesEqual(pc.Flags, tt.wantFlags) {
				t.Errorf("Flags: got %v, want %v", pc.Flags, tt.wantFlags)
			}
			if !slicesEqual(pc.Paths, tt.wantPaths) {
				t.Errorf("Paths: got %v, want %v", pc.Paths, tt.wantPaths)
			}
		})
	}
}

func TestProposeRules_GitPushForce(t *testing.T) {
	eng := newTestEngine(t)
	proposals := eng.ProposeRules("git push --force origin master", "deny")

	if len(proposals) < 2 {
		t.Fatalf("want >= 2 proposals, got %d", len(proposals))
	}

	// Check we get narrow, moderate, and broad.
	generalities := map[string]bool{}
	for _, p := range proposals {
		generalities[p.Generality] = true
		if p.Source == "" {
			t.Errorf("proposal %q has empty Source", p.Description)
		}
	}
	if !generalities["narrow"] {
		t.Error("missing narrow proposal")
	}
	if !generalities["moderate"] {
		t.Error("missing moderate proposal")
	}
	if !generalities["broad"] {
		t.Error("missing broad proposal")
	}
}

func TestProposeRules_MakeJ4(t *testing.T) {
	eng := newTestEngine(t)
	proposals := eng.ProposeRules("make -j4", "deny")

	if len(proposals) < 2 {
		t.Fatalf("want >= 2 proposals, got %d", len(proposals))
	}

	// Should have a narrow flag-based proposal and a broad one.
	hasNarrow := false
	hasBroad := false
	for _, p := range proposals {
		if p.Generality == "narrow" {
			hasNarrow = true
			if !strings.Contains(p.Description, "-j") {
				t.Errorf("narrow proposal should reference -j flag: %s", p.Description)
			}
		}
		if p.Generality == "broad" {
			hasBroad = true
		}
	}
	if !hasNarrow {
		t.Error("missing narrow proposal for make -j4")
	}
	if !hasBroad {
		t.Error("missing broad proposal for make -j4")
	}
}

func TestProposeRules_RmRfBuild(t *testing.T) {
	eng := newTestEngine(t)
	proposals := eng.ProposeRules("rm -rf ./build", "deny")

	if len(proposals) < 2 {
		t.Fatalf("want >= 2 proposals, got %d", len(proposals))
	}

	// Should detect path argument and -r, -f flags.
	hasNarrow := false
	for _, p := range proposals {
		if p.Generality == "narrow" {
			hasNarrow = true
			// Should reference the flags since they're present.
			if !strings.Contains(p.Description, "-r") && !strings.Contains(p.Description, "./build") {
				t.Errorf("narrow proposal should reference flags or path: %s", p.Description)
			}
		}
	}
	if !hasNarrow {
		t.Error("missing narrow proposal for rm -rf ./build")
	}
}

func TestProposeRules_EmptyCommand(t *testing.T) {
	eng := newTestEngine(t)
	proposals := eng.ProposeRules("", "deny")
	if len(proposals) != 0 {
		t.Errorf("empty command: want 0 proposals, got %d", len(proposals))
	}
}

func TestProposeRules_AllowDecision(t *testing.T) {
	eng := newTestEngine(t)
	proposals := eng.ProposeRules("go test ./...", "allow")

	hasBroad := false
	for _, p := range proposals {
		if p.Generality == "broad" {
			hasBroad = true
			if !strings.Contains(p.Description, "Allow") {
				t.Errorf("broad proposal should use 'Allow': %s", p.Description)
			}
		}
	}
	if !hasBroad {
		t.Error("missing broad proposal")
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(cfgPath, []byte(
		"tiers:\n  read: true\n  build: true\n  write: true\n  dangerous: true\n"+
			"audit:\n  path: "+auditPath+"\n"+
			"policy:\n  level1_enabled: true\n  level2_enabled: false\n  level3_enabled: false\n",
	), 0600)

	eng, err := New(Options{ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("newTestEngine: %v", err)
	}
	return eng
}
