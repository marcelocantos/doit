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
