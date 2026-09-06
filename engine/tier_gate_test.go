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

// newTestEngineWithTiers builds an engine whose only policy layer is L1,
// with the four capability tiers set explicitly. dangerous=false is the
// shipped default and the configuration doit_check_config and the threat
// model describe as gating destructive commands.
func newTestEngineWithTiers(t *testing.T, dangerous bool) *Engine {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dangerousLine := "  dangerous: false\n"
	if dangerous {
		dangerousLine = "  dangerous: true\n"
	}
	err := os.WriteFile(cfgPath, []byte(
		"tiers:\n  read: true\n  build: true\n  write: true\n"+dangerousLine+
			"audit:\n  path: "+filepath.Join(dir, "audit.jsonl")+"\n"+
			"policy:\n  level1_enabled: true\n  level2_enabled: false\n  level3_enabled: false\n",
	), 0600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}
	eng, err := New(Options{ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return eng
}

// TestDisabledTierIsEnforced is the ENT-002 regression: with the
// dangerous tier disabled, a dangerous-tier capability must be refused on
// the execution path, not merely omitted from a listing. Before the fix
// Registry.CheckTier had no non-test caller and chmod ran.
func TestDisabledTierIsEnforced(t *testing.T) {
	eng := newTestEngineWithTiers(t, false)
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	res := eng.Execute(context.Background(), Request{Command: "chmod 777 " + victim})
	if res.PolicyDecision != "deny" {
		t.Fatalf("chmod under a disabled dangerous tier: got %+v", res)
	}
	if !strings.Contains(res.PolicyReason, "dangerous") {
		t.Errorf("reason should name the disabled tier, got %q", res.PolicyReason)
	}

	info, err := os.Stat(victim)
	if err != nil {
		t.Fatalf("stat victim: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("chmod ran: mode = %v", info.Mode().Perm())
	}
}

// TestDisabledTierIsNotBypassableByRetry: the tier switch is an operator
// setting, so the agent's own retry/justification cannot lift it.
func TestDisabledTierIsNotBypassableByRetry(t *testing.T) {
	eng := newTestEngineWithTiers(t, false)
	res := eng.Execute(context.Background(), Request{Command: "chmod 777 /tmp", Retry: true})
	if res.PolicyDecision != "deny" {
		t.Fatalf("retry lifted the tier gate: %+v", res)
	}
}

// TestEnabledTierPasses: enabling the tier restores the previous
// behaviour, so the gate is a switch and not a blanket refusal.
func TestEnabledTierPasses(t *testing.T) {
	eng := newTestEngineWithTiers(t, true)
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	res := eng.Execute(context.Background(), Request{Command: "chmod 640 " + victim})
	if res.PolicyDecision == "deny" && strings.Contains(res.PolicyReason, "tier") {
		t.Fatalf("enabled tier still gated: %+v", res)
	}
}

// TestCapabilityValidateIsEnforced is the second half of the ENT-002
// regression: a capability's own Validate now runs on the execution path
// instead of being reachable only from its unit test.
func TestCapabilityValidateIsEnforced(t *testing.T) {
	eng := newTestEngineWithTiers(t, true)
	res := eng.Execute(context.Background(), Request{Command: "rm"})
	if res.PolicyDecision != "deny" {
		t.Fatalf("bare rm: got %+v", res)
	}
	if !strings.Contains(res.PolicyReason, "at least one argument") {
		t.Errorf("reason should carry the capability's message, got %q", res.PolicyReason)
	}
}
