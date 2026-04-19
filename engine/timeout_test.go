// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTimeout_HappyPath(t *testing.T) {
	eng := newTestEngine(t)

	res := eng.Execute(context.Background(), Request{
		Command:        "echo ok",
		TimeoutSeconds: 5,
		Retry:          true, // bypass any config rules
	})
	if res.ExitCode != 0 {
		t.Fatalf("exit code: got %d, stderr=%q", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "ok") {
		t.Errorf("stdout: got %q", res.Stdout)
	}
}

func TestTimeout_KillsRunawayProcess(t *testing.T) {
	eng := newTestEngine(t)

	start := time.Now()
	res := eng.Execute(context.Background(), Request{
		Command:        "sleep 10",
		TimeoutSeconds: 1,
		Retry:          true,
	})
	elapsed := time.Since(start)

	if res.ExitCode != timeoutExitCode {
		t.Errorf("exit code: got %d, want %d", res.ExitCode, timeoutExitCode)
	}
	if elapsed > 5*time.Second {
		t.Errorf("timeout did not fire: took %v", elapsed)
	}
	if !strings.Contains(res.Stderr, "timed out after 1s") {
		t.Errorf("stderr: got %q, expected timeout message", res.Stderr)
	}
}

func TestTimeout_ZeroValueMeansNoTimeout(t *testing.T) {
	eng := newTestEngine(t)

	res := eng.Execute(context.Background(), Request{
		Command:        "echo no-timeout",
		TimeoutSeconds: 0,
		Retry:          true,
	})
	if res.ExitCode != 0 {
		t.Fatalf("exit code: got %d", res.ExitCode)
	}
	if !strings.Contains(res.Stdout, "no-timeout") {
		t.Errorf("stdout: got %q", res.Stdout)
	}
}

func TestTimeout_AuditRecordsExpectedAndActual(t *testing.T) {
	eng := newTestEngine(t)

	_ = eng.Execute(context.Background(), Request{
		Command:                 "echo x",
		ExpectedDurationSeconds: 5,
		Retry:                   true,
	})

	data, err := os.ReadFile(eng.AuditPath())
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := splitJSONLines(t, data)
	if len(lines) == 0 {
		t.Fatal("no audit entries")
	}
	last := lines[len(lines)-1]

	expected, ok := last["expected_duration_ms"].(float64)
	if !ok {
		t.Fatalf("expected_duration_ms missing or wrong type: %T %v", last["expected_duration_ms"], last["expected_duration_ms"])
	}
	if expected != 5000.0 {
		t.Errorf("expected_duration_ms: got %v, want 5000", expected)
	}
	if _, ok := last["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms missing")
	}
	if timedOut, _ := last["timed_out"].(bool); timedOut {
		t.Errorf("timed_out should be false for a successful command")
	}
}

func TestTimeout_AuditFlagsTimeout(t *testing.T) {
	eng := newTestEngine(t)

	_ = eng.Execute(context.Background(), Request{
		Command:        "sleep 10",
		TimeoutSeconds: 1,
		Retry:          true,
	})

	data, err := os.ReadFile(eng.AuditPath())
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := splitJSONLines(t, data)
	if len(lines) == 0 {
		t.Fatal("no audit entries")
	}
	last := lines[len(lines)-1]
	timedOut, _ := last["timed_out"].(bool)
	if !timedOut {
		t.Errorf("expected timed_out=true, got %v (entry: %v)", timedOut, last)
	}
}

func TestTimeout_AppliesToScriptHashPath(t *testing.T) {
	eng, _ := newTestEngineForScriptGate(t)
	dir := t.TempDir()
	path := writeShellScript(t, dir, "slow.sh", "#!/bin/bash\nsleep 10\n")

	// First-encounter: approve the script content.
	eval := eng.Evaluate(context.Background(), Request{Command: "bash slow.sh", Cwd: dir})
	if eval.ScriptApproval == nil {
		t.Fatal("expected ScriptApproval on first encounter")
	}
	if _, err := eng.ApproveScript(eval.ScriptApproval.ContentHash, path, ""); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Now execute with a 1s timeout; the approved script should still be killed.
	start := time.Now()
	res := eng.Execute(context.Background(), Request{
		Command:        "bash slow.sh",
		Cwd:            dir,
		TimeoutSeconds: 1,
	})
	elapsed := time.Since(start)
	if res.ExitCode != timeoutExitCode {
		t.Errorf("exit code: got %d, want %d", res.ExitCode, timeoutExitCode)
	}
	if elapsed > 5*time.Second {
		t.Errorf("timeout did not fire: took %v", elapsed)
	}
}

func splitJSONLines(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("parse audit line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}
