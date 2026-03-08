package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var doitBin string

func TestMain(m *testing.M) {
	// Build the binary once for all tests.
	dir, err := os.MkdirTemp("", "doit-test-*")
	if err != nil {
		panic(err)
	}
	doitBin = filepath.Join(dir, "doit")
	cmd := exec.Command("go", "build", "-o", doitBin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		panic("failed to build doit: " + err.Error())
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// runDoit runs the doit binary with the given args and a config that
// disables the daemon (to avoid connection timeouts in tests).
func runDoit(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	// Create a temp config that disables the daemon.
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	os.WriteFile(cfgPath, []byte("daemon:\n  enabled: false\n"), 0o644)

	// Point HOME at a temp dir so Load() picks up our config.
	home := t.TempDir()
	configDir := filepath.Join(home, ".config", "doit")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"),
		[]byte("daemon:\n  enabled: false\n"), 0o644)

	cmd := exec.Command(doitBin, args...)
	cmd.Env = append(os.Environ(), "HOME="+home)

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run doit: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func TestVersion(t *testing.T) {
	stdout, _, exitCode := runDoit(t, "--version")
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "doit") {
		t.Errorf("expected stdout to contain 'doit', got %q", stdout)
	}
}

func TestHelp(t *testing.T) {
	stdout, _, exitCode := runDoit(t, "--help")
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "usage:") {
		t.Errorf("expected stdout to contain 'usage:', got %q", stdout)
	}
	if !strings.Contains(stdout, "capability") {
		t.Errorf("expected stdout to contain 'capability', got %q", stdout)
	}
}

func TestHelpAgent(t *testing.T) {
	_, _, exitCode := runDoit(t, "--help-agent")
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
}

func TestList(t *testing.T) {
	stdout, _, exitCode := runDoit(t, "--list")
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	// Verify some known capabilities appear.
	for _, cap := range []string{"cat", "ls", "grep", "git"} {
		if !strings.Contains(stdout, cap) {
			t.Errorf("expected --list output to contain %q", cap)
		}
	}
}

func TestListWithTier(t *testing.T) {
	stdout, _, exitCode := runDoit(t, "--list", "--tier", "read")
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	// read-tier capabilities should appear.
	if !strings.Contains(stdout, "cat") {
		t.Errorf("expected read tier to include 'cat', got %q", stdout)
	}
	// write/build-tier capabilities should not appear.
	for _, cap := range []string{"cp", "mkdir", "make"} {
		if strings.Contains(stdout, cap) {
			t.Errorf("expected read tier to exclude %q, got %q", cap, stdout)
		}
	}
}

func TestMissingCommand(t *testing.T) {
	_, _, exitCode := runDoit(t)
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for missing command, got %d", exitCode)
	}
}

func TestLsCommand(t *testing.T) {
	stdout, _, exitCode := runDoit(t, "ls")
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	// ls in cmd/doit/ should show main.go at minimum.
	if !strings.Contains(stdout, "main.go") {
		t.Errorf("expected ls output to contain 'main.go', got %q", stdout)
	}
}
