package cli

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/cap/builtin"
)

func newTestRegistry() *cap.Registry {
	reg := cap.NewRegistry()
	builtin.RegisterAll(reg)
	return reg
}

// --- resolveError tests ---

func TestResolveErrorNil(t *testing.T) {
	var stderr bytes.Buffer
	code, msg := resolveError(nil, &stderr)
	if code != 0 {
		t.Errorf("expected code 0, got %d", code)
	}
	if msg != "" {
		t.Errorf("expected empty msg, got %q", msg)
	}
	if stderr.Len() != 0 {
		t.Errorf("expected no stderr output, got %q", stderr.String())
	}
}

func TestResolveErrorExitError(t *testing.T) {
	var stderr bytes.Buffer
	code, msg := resolveError(&builtin.ExitError{Code: 42}, &stderr)
	if code != 42 {
		t.Errorf("expected code 42, got %d", code)
	}
	if msg != "" {
		t.Errorf("expected empty msg, got %q", msg)
	}
	if stderr.Len() != 0 {
		t.Errorf("expected no stderr output, got %q", stderr.String())
	}
}

func TestResolveErrorOther(t *testing.T) {
	var stderr bytes.Buffer
	code, msg := resolveError(fmt.Errorf("something broke"), &stderr)
	if code != 2 {
		t.Errorf("expected code 2, got %d", code)
	}
	if msg != "something broke" {
		t.Errorf("expected msg %q, got %q", "something broke", msg)
	}
	if !strings.Contains(stderr.String(), "something broke") {
		t.Errorf("expected stderr to contain error, got %q", stderr.String())
	}
}

// --- RunList tests ---

func TestRunListAll(t *testing.T) {
	reg := newTestRegistry()
	var buf bytes.Buffer
	code := RunList(reg, &buf, "")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	out := buf.String()
	// Should contain at least some known capabilities.
	for _, name := range []string{"cat", "git", "ls"} {
		if !strings.Contains(out, name) {
			t.Errorf("expected output to contain %q, got:\n%s", name, out)
		}
	}
}

func TestRunListFiltered(t *testing.T) {
	reg := newTestRegistry()
	var buf bytes.Buffer
	code := RunList(reg, &buf, "read")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "cat") {
		t.Errorf("expected output to contain 'cat' (a read-tier cap), got:\n%s", out)
	}
	// "write" tier caps should not appear.
	if strings.Contains(out, "write ") && strings.Contains(out, "tee") {
		t.Errorf("expected no write-tier capabilities in read filter output")
	}
}

func TestRunListInvalidTier(t *testing.T) {
	reg := newTestRegistry()
	var buf bytes.Buffer
	code := RunList(reg, &buf, "invalid")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// --- RunHelp tests ---

func TestRunHelpGeneral(t *testing.T) {
	reg := newTestRegistry()
	var buf bytes.Buffer
	code := RunHelp(reg, &buf, nil)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "usage:") {
		t.Errorf("expected general help to contain 'usage:', got:\n%s", out)
	}
	if !strings.Contains(out, "doit") {
		t.Errorf("expected general help to contain 'doit', got:\n%s", out)
	}
}

func TestRunHelpCapability(t *testing.T) {
	reg := newTestRegistry()
	var buf bytes.Buffer
	code := RunHelp(reg, &buf, []string{"cat"})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	out := buf.String()
	if !strings.Contains(out, "cat") {
		t.Errorf("expected help output to contain 'cat', got:\n%s", out)
	}
	if !strings.Contains(out, "tier:") {
		t.Errorf("expected help output to contain 'tier:', got:\n%s", out)
	}
}

func TestRunHelpUnknown(t *testing.T) {
	reg := newTestRegistry()
	var buf bytes.Buffer
	code := RunHelp(reg, &buf, []string{"nonexistent"})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// --- RunCommand tests ---

func TestRunCommandEmpty(t *testing.T) {
	reg := newTestRegistry()
	var stdout, stderr bytes.Buffer
	code := RunCommand(context.Background(), reg, nil, nil, nil, &stdout, &stderr, false, "", nil)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "missing command") {
		t.Errorf("expected stderr to contain 'missing command', got %q", stderr.String())
	}
}

func TestRunCommandSuccess(t *testing.T) {
	reg := newTestRegistry()
	var stdout, stderr bytes.Buffer
	code := RunCommand(context.Background(), reg, nil, []string{"cat"}, strings.NewReader("hello\n"), &stdout, &stderr, false, "", nil)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "hello") {
		t.Errorf("expected stdout to contain 'hello', got %q", stdout.String())
	}
}
