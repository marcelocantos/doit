// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package script

import (
	"os"
	"path/filepath"
	"testing"
)

func writeScript(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestDetect_BashWithPath(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "foo.sh", "#!/bin/bash\necho hi\n", 0755)

	inv, err := Detect("bash foo.sh", dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if inv == nil {
		t.Fatal("expected detection, got nil")
	}
	if inv.Interpreter != "bash" {
		t.Errorf("interpreter: got %q, want bash", inv.Interpreter)
	}
	if filepath.Base(inv.ResolvedPath) != "foo.sh" {
		t.Errorf("resolved path: got %q, want .../foo.sh", inv.ResolvedPath)
	}
}

func TestDetect_ShZshPaths(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "bar.sh", "echo x\n", 0644)

	for _, interp := range []string{"sh", "zsh", "/bin/bash", "/usr/bin/env bash"} {
		t.Run(interp, func(t *testing.T) {
			// "/usr/bin/env bash" has two tokens before the script arg; that's fine
			cmd := interp + " bar.sh"
			inv, err := Detect(cmd, dir)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if inv == nil {
				// /usr/bin/env bash: env is not a recognised interpreter, so expect nil
				if interp == "/usr/bin/env bash" {
					return
				}
				t.Fatal("expected detection, got nil")
			}
			if filepath.Base(inv.ResolvedPath) != "bar.sh" {
				t.Errorf("resolved path: got %q", inv.ResolvedPath)
			}
		})
	}
}

func TestDetect_DirectExecutionWithShebang(t *testing.T) {
	dir := t.TempDir()
	path := writeScript(t, dir, "go.sh", "#!/usr/bin/env bash\necho hello\n", 0755)

	inv, err := Detect("./go.sh", dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if inv == nil {
		t.Fatal("expected detection")
	}
	if inv.Interpreter != "direct" {
		t.Errorf("interpreter: got %q, want direct", inv.Interpreter)
	}
	if inv.ResolvedPath != path {
		t.Errorf("resolved: got %q, want %q", inv.ResolvedPath, path)
	}
}

func TestDetect_DirectExecutionNoShebang(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "noshe.sh", "echo no shebang\n", 0755)

	inv, err := Detect("./noshe.sh", dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if inv != nil {
		t.Errorf("expected no detection for script without shell shebang, got %+v", inv)
	}
}

func TestDetect_DirectExecutionOtherShebang(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "py.py", "#!/usr/bin/env python3\nprint('hi')\n", 0755)

	inv, err := Detect("./py.py", dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if inv != nil {
		t.Errorf("expected no detection for python script, got %+v", inv)
	}
}

func TestDetect_RejectShellMetacharacters(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "x.sh", "#!/bin/sh\n", 0755)

	for _, cmd := range []string{
		"bash x.sh | cat",
		"bash x.sh && echo done",
		"bash x.sh; echo",
		"bash x.sh > /tmp/out",
		"bash $(echo x.sh)",
		"bash `which sh`",
	} {
		t.Run(cmd, func(t *testing.T) {
			inv, err := Detect(cmd, dir)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if inv != nil {
				t.Errorf("expected no detection for %q, got %+v", cmd, inv)
			}
		})
	}
}

func TestDetect_NonScriptCommand(t *testing.T) {
	for _, cmd := range []string{
		"git status",
		"ls -la",
		"make test",
		"",
	} {
		t.Run(cmd, func(t *testing.T) {
			inv, err := Detect(cmd, "/tmp")
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if inv != nil {
				t.Errorf("expected no detection for %q, got %+v", cmd, inv)
			}
		})
	}
}

func TestDetect_BashWithFlags(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "f.sh", "echo x\n", 0644)

	inv, err := Detect("bash -x f.sh", dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if inv == nil {
		t.Fatal("expected detection despite -x flag")
	}
	if filepath.Base(inv.ResolvedPath) != "f.sh" {
		t.Errorf("resolved: got %q", inv.ResolvedPath)
	}
}

func TestDetect_BashNoScriptArg(t *testing.T) {
	// `bash` with no positional arg (e.g. for interactive) — not a script invocation.
	inv, err := Detect("bash", "/tmp")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if inv != nil {
		t.Errorf("expected no detection, got %+v", inv)
	}
}

func TestDetect_QuotedPath(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "with space.sh", "echo x\n", 0644)

	inv, err := Detect(`bash "with space.sh"`, dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if inv == nil {
		t.Fatal("expected detection with quoted path")
	}
	if filepath.Base(inv.ResolvedPath) != "with space.sh" {
		t.Errorf("resolved: got %q", inv.ResolvedPath)
	}
}

func TestDetect_MissingScriptFile(t *testing.T) {
	_, err := Detect("bash /nonexistent/foo.sh", "/tmp")
	if err == nil {
		t.Fatal("expected error for missing script")
	}
}

func TestHash_Stable(t *testing.T) {
	dir := t.TempDir()
	p := writeScript(t, dir, "s.sh", "#!/bin/sh\necho hi\n", 0644)

	h1, err := Hash(p)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	h2, err := Hash(p)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if h1 != h2 {
		t.Errorf("expected stable hash, got %q and %q", h1, h2)
	}

	// Modify the file — hash must change.
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho bye\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	h3, err := Hash(p)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if h1 == h3 {
		t.Errorf("hash did not change after modification")
	}
}
