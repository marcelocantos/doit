// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Package script detects shell-script invocations in command strings,
// computes content hashes, extracts previews, and persists user approvals.
//
// The detection scope is deliberately conservative: only "plain" command
// forms are recognised as script invocations (explicit interpreter +
// path, or direct execution of a file with a shell shebang). Commands
// with shell metacharacters (pipelines, redirects, compound statements,
// subshells, variable expansion) fall through to normal policy, because
// the script-hash gate cannot reason about what the shell might do
// around the script.
package script

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Invocation describes a detected script invocation.
type Invocation struct {
	// Interpreter is "bash", "sh", "zsh", or "direct" (for ./foo).
	Interpreter string
	// ResolvedPath is the absolute path to the script on disk.
	ResolvedPath string
	// OriginalArg is the script argument as it appeared in the command.
	OriginalArg string
}

// shellMetacharacters that, if present outside quotes, disqualify a
// command from script-hash gating. These forms imply the shell is doing
// work beyond a single invocation, which the gate cannot reason about.
const shellMetacharacters = "|&;<>()`$"

// Detect inspects a command string and returns the script invocation if
// the command is a plain script execution the gate should handle.
//
// Returns (nil, nil) if the command is not a script invocation (and
// policy should proceed normally). Returns (nil, err) if the command
// looks like a script invocation but the file can't be resolved or
// read — the caller should surface this as a denial, since we cannot
// prove the content is trusted.
func Detect(command, cwd string) (*Invocation, error) {
	tokens, ok := tokenize(command)
	if !ok {
		return nil, nil
	}
	if len(tokens) == 0 {
		return nil, nil
	}

	interpreter, scriptArg := scriptTargetFrom(tokens)
	if scriptArg == "" {
		return nil, nil
	}

	resolved, err := resolveScriptPath(scriptArg, cwd)
	if err != nil {
		return nil, err
	}

	if interpreter == "direct" {
		hasShellShebang, err := fileHasShellShebang(resolved)
		if err != nil {
			return nil, err
		}
		if !hasShellShebang {
			return nil, nil
		}
	}

	return &Invocation{
		Interpreter:  interpreter,
		ResolvedPath: resolved,
		OriginalArg:  scriptArg,
	}, nil
}

// scriptTargetFrom inspects already-tokenised args and returns the
// interpreter label and the script-argument string, or "" if the
// command is not a recognised script invocation.
func scriptTargetFrom(tokens []string) (interpreter, scriptArg string) {
	head := tokens[0]
	switch base := filepath.Base(head); base {
	case "bash", "sh", "zsh":
		for _, tok := range tokens[1:] {
			if strings.HasPrefix(tok, "-") {
				continue
			}
			return base, tok
		}
		return "", ""
	}
	if strings.HasPrefix(head, "./") || strings.HasPrefix(head, "../") || strings.HasPrefix(head, "/") {
		return "direct", head
	}
	return "", ""
}

// tokenize splits a command string into whitespace-separated tokens,
// honouring simple single/double quoting. Returns (nil, false) if the
// command contains shell metacharacters outside quotes (pipelines,
// redirects, etc.) — such commands are out of scope for the
// script-hash gate.
func tokenize(s string) ([]string, bool) {
	var tokens []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(c)
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			} else if c == '\\' && i+1 < len(s) {
				next := s[i+1]
				if next == '"' || next == '\\' {
					cur.WriteByte(next)
					i++
				} else {
					cur.WriteByte(c)
				}
			} else {
				cur.WriteByte(c)
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ' ' || c == '\t' || c == '\n':
			flush()
		case strings.IndexByte(shellMetacharacters, c) >= 0:
			return nil, false
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i++
		default:
			cur.WriteByte(c)
		}
	}
	if inSingle || inDouble {
		return nil, false
	}
	flush()
	return tokens, true
}

// resolveScriptPath resolves scriptArg against cwd, requiring that the
// result points at an existing regular file.
func resolveScriptPath(scriptArg, cwd string) (string, error) {
	path := scriptArg
	if !filepath.IsAbs(path) {
		if cwd == "" {
			wd, err := os.Getwd()
			if err != nil {
				return "", fmt.Errorf("resolve script path: %w", err)
			}
			cwd = wd
		}
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat script %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("script %s is not a regular file", path)
	}
	return path, nil
}

// fileHasShellShebang returns true if the file starts with a shebang
// that names bash, sh, or zsh as the interpreter.
func fileHasShellShebang(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open script %s: %w", path, err)
	}
	defer f.Close()

	buf := make([]byte, 256)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return false, fmt.Errorf("read script %s: %w", path, err)
	}
	line := string(buf[:n])
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	if !strings.HasPrefix(line, "#!") {
		return false, nil
	}
	shebang := strings.TrimSpace(line[2:])
	// Take the first whitespace-separated token of the shebang as the
	// interpreter path (`#!/usr/bin/env bash` -> `/usr/bin/env`).
	fields := strings.Fields(shebang)
	if len(fields) == 0 {
		return false, nil
	}
	base := filepath.Base(fields[0])
	if base == "env" && len(fields) > 1 {
		base = filepath.Base(fields[1])
	}
	switch base {
	case "bash", "sh", "zsh":
		return true, nil
	}
	return false, nil
}
