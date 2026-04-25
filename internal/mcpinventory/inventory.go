// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Package mcpinventory classifies MCP server names by execution risk and
// emits a startup warning when unacknowledged risky siblings are present.
package mcpinventory

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// RiskCategory describes why a server is considered execution-adjacent.
type RiskCategory string

const (
	ShellExec       RiskCategory = "shell-exec"
	FileWriteExec   RiskCategory = "file-write+exec"
	LanguageRuntime RiskCategory = "language-runtime"
	HTTPLocalhost   RiskCategory = "http-localhost"
	ProcessSpawn    RiskCategory = "process-spawn"
)

// riskEntry pairs a substring match with a category.
type riskEntry struct {
	substr   string
	category RiskCategory
}

// knownRisky is the canonical seed list. Match is case-insensitive substring.
var knownRisky = []riskEntry{
	// Shell execution
	{"shell", ShellExec},
	{"bash", ShellExec},
	{"desktop-commander", ShellExec},
	{"shell-mcp", ShellExec},

	// Filesystem write + potential exec
	{"filesystem", FileWriteExec},
	{"-fs", FileWriteExec},
	{"fs-", FileWriteExec},

	// Language runtimes
	{"python", LanguageRuntime},
	{"node", LanguageRuntime},
	{"ruby", LanguageRuntime},
	{"jupyter", LanguageRuntime},
	{"repl", LanguageRuntime},

	// HTTP clients capable of reaching localhost
	{"http", HTTPLocalhost},
	{"fetch", HTTPLocalhost},
	{"curl", HTTPLocalhost},
	{"browser", HTTPLocalhost},
	{"playwright", HTTPLocalhost},
	{"puppeteer", HTTPLocalhost},

	// Process-spawning servers
	{"docker", ProcessSpawn},
	{"kubernetes", ProcessSpawn},
	{"k8s", ProcessSpawn},
	{"ssh", ProcessSpawn},
	{"exec", ProcessSpawn},
}

// Classify returns the risk category for a server name and true when the name
// matches a known-risky entry. Match is case-insensitive substring.
func Classify(serverName string) (RiskCategory, bool) {
	lower := strings.ToLower(serverName)
	for _, e := range knownRisky {
		if strings.Contains(lower, e.substr) {
			return e.category, true
		}
	}
	return "", false
}

// WarnAboutSiblings reads ~/.claude.json (or the path given), classifies every
// sibling MCP server, and calls logf for each unacknowledged risky server it
// finds. Servers whose names appear in acknowledged are silently skipped.
//
// logf receives a complete, multi-line warning block; callers typically wire
// it to log.Printf or fmt.Fprintf(os.Stderr, …).
//
// Missing claudeJSONPath is not an error — if the file is absent there is
// nothing to warn about.
func WarnAboutSiblings(claudeJSONPath string, acknowledged []string, logf func(string)) {
	siblings, err := listOtherMCPServers(claudeJSONPath)
	if err != nil {
		return
	}

	ackSet := make(map[string]bool, len(acknowledged))
	for _, name := range acknowledged {
		ackSet[strings.ToLower(name)] = true
	}

	type risky struct {
		name     string
		category RiskCategory
	}
	var found []risky
	for _, name := range siblings {
		if ackSet[strings.ToLower(name)] {
			continue
		}
		if cat, ok := Classify(name); ok {
			found = append(found, risky{name, cat})
		}
	}
	if len(found) == 0 {
		return
	}

	var b strings.Builder
	fmt.Fprintln(&b, "⚠ STARTUP WARNING: execution-adjacent sibling MCP server(s) detected.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Server(s) present that can bypass doit's policy engine:")
	for _, r := range found {
		fmt.Fprintf(&b, "  • %s  [%s]\n", r.name, r.category)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, `Threat model: "doit is trivially bypassed if the agent has any other execution path."`)
	fmt.Fprintln(&b, "See: https://github.com/marcelocantos/doit/blob/master/docs/threat-model.md#1-execution-outside-doit_execute--the-fundamental-bypass")
	fmt.Fprintln(&b)
	// Build the acknowledged list for the silencing instruction.
	names := make([]string, 0, len(found))
	for _, r := range found {
		names = append(names, fmt.Sprintf("%q", r.name))
	}
	sort.Strings(names)
	fmt.Fprintf(&b, "To silence: add to ~/.config/doit/config.yaml:\n")
	fmt.Fprintf(&b, "  policy:\n    acknowledged_sibling_servers: [%s]\n", strings.Join(names, ", "))

	logf(b.String())
}

// listOtherMCPServers collects all MCP server names from the JSON file at
// path, excluding "doit" itself. Returns nil (not an error) when the file
// does not exist.
func listOtherMCPServers(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	seen := map[string]bool{}
	collectMCPServerNames(root, seen)
	delete(seen, "doit")
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func collectMCPServerNames(obj map[string]json.RawMessage, out map[string]bool) {
	if raw, ok := obj["mcpServers"]; ok {
		var servers map[string]json.RawMessage
		if err := json.Unmarshal(raw, &servers); err == nil {
			for name := range servers {
				out[name] = true
			}
		}
	}
	for _, v := range obj {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(v, &nested); err == nil {
			collectMCPServerNames(nested, out)
		}
	}
}
