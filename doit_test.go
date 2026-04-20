// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package doit

import (
	"os"
	"strings"
	"testing"
)

func TestAgentsGuide_EmbeddedAndMatchesSource(t *testing.T) {
	if AgentsGuide == "" {
		t.Fatal("AgentsGuide is empty — go:embed failed to pick up agents-guide.md")
	}

	// Sanity check: content begins with the expected heading so we catch
	// accidental encoding shifts (BOM, line-ending rewrites) that slip
	// past a simple non-empty check.
	if !strings.HasPrefix(AgentsGuide, "# doit — Agent Usage Guide") {
		t.Errorf("AgentsGuide does not start with the expected heading; first 80 chars: %q", AgentsGuide[:80])
	}

	// Keep the embedded content in lockstep with the on-disk source.
	// If someone edits agents-guide.md at runtime and forgets to rebuild,
	// this won't catch them (embedding is a compile-time snapshot), but
	// during a normal `go test` run the source and the embed are in the
	// same working tree and must match.
	source, err := os.ReadFile("agents-guide.md")
	if err != nil {
		t.Fatalf("read agents-guide.md: %v", err)
	}
	if string(source) != AgentsGuide {
		t.Error("embedded AgentsGuide drifted from repo-root agents-guide.md")
	}
}
