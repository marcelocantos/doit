// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	"github.com/marcelocantos/doit/internal/audit"
)

// defaultL3MaxChars is used when no cap is configured.
const defaultL3MaxChars = 16384

// truncateField truncates s to maxChars (if maxChars > 0), appending a
// marker that includes the original byte count. Returns the (possibly
// truncated) string, the original length, and whether truncation occurred.
func truncateField(s string, maxChars int) (result string, originalBytes int, truncated bool) {
	if maxChars <= 0 || len(s) <= maxChars {
		return s, len(s), false
	}
	marker := fmt.Sprintf("\n[…truncated, total %d bytes]", len(s))
	cutAt := maxChars - len(marker)
	if cutAt < 0 {
		cutAt = 0
	}
	return s[:cutAt] + marker, len(s), true
}

// buildL3Evidence constructs an L3Evidence block from raw LLM call data,
// applying the size cap from maxChars (0 = no cap).
func buildL3Evidence(model, prompt, response string, latencyMs float64, decision Decision, reason string, maxChars int) *audit.L3Evidence {
	ev := &audit.L3Evidence{
		Model:     model,
		LatencyMs: latencyMs,
		Decision:  decision.String(),
		Reason:    reason,
	}

	truncatedPrompt, origPromptBytes, promptTruncated := truncateField(prompt, maxChars)
	truncatedResponse, origResponseBytes, responseTruncated := truncateField(response, maxChars)

	ev.Prompt = truncatedPrompt
	ev.Response = truncatedResponse

	if promptTruncated || responseTruncated {
		ev.Truncated = true
		if promptTruncated {
			ev.OriginalPromptBytes = origPromptBytes
		}
		if responseTruncated {
			ev.OriginalResponseBytes = origResponseBytes
		}
	}

	return ev
}

// CascadeEvidence holds evidence for one or both tiers of an L3 evaluation.
type CascadeEvidence struct {
	Fast *audit.L3Evidence // always set when L3 fires
	Deep *audit.L3Evidence // set only when the cascade fires both tiers
}
