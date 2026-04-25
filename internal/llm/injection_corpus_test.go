// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package llm_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/marcelocantos/doit/internal/policy"
)

// xmlEscapeForTest mirrors the escaping logic used in policy.buildPrompt.
// We duplicate it here so the test can check the escaped form inside tags.
func xmlEscapeForTest(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

// corpusPayload is one entry in the injection corpus YAML.
type corpusPayload struct {
	ID                   string `yaml:"id"`
	Kind                 string `yaml:"kind"` // "command", "justification", "safety_argument"
	Payload              string `yaml:"payload"`
	ExpectedContainment  string `yaml:"expected_containment"`
}

type injectionCorpus struct {
	Payloads []corpusPayload `yaml:"payloads"`
}

// TestInjectionCorpusPromptContainment loads the corpus and for each payload
// renders the L3 prompt template, then asserts structural containment:
//
//  1. The payload appears verbatim inside the expected XML data tag.
//  2. The payload does NOT appear in the prompt text before the opening
//     data tag (i.e. it is not at instruction level).
//
// This test does NOT invoke a live LLM. It verifies only that the renderer
// wraps adversarial inputs in data tags so they cannot reach the instruction
// section of the prompt. Whether the LLM honours that framing is a separate
// concern (documented as future regression testing work in docs/l3-injection.md).
func TestInjectionCorpusPromptContainment(t *testing.T) {
	corpusPath := filepath.Join("testdata", "injection_corpus.yaml")
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}

	var corpus injectionCorpus
	if err := yaml.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(corpus.Payloads) == 0 {
		t.Fatal("corpus is empty")
	}

	for _, p := range corpus.Payloads {
		p := p
		t.Run(p.ID, func(t *testing.T) {
			req := &policy.Request{}
			switch p.Kind {
			case "command":
				req.Command = p.Payload
			case "justification":
				req.Command = "ls"
				req.Justification = p.Payload
			case "safety_argument":
				req.Command = "ls"
				req.SafetyArg = p.Payload
			default:
				t.Fatalf("unknown kind %q", p.Kind)
			}

			prompt := policy.BuildPromptForTest(req, false)

			openTag := "<" + kindToTag(t, p.Kind) + ">"
			closeTag := "</" + kindToTag(t, p.Kind) + ">"

			// The opening tag must be present.
			openIdx := strings.Index(prompt, openTag)
			if openIdx == -1 {
				t.Fatalf("prompt missing opening tag %q", openTag)
			}

			// The closing tag must follow the opening tag.
			closeIdx := strings.Index(prompt[openIdx:], closeTag)
			if closeIdx == -1 {
				t.Fatalf("prompt missing closing tag %q after %q", closeTag, openTag)
			}
			closeIdx += openIdx // absolute position

			// Extract the data section between the tags.
			dataSection := prompt[openIdx+len(openTag) : closeIdx]

			// The payload (trimmed and XML-escaped) must appear inside the
			// data section. The renderer XML-escapes all data values so that
			// tag-injection characters (<, >) cannot break out of their wrapper.
			trimmedPayload := strings.TrimRight(p.Payload, "\n")
			escapedPayload := xmlEscapeForTest(trimmedPayload)
			if !strings.Contains(dataSection, escapedPayload) {
				t.Errorf("escaped payload not found inside data tag\nraw payload:     %q\nescaped payload: %q\ndata section:    %q",
					trimmedPayload, escapedPayload, dataSection)
			}

			// The raw (unescaped) payload must NOT appear before the opening
			// data tag (i.e. it must not be at instruction level).
			instructionSection := prompt[:openIdx]
			if strings.Contains(instructionSection, trimmedPayload) {
				t.Errorf("payload leaked into instruction section (before %q)\npayload: %q\ninstruction section: %q",
					openTag, trimmedPayload, instructionSection)
			}
		})
	}
}

// kindToTag maps a corpus payload kind to its XML tag name.
func kindToTag(t *testing.T, kind string) string {
	t.Helper()
	switch kind {
	case "command":
		return "command"
	case "justification":
		return "justification"
	case "safety_argument":
		return "safety_argument"
	default:
		t.Fatalf("unknown kind %q", kind)
		return ""
	}
}
