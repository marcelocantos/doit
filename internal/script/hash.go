// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package script

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// HashPrefix is prepended to every hash so the encoding is self-describing.
const HashPrefix = "sha256:"

// previewMaxBytes caps how much of the script is displayed in elicitation
// previews. Large enough to show typical script headers without overwhelming
// the UI.
const previewMaxBytes = 2048

// previewMaxLines further caps the preview length by line count.
const previewMaxLines = 40

// Hash computes the SHA-256 content hash of the file at path, returned
// as "sha256:<hex>".
func Hash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open script %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash script %s: %w", path, err)
	}
	return HashPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// Preview returns a human-readable preview of the script contents,
// truncated to previewMaxBytes/previewMaxLines whichever is smaller.
// Returns a marker comment if the file is binary (contains NUL bytes or
// is not valid UTF-8).
func Preview(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read script %s: %w", path, err)
	}

	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return fmt.Sprintf("<binary content, %d bytes>", len(data)), nil
	}

	if len(data) > previewMaxBytes {
		data = data[:previewMaxBytes]
	}

	lines := strings.SplitAfter(string(data), "\n")
	if len(lines) > previewMaxLines {
		lines = lines[:previewMaxLines]
		return strings.Join(lines, "") + fmt.Sprintf("... (truncated at %d lines)\n", previewMaxLines), nil
	}
	out := strings.Join(lines, "")
	if len(data) == previewMaxBytes {
		out += fmt.Sprintf("... (truncated at %d bytes)\n", previewMaxBytes)
	}
	return out, nil
}

// ShortHash returns the first 12 hex characters after the "sha256:" prefix
// for display purposes. Never used for identity matching.
func ShortHash(h string) string {
	if !strings.HasPrefix(h, HashPrefix) {
		return h
	}
	rest := h[len(HashPrefix):]
	if len(rest) > 12 {
		rest = rest[:12]
	}
	return HashPrefix + rest
}
