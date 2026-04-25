// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

const redactedMarker = "<redacted: capability marked sensitive>"

// captureWriter is an io.Writer that captures up to cap bytes into a buffer,
// counting total bytes written to report truncation.
type captureWriter struct {
	buf   bytes.Buffer
	cap   int
	total int
}

func (c *captureWriter) Write(p []byte) (int, error) {
	c.total += len(p)
	if c.buf.Len() < c.cap {
		space := c.cap - c.buf.Len()
		if len(p) <= space {
			c.buf.Write(p)
		} else {
			c.buf.Write(p[:space])
		}
	}
	return len(p), nil
}

// excerpt returns the captured content, appending a truncation marker when
// the total byte count exceeded the cap. It ensures the returned string is
// valid UTF-8 by trimming trailing incomplete multi-byte rune sequences.
func (c *captureWriter) excerpt() string {
	data := c.buf.Bytes()
	if c.total > c.cap {
		// Walk back until the prefix is valid UTF-8. A single-pass approach:
		// find the longest valid prefix by trimming from the end.
		for len(data) > 0 && !utf8.Valid(data) {
			data = data[:len(data)-1]
		}
		return string(data) + fmt.Sprintf("\n[\u2026truncated, total %d bytes]", c.total)
	}
	return string(data)
}

// shouldCapture reports whether output capture is enabled for this execution,
// given the config setting and the failure condition of the command.
// captureMode is one of "always", "on_failure", "never".
// failure is true when exit_code != 0, policy_result == "deny", or timed_out.
func shouldCapture(captureMode string, failure bool) bool {
	switch captureMode {
	case "always":
		return true
	case "never":
		return false
	default: // "on_failure" and any unrecognised value
		return failure
	}
}
