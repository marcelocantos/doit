// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const genesisInput = "doit-genesis"

// ErrAuditFull is returned by Log once the audit file has reached
// MaxSizeBytes. Callers must surface it: an unrecorded command is a
// security-of-record gap, not a soft skip (🎯T43).
var ErrAuditFull = errors.New("audit log has reached its size limit")

// sizeCheckInterval is how often (in writes) we check whether the log has
// exceeded MaxSizeBytes.
const sizeCheckInterval = 100

// Logger is an append-only, hash-chained audit log writer.
type Logger struct {
	mu           sync.Mutex
	path         string
	seq          uint64
	prevHash     string
	maxSizeBytes int64 // 0 = unlimited
	writesSince  int   // writes since last size check
	sizeLimitHit bool  // true once the limit has been reached
	// needsNewline is set when the existing file does not end in '\n'
	// (a torn final line). The next append starts with a newline so the
	// torn line stays isolated instead of being glued to a valid entry.
	needsNewline bool
}

// NewLogger opens or creates an audit log at the given path.
// It reads the last entry to resume the hash chain.
// maxSizeBytes controls the maximum file size; 0 means unlimited.
func NewLogger(path string, maxSizeBytes int64) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}

	l := &Logger{
		path:         path,
		prevHash:     genesisHash(),
		maxSizeBytes: maxSizeBytes,
	}

	// Resume the chain from the last parseable entry. A torn final line
	// (crash mid-append) must not silently reset the chain to genesis;
	// Verify and Tail will still report the torn line.
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		l.needsNewline = data[len(data)-1] != '\n'
		lines := splitLines(data)
		for i := len(lines) - 1; i >= 0; i-- {
			var last Entry
			if err := json.Unmarshal(lines[i], &last); err != nil {
				log.Printf("doit: audit log %s: line %d is not valid JSON; resuming chain from the last parseable entry", path, i+1)
				continue
			}
			l.seq = last.Seq
			l.prevHash = last.Hash
			break
		}
	}

	return l, nil
}

// checkSize returns true if the log file has exceeded the configured size limit.
// Must be called with l.mu held.
func (l *Logger) checkSize() bool {
	if l.maxSizeBytes <= 0 {
		return false
	}
	// Once the limit has been hit, re-check every write so that rotating
	// or truncating the file lets logging resume instead of latching the
	// refusal for the life of the process.
	if !l.sizeLimitHit {
		l.writesSince++
		if l.writesSince < sizeCheckInterval {
			return false
		}
		l.writesSince = 0
	}
	info, err := os.Stat(l.path)
	if err != nil {
		l.sizeLimitHit = false
		return false
	}
	if info.Size() >= l.maxSizeBytes {
		if !l.sizeLimitHit {
			log.Printf("doit: audit log %s has reached size limit (%d bytes); further entries will be refused until it is rotated", l.path, l.maxSizeBytes)
		}
		l.sizeLimitHit = true
		return true
	}
	l.sizeLimitHit = false
	return false
}

// Log writes an audit entry to the log file. If opts is non-nil, policy
// evaluation metadata is included in the entry. Returns the assigned sequence
// number so callers can link child entries (e.g. elicitation entries) back to
// this entry via ParentSeq.
func (l *Logger) Log(pipeline string, segments, tiers []string, exitCode int, errMsg string, duration time.Duration, cwd string, retry bool, opts *LogOptions) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.checkSize() {
		return 0, ErrAuditFull
	}

	// Build the entry against the current chain head but do not advance
	// l.seq / l.prevHash until the bytes are on disk: a failed write must
	// leave the in-memory chain exactly where the file is (🎯T43).
	entry := Entry{
		Seq:      l.seq + 1,
		Time:     time.Now().UTC(),
		PrevHash: l.prevHash,
		Pipeline: pipeline,
		Segments: segments,
		Tiers:    tiers,
		Retry:    retry,
		ExitCode: exitCode,
		Error:    errMsg,
		Duration: float64(duration.Microseconds()) / 1000.0,
		Cwd:      cwd,
	}
	if opts != nil {
		entry.PolicyLevel = opts.PolicyLevel
		entry.PolicyResult = opts.PolicyResult
		entry.PolicyRuleID = opts.PolicyRuleID
		entry.Justification = opts.Justification
		entry.SafetyArg = opts.SafetyArg
		entry.ScriptHash = opts.ScriptHash
		entry.ScriptPath = opts.ScriptPath
		entry.ExpectedDuration = opts.ExpectedDuration
		entry.TimedOut = opts.TimedOut
		entry.ProjectRoot = opts.ProjectRoot
		entry.L3Fast = opts.L3Fast
		entry.L3Deep = opts.L3Deep
		entry.ParentSeq = opts.ParentSeq
		entry.ElicitationPrompt = opts.ElicitationPrompt
		entry.ElicitationChoice = opts.ElicitationChoice
		entry.ElicitationLatencyMs = opts.ElicitationLatencyMs
		entry.ProposedRuleSource = opts.ProposedRuleSource
		entry.ProposedRuleGenerality = opts.ProposedRuleGenerality
		entry.ProposedRuleID = opts.ProposedRuleID
		entry.StdoutExcerpt = opts.StdoutExcerpt
		entry.StderrExcerpt = opts.StderrExcerpt
	}

	// Compute hash with Hash field empty.
	entry.Hash = computeHash(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		return 0, fmt.Errorf("marshal audit entry: %w", err)
	}
	data = append(data, '\n')
	if l.needsNewline {
		data = append([]byte{'\n'}, data...)
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return 0, fmt.Errorf("open audit log: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return 0, fmt.Errorf("write audit entry: %w", err)
	}
	if err := f.Close(); err != nil {
		return 0, fmt.Errorf("close audit log: %w", err)
	}

	// Durable: advance the chain head.
	l.seq = entry.Seq
	l.prevHash = entry.Hash
	l.needsNewline = false
	return entry.Seq, nil
}

// Path returns the audit log file path.
func (l *Logger) Path() string {
	return l.path
}

func genesisHash() string {
	h := sha256.Sum256([]byte(genesisInput))
	return fmt.Sprintf("%x", h)
}

func computeHash(e Entry) string {
	e.Hash = "" // hash is computed with this field empty
	data, _ := json.Marshal(e)
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
