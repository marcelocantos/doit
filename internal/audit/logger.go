package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const genesisInput = "doit-genesis"

// Logger is an append-only, hash-chained audit log writer.
type Logger struct {
	mu       sync.Mutex
	path     string
	seq      uint64
	prevHash string
}

// NewLogger opens or creates an audit log at the given path.
// It reads the last entry to resume the hash chain.
func NewLogger(path string) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}

	l := &Logger{
		path:     path,
		prevHash: genesisHash(),
	}

	// Read existing log to find last entry.
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		lines := splitLines(data)
		if len(lines) > 0 {
			var last Entry
			if err := json.Unmarshal(lines[len(lines)-1], &last); err == nil {
				l.seq = last.Seq
				l.prevHash = last.Hash
			}
		}
	}

	return l, nil
}

// Log writes an audit entry to the log file.
func (l *Logger) Log(pipeline string, segments, tiers []string, exitCode int, errMsg string, duration time.Duration, cwd string, retry bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	entry := Entry{
		Seq:      l.seq,
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

	// Compute hash with Hash field empty.
	entry.Hash = computeHash(entry)
	l.prevHash = entry.Hash

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	data = append(data, '\n')

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return nil
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
