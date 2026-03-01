package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Frame tags identify the type of each IPC message.
// Client-to-server tags are in the 0x01-0x0F range.
// Server-to-client tags are in the 0x10-0x1F range.
const (
	TagRequest   byte = 0x01 // C→S: JSON-encoded Request
	TagStdinData byte = 0x02 // C→S: raw stdin bytes
	TagStdinEOF  byte = 0x03 // C→S: stdin closed (no payload)
	TagSignal    byte = 0x04 // C→S: JSON-encoded SignalMsg

	TagStdoutData byte = 0x10 // S→C: raw stdout bytes
	TagStderrData byte = 0x11 // S→C: raw stderr bytes
	TagExit       byte = 0x12 // S→C: JSON-encoded ExitResult
)

// Request is the initial frame sent by the client to the daemon.
type Request struct {
	Args  []string          `json:"args"`
	Cwd   string            `json:"cwd"`
	Retry bool              `json:"retry,omitempty"`
	Env   map[string]string `json:"env,omitempty"`
}

// ExitResult is sent by the daemon when command execution completes.
type ExitResult struct {
	Code  int    `json:"code"`
	Error string `json:"error,omitempty"`
}

// SignalMsg carries a signal name from client to daemon.
type SignalMsg struct {
	Signal string `json:"signal"`
}

// WriteFrame writes a tagged frame: [tag:1][len:4 big-endian][payload:len].
func WriteFrame(w io.Writer, tag byte, payload []byte) error {
	var header [5]byte
	header[0] = tag
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("write frame payload: %w", err)
		}
	}
	return nil
}

// ReadFrame reads one tagged frame, returning the tag and payload.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	tag := header[0]
	length := binary.BigEndian.Uint32(header[1:])
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, fmt.Errorf("read frame payload: %w", err)
		}
	}
	return tag, payload, nil
}

// WriteJSON writes a tagged frame with a JSON-encoded payload.
func WriteJSON(w io.Writer, tag byte, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	return WriteFrame(w, tag, data)
}
