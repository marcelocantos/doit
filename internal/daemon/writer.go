package daemon

import (
	"io"
	"sync"

	"github.com/marcelocantos/doit/internal/ipc"
)

// frameWriter wraps an io.Writer to emit tagged IPC frames.
// Multiple frameWriters sharing the same underlying writer and mutex
// are safe for concurrent use (e.g. stdout and stderr from pipeline
// goroutines writing to the same connection).
type frameWriter struct {
	mu  *sync.Mutex
	w   io.Writer
	tag byte
}

func newFrameWriter(w io.Writer, mu *sync.Mutex, tag byte) *frameWriter {
	return &frameWriter{mu: mu, w: w, tag: tag}
}

func (fw *frameWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if err := ipc.WriteFrame(fw.w, fw.tag, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
