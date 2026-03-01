package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marcelocantos/doit/internal/audit"
	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/cli"
	"github.com/marcelocantos/doit/internal/config"
	"github.com/marcelocantos/doit/internal/ipc"
)

// Server is the persistent daemon process that accepts IPC connections
// and executes commands on behalf of CLI clients.
type Server struct {
	cfg         *config.Config
	reg         *cap.Registry
	logger      *audit.Logger
	idleTimeout time.Duration

	mu        sync.Mutex
	idleTimer *time.Timer
	active    sync.WaitGroup
}

// New creates a daemon server.
func New(cfg *config.Config, reg *cap.Registry, logger *audit.Logger, idleTimeout time.Duration) *Server {
	return &Server{
		cfg:         cfg,
		reg:         reg,
		logger:      logger,
		idleTimeout: idleTimeout,
	}
}

// Run creates a listener at the standard socket path and calls Serve.
func (s *Server) Run(ctx context.Context) error {
	sockPath, err := ipc.SocketPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(sockPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	if err := cleanStaleSocket(sockPath); err != nil {
		return err
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	if err := os.Chmod(sockPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	if err := writePidFile(); err != nil {
		ln.Close()
		return fmt.Errorf("write pid: %w", err)
	}

	defer func() {
		os.Remove(sockPath)
		if pidPath, err := ipc.PidPath(); err == nil {
			os.Remove(pidPath)
		}
	}()

	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled or the idle timer
// fires. The listener is closed on return. This method is exported for
// testability — tests pass a listener on a temp socket.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()

	// Idle timer cancels idleCtx when no connections arrive for idleTimeout.
	idleCtx, idleCancel := context.WithCancel(ctx)
	defer idleCancel()

	s.mu.Lock()
	s.idleTimer = time.AfterFunc(s.idleTimeout, idleCancel)
	s.mu.Unlock()

	// Close the listener when the context is done (idle or parent cancel).
	go func() {
		<-idleCtx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check if this is a clean shutdown.
			select {
			case <-idleCtx.Done():
				s.active.Wait()
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		s.resetIdle()

		s.active.Add(1)
		go func() {
			defer s.active.Done()
			defer conn.Close()
			defer s.resetIdle()
			s.handleConnection(idleCtx, conn)
		}()
	}
}

func (s *Server) resetIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idleTimer != nil {
		s.idleTimer.Reset(s.idleTimeout)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	// Read request frame.
	tag, payload, err := ipc.ReadFrame(conn)
	if err != nil {
		writeExit(conn, 2, fmt.Sprintf("read request: %v", err))
		return
	}
	if tag != ipc.TagRequest {
		writeExit(conn, 2, fmt.Sprintf("expected request frame (0x%02x), got 0x%02x", ipc.TagRequest, tag))
		return
	}

	var req ipc.Request
	if err := json.Unmarshal(payload, &req); err != nil {
		writeExit(conn, 2, fmt.Sprintf("unmarshal request: %v", err))
		return
	}

	// Per-request context with cancellation for signal handling.
	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()

	// Stdin pipe: demux goroutine writes to it, RunCommand reads from it.
	stdinR, stdinW := io.Pipe()

	// Demux goroutine: reads stdin data, stdin EOF, and signal frames.
	go func() {
		defer stdinW.Close()
		for {
			t, p, err := ipc.ReadFrame(conn)
			if err != nil {
				return
			}
			switch t {
			case ipc.TagStdinData:
				if _, err := stdinW.Write(p); err != nil {
					return
				}
			case ipc.TagStdinEOF:
				return
			case ipc.TagSignal:
				var sig ipc.SignalMsg
				if json.Unmarshal(p, &sig) == nil && sig.Signal == "INT" {
					reqCancel()
				}
			}
		}
	}()

	// Stdout and stderr frame writers share a mutex on the connection
	// to prevent interleaved frame bytes from concurrent goroutines.
	var connMu sync.Mutex
	stdoutW := newFrameWriter(conn, &connMu, ipc.TagStdoutData)
	stderrW := newFrameWriter(conn, &connMu, ipc.TagStderrData)

	exitCode := cli.RunCommand(reqCtx, s.reg, s.logger, req.Args,
		stdinR, stdoutW, stderrW, req.Retry, req.Cwd, req.Env)

	connMu.Lock()
	defer connMu.Unlock()
	ipc.WriteJSON(conn, ipc.TagExit, ipc.ExitResult{Code: exitCode})
}

func writeExit(conn net.Conn, code int, msg string) {
	ipc.WriteJSON(conn, ipc.TagExit, ipc.ExitResult{Code: code, Error: msg})
}
