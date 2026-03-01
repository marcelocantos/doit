package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/config"
	"github.com/marcelocantos/doit/internal/ipc"
)

// echoCap writes args joined by spaces to stdout, then copies stdin.
type echoCap struct{ name string }

func (e *echoCap) Name() string                  { return e.name }
func (e *echoCap) Description() string            { return "echo" }
func (e *echoCap) Tier() cap.Tier                 { return cap.TierRead }
func (e *echoCap) Validate([]string) error        { return nil }
func (e *echoCap) Run(_ context.Context, args []string, stdin io.Reader, stdout, _ io.Writer) error {
	if len(args) > 0 {
		fmt.Fprintln(stdout, strings.Join(args, " "))
	}
	io.Copy(stdout, stdin)
	return nil
}

// upperCap reads stdin and writes it uppercased to stdout.
type upperCap struct{}

func (u *upperCap) Name() string                  { return "upper" }
func (u *upperCap) Description() string            { return "uppercase" }
func (u *upperCap) Tier() cap.Tier                 { return cap.TierRead }
func (u *upperCap) Validate([]string) error        { return nil }
func (u *upperCap) Run(_ context.Context, _ []string, stdin io.Reader, stdout, _ io.Writer) error {
	data, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	_, err = stdout.Write([]byte(strings.ToUpper(string(data))))
	return err
}

// slowCap blocks until context is cancelled.
type slowCap struct{}

func (s *slowCap) Name() string                  { return "slow" }
func (s *slowCap) Description() string            { return "blocks until cancelled" }
func (s *slowCap) Tier() cap.Tier                 { return cap.TierRead }
func (s *slowCap) Validate([]string) error        { return nil }
func (s *slowCap) Run(ctx context.Context, _ []string, _ io.Reader, stdout, _ io.Writer) error {
	<-ctx.Done()
	fmt.Fprintln(stdout, "cancelled")
	return ctx.Err()
}

func testRegistry() *cap.Registry {
	reg := cap.NewRegistry()
	reg.Register(&echoCap{name: "echo"})
	reg.Register(&upperCap{})
	reg.Register(&slowCap{})
	return reg
}

func testServer(t *testing.T, idleTimeout time.Duration) (*Server, net.Listener, string) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.jsonl")
	reg := testRegistry()

	// Use /tmp directly for the socket to stay within macOS's 104-char
	// unix socket path limit (t.TempDir() paths can be too long).
	sockDir, err := os.MkdirTemp("", "doit-test-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })

	sockPath := filepath.Join(sockDir, "s.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := New(cfg, reg, nil, idleTimeout)
	return srv, ln, sockPath
}

func sendRequest(t *testing.T, conn net.Conn, req ipc.Request) {
	t.Helper()
	if err := ipc.WriteJSON(conn, ipc.TagRequest, &req); err != nil {
		t.Fatalf("send request: %v", err)
	}
	// Send stdin EOF immediately (no stdin for this request).
	if err := ipc.WriteFrame(conn, ipc.TagStdinEOF, nil); err != nil {
		t.Fatalf("send stdin eof: %v", err)
	}
}

func readUntilExit(t *testing.T, conn net.Conn) (stdout, stderr string, exit ipc.ExitResult) {
	t.Helper()
	var outBuf, errBuf strings.Builder
	for {
		tag, payload, err := ipc.ReadFrame(conn)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		switch tag {
		case ipc.TagStdoutData:
			outBuf.Write(payload)
		case ipc.TagStderrData:
			errBuf.Write(payload)
		case ipc.TagExit:
			if err := json.Unmarshal(payload, &exit); err != nil {
				t.Fatalf("unmarshal exit: %v", err)
			}
			return outBuf.String(), errBuf.String(), exit
		}
	}
}

func TestServerEcho(t *testing.T) {
	srv, ln, sockPath := testServer(t, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx, ln)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	sendRequest(t, conn, ipc.Request{Args: []string{"echo", "hello", "world"}, Cwd: t.TempDir()})
	stdout, _, exit := readUntilExit(t, conn)

	if exit.Code != 0 {
		t.Errorf("exit code = %d, want 0", exit.Code)
	}
	if got := strings.TrimSpace(stdout); got != "hello world" {
		t.Errorf("stdout = %q, want %q", got, "hello world")
	}
}

func TestServerStdinRelay(t *testing.T) {
	srv, ln, sockPath := testServer(t, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx, ln)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send request.
	if err := ipc.WriteJSON(conn, ipc.TagRequest, &ipc.Request{Args: []string{"upper"}, Cwd: t.TempDir()}); err != nil {
		t.Fatalf("send request: %v", err)
	}

	// Send stdin data in chunks.
	if err := ipc.WriteFrame(conn, ipc.TagStdinData, []byte("hello ")); err != nil {
		t.Fatalf("send stdin data: %v", err)
	}
	if err := ipc.WriteFrame(conn, ipc.TagStdinData, []byte("world")); err != nil {
		t.Fatalf("send stdin data: %v", err)
	}
	if err := ipc.WriteFrame(conn, ipc.TagStdinEOF, nil); err != nil {
		t.Fatalf("send stdin eof: %v", err)
	}

	stdout, _, exit := readUntilExit(t, conn)
	if exit.Code != 0 {
		t.Errorf("exit code = %d, want 0", exit.Code)
	}
	if got := strings.TrimSpace(stdout); got != "HELLO WORLD" {
		t.Errorf("stdout = %q, want %q", got, "HELLO WORLD")
	}
}

func TestServerSignalCancelsRequest(t *testing.T) {
	srv, ln, sockPath := testServer(t, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx, ln)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send request for a slow command that blocks until cancelled.
	if err := ipc.WriteJSON(conn, ipc.TagRequest, &ipc.Request{Args: []string{"slow"}, Cwd: t.TempDir()}); err != nil {
		t.Fatalf("send request: %v", err)
	}

	// Give the server a moment to start handling.
	time.Sleep(50 * time.Millisecond)

	// Send signal to cancel.
	if err := ipc.WriteJSON(conn, ipc.TagSignal, ipc.SignalMsg{Signal: "INT"}); err != nil {
		t.Fatalf("send signal: %v", err)
	}

	// Should complete (not hang).
	done := make(chan struct{})
	go func() {
		readUntilExit(t, conn)
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for exit after signal")
	}
}

func TestServerConcurrentConnections(t *testing.T) {
	srv, ln, sockPath := testServer(t, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx, ln)

	const n = 5
	var wg sync.WaitGroup
	wg.Add(n)

	for i := range n {
		go func() {
			defer wg.Done()

			conn, err := net.Dial("unix", sockPath)
			if err != nil {
				t.Errorf("dial %d: %v", i, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("msg-%d", i)
			sendRequest(t, conn, ipc.Request{Args: []string{"echo", msg}, Cwd: t.TempDir()})
			stdout, _, exit := readUntilExit(t, conn)

			if exit.Code != 0 {
				t.Errorf("conn %d: exit code = %d, want 0", i, exit.Code)
			}
			if !strings.Contains(stdout, msg) {
				t.Errorf("conn %d: stdout = %q, want to contain %q", i, stdout, msg)
			}
		}()
	}

	wg.Wait()
}

func TestServerIdleTimeout(t *testing.T) {
	srv, ln, _ := testServer(t, 100*time.Millisecond)

	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ctx, ln)
	}()

	// Server should shut down after idle timeout.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for idle shutdown")
	}
}

func TestServerInvalidFirstFrame(t *testing.T) {
	srv, ln, sockPath := testServer(t, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx, ln)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a non-request frame as the first frame.
	if err := ipc.WriteFrame(conn, ipc.TagStdinData, []byte("bogus")); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, exit := readUntilExit(t, conn)
	if exit.Code != 2 {
		t.Errorf("exit code = %d, want 2", exit.Code)
	}
	if exit.Error == "" {
		t.Error("expected non-empty error in exit result")
	}
}

func TestCleanStaleSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	// No socket — should be a no-op.
	if err := cleanStaleSocket(sockPath); err != nil {
		t.Fatalf("no socket: %v", err)
	}

	// Create a stale socket file (just a regular file, nobody listening).
	if err := os.WriteFile(sockPath, nil, 0600); err != nil {
		t.Fatalf("create fake socket: %v", err)
	}

	if err := cleanStaleSocket(sockPath); err != nil {
		t.Fatalf("stale socket: %v", err)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Error("stale socket should have been removed")
	}
}

func TestCleanStaleSocketLiveDaemon(t *testing.T) {
	dir, err := os.MkdirTemp("", "doit-test-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "s.sock")

	// Start a real listener so the socket is active.
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	err = cleanStaleSocket(sockPath)
	if err == nil {
		t.Fatal("expected error for live socket, got nil")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("error = %q, want to contain 'already running'", err.Error())
	}
}
