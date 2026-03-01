package client

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/marcelocantos/doit/internal/ipc"
)

// mockServer simulates a daemon on the server side of a net.Pipe.
// It reads a Request, sends back stdout data and an Exit frame.
func mockServer(t *testing.T, conn net.Conn, handler func(req ipc.Request, stdinData []byte) (stdout, stderr string, code int)) {
	t.Helper()
	defer conn.Close()

	// Read request frame.
	tag, payload, err := ipc.ReadFrame(conn)
	if err != nil {
		t.Errorf("mock: read request: %v", err)
		return
	}
	if tag != ipc.TagRequest {
		t.Errorf("mock: expected TagRequest, got 0x%02x", tag)
		return
	}

	var req ipc.Request
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Errorf("mock: unmarshal request: %v", err)
		return
	}

	// Read stdin until EOF.
	var stdinBuf []byte
	for {
		tag, payload, err := ipc.ReadFrame(conn)
		if err != nil {
			break
		}
		switch tag {
		case ipc.TagStdinData:
			stdinBuf = append(stdinBuf, payload...)
		case ipc.TagStdinEOF:
			goto stdinDone
		}
	}
stdinDone:

	stdout, stderr, code := handler(req, stdinBuf)

	if stdout != "" {
		ipc.WriteFrame(conn, ipc.TagStdoutData, []byte(stdout))
	}
	if stderr != "" {
		ipc.WriteFrame(conn, ipc.TagStderrData, []byte(stderr))
	}
	ipc.WriteJSON(conn, ipc.TagExit, ipc.ExitResult{Code: code})
}

func TestRelayBasic(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mockServer(t, serverConn, func(req ipc.Request, stdin []byte) (string, string, int) {
			return "hello world\n", "", 0
		})
	}()

	req := &ipc.Request{Args: []string{"echo", "hello", "world"}, Cwd: "/tmp"}
	var stdout, stderr strings.Builder
	result, err := Relay(context.Background(), clientConn, req, strings.NewReader(""), &stdout, &stderr)
	clientConn.Close()
	wg.Wait()

	if err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if result.Code != 0 {
		t.Errorf("code = %d, want 0", result.Code)
	}
	if got := strings.TrimSpace(stdout.String()); got != "hello world" {
		t.Errorf("stdout = %q, want %q", got, "hello world")
	}
}

func TestRelayWithStdin(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mockServer(t, serverConn, func(req ipc.Request, stdin []byte) (string, string, int) {
			return strings.ToUpper(string(stdin)), "", 0
		})
	}()

	req := &ipc.Request{Args: []string{"upper"}, Cwd: "/tmp"}
	var stdout, stderr strings.Builder
	result, err := Relay(context.Background(), clientConn, req, strings.NewReader("hello world"), &stdout, &stderr)
	clientConn.Close()
	wg.Wait()

	if err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if result.Code != 0 {
		t.Errorf("code = %d, want 0", result.Code)
	}
	if got := stdout.String(); got != "HELLO WORLD" {
		t.Errorf("stdout = %q, want %q", got, "HELLO WORLD")
	}
}

func TestRelayStderrInterleaved(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mockServer(t, serverConn, func(req ipc.Request, stdin []byte) (string, string, int) {
			return "output\n", "warning\n", 0
		})
	}()

	req := &ipc.Request{Args: []string{"cmd"}, Cwd: "/tmp"}
	var stdout, stderr strings.Builder
	result, err := Relay(context.Background(), clientConn, req, strings.NewReader(""), &stdout, &stderr)
	clientConn.Close()
	wg.Wait()

	if err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if result.Code != 0 {
		t.Errorf("code = %d, want 0", result.Code)
	}
	if got := strings.TrimSpace(stdout.String()); got != "output" {
		t.Errorf("stdout = %q, want %q", got, "output")
	}
	if got := strings.TrimSpace(stderr.String()); got != "warning" {
		t.Errorf("stderr = %q, want %q", got, "warning")
	}
}

func TestRelayNonZeroExit(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mockServer(t, serverConn, func(req ipc.Request, stdin []byte) (string, string, int) {
			return "", "error occurred\n", 1
		})
	}()

	req := &ipc.Request{Args: []string{"fail"}, Cwd: "/tmp"}
	var stdout, stderr strings.Builder
	result, err := Relay(context.Background(), clientConn, req, strings.NewReader(""), &stdout, &stderr)
	clientConn.Close()
	wg.Wait()

	if err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if result.Code != 1 {
		t.Errorf("code = %d, want 1", result.Code)
	}
}

func TestRelayServerDisconnect(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// Server closes immediately — no response.
	serverConn.Close()

	req := &ipc.Request{Args: []string{"echo"}, Cwd: "/tmp"}
	var stdout, stderr strings.Builder
	_, err := Relay(context.Background(), clientConn, req, strings.NewReader(""), &stdout, &stderr)
	clientConn.Close()

	if err == nil {
		t.Error("expected error for server disconnect, got nil")
	}
}

func TestConnectNoSocket(t *testing.T) {
	// Override XDG_RUNTIME_DIR to a temp dir with no socket.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	_, err := Connect()
	if err == nil {
		t.Error("expected error connecting to nonexistent socket, got nil")
	}
}

func TestRelayLargeStdin(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mockServer(t, serverConn, func(req ipc.Request, stdin []byte) (string, string, int) {
			return string(stdin), "", 0
		})
	}()

	// 256KB of input.
	largeInput := strings.Repeat("x", 256*1024)
	req := &ipc.Request{Args: []string{"cat"}, Cwd: "/tmp"}
	var stdout, stderr strings.Builder
	result, err := Relay(context.Background(), clientConn, req, strings.NewReader(largeInput), &stdout, &stderr)
	clientConn.Close()
	wg.Wait()

	if err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if result.Code != 0 {
		t.Errorf("code = %d, want 0", result.Code)
	}
	if got := stdout.String(); got != largeInput {
		t.Errorf("stdout length = %d, want %d", len(got), len(largeInput))
	}
}

func TestRelayEmptyStdin(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mockServer(t, serverConn, func(req ipc.Request, stdin []byte) (string, string, int) {
			if len(stdin) != 0 {
				return "", "expected empty stdin", 1
			}
			return "ok\n", "", 0
		})
	}()

	req := &ipc.Request{Args: []string{"cmd"}, Cwd: "/tmp"}
	var stdout, stderr strings.Builder
	result, err := Relay(context.Background(), clientConn, req, io.LimitReader(strings.NewReader(""), 0), &stdout, &stderr)
	clientConn.Close()
	wg.Wait()

	if err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if result.Code != 0 {
		t.Errorf("code = %d, want 0; stderr: %s", result.Code, stderr.String())
	}
}
