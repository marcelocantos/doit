package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/marcelocantos/doit/internal/ipc"
)

// Relay sends a request to the daemon and relays stdin/stdout/stderr.
// Returns the daemon's exit code.
func Relay(ctx context.Context, conn net.Conn, req *ipc.Request,
	stdin io.Reader, stdout, stderr io.Writer) (int, error) {

	if err := ipc.WriteJSON(conn, ipc.TagRequest, req); err != nil {
		return 2, fmt.Errorf("send request: %w", err)
	}

	// Stdin pump goroutine: reads from stdin, sends StdinData frames,
	// sends StdinEOF when done.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stdin.Read(buf)
			if n > 0 {
				if writeErr := ipc.WriteFrame(conn, ipc.TagStdinData, buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				ipc.WriteFrame(conn, ipc.TagStdinEOF, nil)
				return
			}
		}
	}()

	// Demux loop: reads daemon frames, dispatches to stdout/stderr,
	// returns on Exit frame.
	var exitResult ipc.ExitResult
	for {
		tag, payload, err := ipc.ReadFrame(conn)
		if err != nil {
			wg.Wait()
			return 2, fmt.Errorf("read daemon frame: %w", err)
		}
		switch tag {
		case ipc.TagStdoutData:
			stdout.Write(payload)
		case ipc.TagStderrData:
			stderr.Write(payload)
		case ipc.TagExit:
			if err := json.Unmarshal(payload, &exitResult); err != nil {
				wg.Wait()
				return 2, fmt.Errorf("unmarshal exit: %w", err)
			}
			wg.Wait()
			return exitResult.Code, nil
		}
	}
}

// Connect attempts to connect to a running daemon.
func Connect() (net.Conn, error) {
	sockPath, err := ipc.SocketPath()
	if err != nil {
		return nil, err
	}
	return net.Dial("unix", sockPath)
}

// ConnectOrSpawn tries to connect to an existing daemon. If none is
// running, it spawns one as a detached child and retries with backoff.
func ConnectOrSpawn(ctx context.Context, selfPath string) (net.Conn, error) {
	if conn, err := Connect(); err == nil {
		return conn, nil
	}

	// Spawn daemon.
	cmd := exec.Command(selfPath, "--daemon")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	setSysProcAttr(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn daemon: %w", err)
	}
	cmd.Process.Release()

	// Backoff retry.
	delays := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		500 * time.Millisecond,
	}
	for _, d := range delays {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(d):
		}
		if conn, err := Connect(); err == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("daemon did not start within timeout")
}
