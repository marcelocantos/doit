package daemon

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/marcelocantos/doit/internal/ipc"
)

func writePidFile() error {
	path, err := ipc.PidPath()
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600)
}

// cleanStaleSocket removes a socket file if no process is listening on it.
// Returns an error if a live daemon is detected.
func cleanStaleSocket(sockPath string) error {
	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		return nil
	}

	// Try connecting — if it succeeds, a daemon is already running.
	conn, err := net.Dial("unix", sockPath)
	if err == nil {
		conn.Close()
		return fmt.Errorf("daemon already running (socket %s is active)", sockPath)
	}

	// Check PID file for extra safety.
	pidPath, err := ipc.PidPath()
	if err == nil {
		if data, err := os.ReadFile(pidPath); err == nil {
			if pid, err := strconv.Atoi(string(data)); err == nil {
				proc, err := os.FindProcess(pid)
				if err == nil {
					if err := proc.Signal(syscall.Signal(0)); err == nil {
						return fmt.Errorf("daemon already running (pid %d)", pid)
					}
				}
			}
		}
	}

	// Stale socket — remove it.
	return os.Remove(sockPath)
}
