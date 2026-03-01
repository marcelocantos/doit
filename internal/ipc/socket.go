package ipc

import (
	"os"
	"path/filepath"
)

// SocketDir returns the directory for the doit daemon socket.
// Prefers $XDG_RUNTIME_DIR/doit/, falls back to ~/.local/share/doit/.
func SocketDir() (string, error) {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "doit"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "doit"), nil
}

// SocketPath returns the full path to the daemon socket file.
func SocketPath() (string, error) {
	dir, err := SocketDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "daemon.sock"), nil
}

// PidPath returns the full path to the daemon PID file.
func PidPath() (string, error) {
	dir, err := SocketDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "daemon.pid"), nil
}
