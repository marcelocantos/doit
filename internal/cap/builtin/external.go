package builtin

import (
	"context"
	"io"
	"os"
	"os/exec"
)

// ExitError represents a command that exited with a non-zero status.
// It carries the exit code so callers can propagate it without extra messaging.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return "" // intentionally empty — the command's own stderr is sufficient
}

// runExternal executes an external command with streaming I/O.
// Non-zero exit codes are returned as *ExitError so callers can propagate
// the code directly. Other errors (e.g. command not found) are returned as-is.
func runExternal(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	if stderr != nil {
		cmd.Stderr = stderr
	} else {
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return &ExitError{Code: exitErr.ExitCode()}
		}
		return err
	}
	return nil
}
