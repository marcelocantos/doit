// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package engine

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup prepares cmd so that its entire process group
// is killed on context cancellation, not just the direct child. This
// matters for cases like `sh -c "bash foo.sh"` where a naive SIGKILL
// to sh leaves bash (and its children) running as orphans.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid signals the whole process group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
