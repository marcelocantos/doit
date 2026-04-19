// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package engine

import "os/exec"

// configureProcessGroup is a no-op on non-Unix platforms. The default
// exec.CommandContext behaviour (SIGKILL to the direct child) applies.
func configureProcessGroup(cmd *exec.Cmd) {}
