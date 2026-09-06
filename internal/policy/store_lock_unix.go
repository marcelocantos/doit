// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// storeLockIsAdvisoryOnly reports whether lockStoreFile provides no
// cross-process exclusion on this platform.
const storeLockIsAdvisoryOnly = false

// lockStoreFile takes an exclusive advisory flock on lockPath, creating
// it if needed, and returns the release function. It blocks until the
// lock is available.
func lockStoreFile(lockPath string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		return nil, fmt.Errorf("create policy store dir: %w", err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open policy store lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock policy store: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
