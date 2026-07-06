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

// flockStore acquires an exclusive advisory lock covering the learned-policy
// store at path, so two doit processes sharing the same store cannot interleave
// their read-modify-write cycles and lose entries (Fable-5 F7 / 🎯T44). The
// returned function releases the lock; callers must always invoke it.
func flockStore(path string) (func(), error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create policy store dir: %w", err)
	}

	lockPath := path + ".lock"
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
		_ = f.Close()
	}, nil
}
