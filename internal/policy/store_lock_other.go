// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package policy

// storeLockIsAdvisoryOnly reports whether lockStoreFile provides no
// cross-process exclusion on this platform.
const storeLockIsAdvisoryOnly = true

// lockStoreFile is a no-op on platforms without flock; the in-process
// storeMu still serialises writers within one doit server.
func lockStoreFile(string) (func(), error) {
	return func() {}, nil
}
