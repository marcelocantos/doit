// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package policy

// flockStore is a no-op on non-Unix platforms: the in-process storeMu still
// serialises mutations within a single process, but cross-process advisory
// locking is unavailable. The returned function is a no-op.
func flockStore(path string) (func(), error) {
	return func() {}, nil
}
