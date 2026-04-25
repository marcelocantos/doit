// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

// Base provides default implementations of optional Capability methods.
// Embed Base in a capability struct to satisfy the full interface without
// repeating boilerplate. All defaults are false/no-op.
type Base struct{}

// RedactOutput returns false. Override in a capability struct to return
// true when the capability handles sensitive data (credentials, secrets)
// whose output must never appear in audit excerpts.
func (Base) RedactOutput() bool { return false }
