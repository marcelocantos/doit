// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Package doit is a thin top-level package that exists solely to
// embed the repo-root agents-guide.md. go:embed cannot reach outside
// its own package directory, so cmd/doit/main.go cannot embed the
// guide directly without a pre-build copy step; exporting the content
// from the module root keeps the single-source-of-truth property
// (agents-guide.md lives in the repo root for GitHub rendering and
// README linking) while letting the binary inline it at compile time.
package doit

import _ "embed"

// AgentsGuide is the full text of agents-guide.md, embedded at build
// time. Consumed by `doit --help-agent` and exposed for other tools
// that want to ship the guide alongside the binary.
//
//go:embed agents-guide.md
var AgentsGuide string
