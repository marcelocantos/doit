# doit — Convergence Targets

## Active

(none)

## Achieved

### 🎯T1 MCP-first architecture

- **Weight**: 5 (value 5 / cost 1)
- **Status**: achieved

All four MCP tools registered and tested. `engine/` and `mcptools/` packages
importable. `cmd/doit-mcp/` binary exists. 9 integration tests passing.

### 🎯T2 sh -c execution model

- **Weight**: 4 (value 4 / cost 1)
- **Status**: achieved

`engine.Execute` dispatches via `sh -c` when `Request.Command` is set and
`Request.Args` is empty. Pipeline parser retained for policy evaluation only.
Exit codes faithfully propagated. 6 engine tests covering shell execution.
Merged in PR #5 (`a7c0506`).

### 🎯T3 Starlark L1 rules

- **Weight**: 3 (value 3 / cost 2)
- **Status**: achieved

Starlark interpreter embedded (`go.starlark.net`). L1 rules loadable from
`.star` files with embedded test cases validated on load. L3→L1 promotion
generates Starlark code + tests. 5 example rules in `rules/` equivalent
to existing hardcoded Go rules.

### 🎯T4 Per-project policy

- **Weight**: 2 (value 2 / cost 1)
- **Status**: achieved

`.doit/config.yaml` in project root, tighten-only merge semantics.
`LoadProject()`, `MergeProject()`, `Options.ProjectRoot` in `engine.New()`.
Comprehensive tests for merge semantics, flag dedup, and edge cases.

### 🎯T5 Test coverage for core packages

- **Weight**: 3 (value 3 / cost 1)
- **Status**: achieved

All 5 acceptance criteria met. `internal/cap/`, `internal/cap/builtin/`,
`internal/cli/`, `internal/config/` have comprehensive tests. `cmd/doit/`
has subprocess-based smoke tests. `cmd/doit-mcp/` exercised via MCP
integration tests in `mcptools/integration_test.go`.

### 🎯T6 Clean up legacy code paths

- **Weight**: 1 (value 1 / cost 1)
- **Status**: achieved

`internal/daemon/`, `internal/client/`, `internal/ipc/` removed. Pipeline
executor removed; parser retained for policy evaluation. ~2,454 lines deleted.
All tests pass.
