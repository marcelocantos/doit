# doit — Convergence Targets

## Active

### 🎯T3 Starlark L1 rules

- **Weight**: 3 (value 3 / cost 2)
- **Status**: achieved

L1 deterministic rules are expressed in Starlark (sandboxed, deterministic,
Python-like). LLMs can author Starlark rules as part of L3→L1 promotion.
Each rule has a pattern, decision, justification, and test suite.

**Acceptance criteria**:
- [x] Starlark interpreter embedded (`go.starlark.net`).
- [x] L1 rules loadable from `.star` files (`internal/starlark/loader.go`).
- [x] Each rule includes test cases that are validated on load.
- [x] L3→L1 promotion generates Starlark code + tests (`internal/starlark/generator.go`).
- [x] Existing hardcoded Go rules expressed equivalently in Starlark (`rules/*.star`).

---

### 🎯T6 Clean up legacy code paths

- **Weight**: 1 (value 1 / cost 1)
- **Status**: not started

Once MCP is the sole entry point and sh -c is the execution model, remove
the legacy code: `internal/daemon/`, `internal/client/`, `internal/ipc/`,
unicode operator constants, and the pipeline execution engine (retain parser
for policy segment extraction only).

**Acceptance criteria**:
- `internal/daemon/`, `internal/client/`, `internal/ipc/` are removed.
- Unicode operator constants in `internal/pipeline/types.go` are removed.
- Pipeline execution code is removed; only parsing for policy evaluation remains.
- All tests pass after removal.

## Achieved

### 🎯T1 MCP-first architecture

- **Weight**: 5 (value 5 / cost 1)
- **Status**: achieved

All four MCP tools registered and tested. `engine/` and `mcptools/` packages
importable. `cmd/doit-mcp/` binary exists. 9 integration tests passing.
Legacy daemon/IPC removal gated by 🎯T6.

### 🎯T2 sh -c execution model

- **Weight**: 4 (value 4 / cost 1)
- **Status**: achieved

`engine.Execute` dispatches via `sh -c` when `Request.Command` is set and
`Request.Args` is empty. Pipeline parser retained for policy evaluation only.
Exit codes faithfully propagated. 6 engine tests covering shell execution.
Merged in PR #5 (`a7c0506`).

### 🎯T5 Test coverage for core packages

- **Weight**: 3 (value 3 / cost 1)
- **Status**: achieved

All 5 acceptance criteria met. `internal/cap/`, `internal/cap/builtin/`,
`internal/cli/`, `internal/config/` have comprehensive tests. `cmd/doit/`
has subprocess-based smoke tests. `cmd/doit-mcp/` exercised via MCP
integration tests in `mcptools/integration_test.go`.

### 🎯T4 Per-project policy

- **Weight**: 2 (value 2 / cost 1)
- **Status**: achieved

`.doit/config.yaml` in project root, tighten-only merge semantics.
`LoadProject()`, `MergeProject()`, `Options.ProjectRoot` in `engine.New()`.
Comprehensive tests for merge semantics, flag dedup, and edge cases.
