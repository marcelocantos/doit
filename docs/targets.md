# doit — Convergence Targets

## Active

### 🎯T2 sh -c execution model

- **Weight**: 4 (value 4 / cost 1)
- **Status**: identified

Commands are executed via `sh -c` instead of the per-capability pipeline
parser. doit receives opaque command strings and delegates shell composition
to the shell. The pipeline parser (`internal/pipeline/`), unicode operators,
and per-capability `Run()` methods are no longer needed for execution.

**Acceptance criteria**:
- `engine.Execute` can run commands via `sh -c` when given a `Command` string.
- Pipeline parser is used only for policy evaluation (segment extraction),
  not execution.
- Unicode operators are not required for command submission.
- Exit codes are faithfully propagated from `sh -c`.

---

### 🎯T3 Starlark L1 rules

- **Weight**: 3 (value 3 / cost 2)
- **Status**: not started

L1 deterministic rules are expressed in Starlark (sandboxed, deterministic,
Python-like). LLMs can author Starlark rules as part of L3→L1 promotion.
Each rule has a pattern, decision, justification, and test suite.

**Acceptance criteria**:
- Starlark interpreter embedded (e.g. `go.starlark.net`).
- L1 rules loadable from `.star` files.
- Each rule includes test cases that are validated on load.
- L3→L1 promotion generates Starlark code + tests for human review.
- Existing hardcoded Go rules can be expressed equivalently in Starlark.

---

### 🎯T4 Per-project policy

- **Weight**: 2 (value 2 / cost 1)
- **Status**: not started

Policy exists at both global and repo-level scopes. Repo policy can tighten
but not loosen global policy. The gatekeeper discovers repo context from
project structure.

**Acceptance criteria**:
- Config supports per-project overrides (e.g. `.doit/config.yaml` in repo root).
- Repo config can add rules and tighten tiers but cannot remove global rules.
- `engine.New` accepts a project root path for repo-level config discovery.

---

### 🎯T5 Test coverage for core packages

- **Weight**: 3 (value 3 / cost 1)
- **Status**: converging

All core packages have meaningful test coverage. Packages without test files
are covered.

**Acceptance criteria**:
- `internal/cap/` has tests for Registry, Tier, and context helpers.
- `internal/cap/builtin/` has tests for capability registration and tier mapping.
- `internal/cli/` has tests for subcommand dispatch.
- `internal/config/` has tests for YAML loading, defaults, and rule application.
- `cmd/doit/` has at least smoke tests.

**Notes**: Several packages show `[no test files]` in `go test ./...` output:
`cmd/doit`, `cmd/doit-mcp`, `internal/cap`, `internal/cap/builtin`,
`internal/cli`, `internal/config`.

---

### 🎯T6 Clean up legacy code paths

- **Weight**: 1 (value 1 / cost 1)
- **Status**: not started
- **Depends on**: 🎯T1, 🎯T2

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
