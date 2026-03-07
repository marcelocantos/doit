# Convergence Report

Generated: 2026-03-06
Branch: master
SHA: 1ce61f6

## Standing invariants

- Tests: PASSING (`go test ./...` — all green)
- CI: not checked (no open PRs)

## Gap Report

### 🎯T1 MCP-first architecture  [high, effective 6.0]
Gap: **close**

Most acceptance criteria are met: `engine/` and `mcptools/` packages exist
and are importable, `cmd/doit-mcp/main.go` binary exists, all four MCP tools
are registered. Integration tests exist but are untracked
(`mcptools/integration_test.go`). The old daemon/client/IPC code is still
present but can be removed once MCP is sole entry point (gated by 🎯T6).
Remaining work: commit the integration test file.

### 🎯T2 sh -c execution model  [high, effective 5.0]
Gap: **significant**

`engine.Execute` currently delegates to the pipeline parser for execution.
No `sh -c` code path exists yet. The `Request.Command` field is split via
`strings.Fields` — it doesn't go through `sh -c`. All execution still flows
through `pipeline.ExecuteCommand` with per-capability `Run()` methods.

### 🎯T5 Test coverage for core packages  [medium, effective 3.0]
Gap: **significant**

6 packages have no test files: `cmd/doit`, `cmd/doit-mcp`, `internal/cap`,
`internal/cap/builtin`, `internal/cli`, `internal/config`. The packages that
do have tests pass.

### 🎯T4 Per-project policy  [medium, effective 2.0]  (status only)
Status: not started

### 🎯T3 Starlark L1 rules  [medium, effective 1.5]  (status only)
Status: not started

### 🎯T6 Clean up legacy code paths  [low, effective 1.0]  (blocked)
Status: not started
Blocked by: 🎯T1, 🎯T2

## Recommendation

Work on: **🎯T1 MCP-first architecture**

Reason: Highest effective weight (6.0), already close to achieved, and
unblocks 🎯T6. The integration test file just needs to be committed, and
the daemon testdata needs to be tracked or gitignored.

## Suggested action

Commit the untracked files (`internal/daemon/testdata/` and
`mcptools/integration_test.go`), then verify the integration tests pass
with `go test ./mcptools/ -run TestIntegration -v`. If everything passes,
🎯T1 moves to achieved.

Type **go** to execute the suggested action.

<!-- convergence-deps
evaluated: 2026-03-06T00:00:00Z
sha: 1ce61f6

🎯T1:
  gap: close
  assessment: "Engine, mcptools, and doit-mcp binary exist. Integration tests untracked but written. Old daemon/client/IPC still present."
  read:
    - engine/engine.go
    - mcptools/mcptools.go
    - mcptools/integration_test.go
    - cmd/doit-mcp/main.go

🎯T2:
  gap: significant
  assessment: "No sh -c execution path. All execution via pipeline parser."
  read:
    - engine/engine.go

🎯T5:
  gap: significant
  assessment: "6 packages lack test files."
  read: []

🎯T4:
  gap: not started
  assessment: "No per-project config support."
  read: []

🎯T3:
  gap: not started
  assessment: "No Starlark integration."
  read: []

🎯T6:
  gap: not started
  assessment: "Blocked by T1 and T2. Legacy code still present."
  read:
    - internal/daemon/server.go
    - internal/client/client.go
    - internal/ipc/protocol.go
-->
