# Convergence Report

Generated: 2026-03-07
Branch: master
SHA: d8b6948

## Standing invariants: all green

## Movement

- 🎯T1: close → **achieved** (integration tests committed, all passing)
- 🎯T2: (unchanged)
- 🎯T5: (unchanged)
- 🎯T3: (unchanged)
- 🎯T4: (unchanged)
- 🎯T6: (unchanged)

## Gap Report

### 🎯T1 MCP-first architecture  [high, effective 6.0]
Gap: **achieved**

All acceptance criteria met: `doit-mcp` binary, importable `engine`/`mcptools`
packages, 9 integration tests committed and passing. Legacy code removal
deferred to 🎯T6.

### 🎯T2 sh -c execution model  [high, effective 5.0]
Gap: **significant**

No `sh -c` code path exists. All execution flows through `pipeline.ExecuteCommand`
with per-capability `Run()` methods. `Request.Command` is split via
`strings.Fields`, not passed to a shell.

### 🎯T5 Test coverage for core packages  [medium, effective 3.0]
Gap: **significant**

6 packages have no test files: `cmd/doit`, `cmd/doit-mcp`, `internal/cap`,
`internal/cap/builtin`, `internal/cli`, `internal/config`.

### 🎯T4 Per-project policy  [medium, effective 2.0]  (status only)
Status: not started

### 🎯T3 Starlark L1 rules  [medium, effective 1.5]  (status only)
Status: not started

### 🎯T6 Clean up legacy code paths  [low, effective 1.0]  (blocked)
Status: not started
Blocked by: 🎯T1, 🎯T2

## Recommendation

Work on: **🎯T2 sh -c execution model**

Reason: Highest effective weight among unachieved targets (5.0), unblocks
🎯T6. This is the architectural shift that lets doit receive opaque command
strings and delegate shell composition to the shell.

## Suggested action

Add an `sh -c` execution path in `engine.Execute`: when `Request.Command`
is set and `Request.Args` is empty, execute via `exec.Command("sh", "-c", req.Command)`
instead of going through the pipeline parser. Propagate exit codes from the
child process. Keep the pipeline parser path for policy evaluation (segment
extraction) but bypass it for execution.

Type **go** to execute the suggested action.

<!-- convergence-deps
evaluated: 2026-03-07T00:00:00Z
sha: d8b6948

🎯T1:
  gap: achieved
  assessment: "All criteria met. Integration tests committed and passing."
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
