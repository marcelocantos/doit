# Convergence Report

Generated: 2026-03-08
Branch: master
SHA: 13efbe1

## Standing invariants: all green

All tests pass (including 4 new test files).

## Movement

- 🎯T2: significant → **achieved** (sh -c execution path merged in PR #5)
- 🎯T5: significant → **close** (4/5 acceptance criteria met — cap, builtin, cli, config all tested)
- 🎯T6: blocked → **unblocked** (both T1, T2 achieved)
- 🎯T3: (unchanged)
- 🎯T4: (unchanged)

## Gap Report

### 🎯T5 Test coverage for core packages  [effective 3.0]
Gap: **close**
4 of 5 acceptance criteria met. `internal/cap/`, `internal/cap/builtin/`,
`internal/cli/`, and `internal/config/` all have comprehensive tests.
Remaining: `cmd/doit/` smoke tests (entry-point binary, tightly coupled
to OS state). `cmd/doit-mcp/` is exercised by MCP integration tests.

### 🎯T4 Per-project policy  [effective 2.0]
Gap: **not started**
No per-project config support exists.

### 🎯T3 Starlark L1 rules  [effective 1.5]
Gap: **not started**
No Starlark integration exists.

### 🎯T6 Clean up legacy code paths  [effective 1.0]
Gap: **significant**
Now unblocked. `internal/daemon/`, `internal/client/`, `internal/ipc/`,
unicode operators, and pipeline execution code still present.

## Recommendation

Work on: **🎯T5 Test coverage for core packages**

Reason: Gap is "close" — one remaining criterion (`cmd/doit/` smoke tests).
Closing this target is cheap and enables confident refactoring for 🎯T6.

## Suggested action

Add a smoke test for `cmd/doit/` — test the `run()` function with
`--version` and `--help` args to verify subcommand dispatch without
requiring daemon/network dependencies.

Type **go** to execute the suggested action.

<!-- convergence-deps
evaluated: 2026-03-08T00:00:00Z
sha: 13efbe1

🎯T5:
  gap: close
  assessment: "4/5 criteria met. cap, builtin, cli, config tested. Remaining: cmd/doit smoke tests."
  read:
    - internal/cap/capability_test.go
    - internal/cap/builtin/builtin_test.go
    - internal/cli/cli_test.go
    - internal/config/config_test.go

🎯T4:
  gap: not started
  assessment: "No per-project config support."
  read: []

🎯T3:
  gap: not started
  assessment: "No Starlark integration."
  read: []

🎯T6:
  gap: significant
  assessment: "Unblocked. Legacy code still present."
  read: []
-->
