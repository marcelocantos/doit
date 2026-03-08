# Convergence Report

Generated: 2026-03-08
Branch: master
SHA: e8c76a0

## Standing invariants: all green

All tests pass. No CI configured.

## Movement

- 🎯T5: close → **achieved** (cmd/doit smoke tests added, PR #6 merged)
- 🎯T3: (unchanged)
- 🎯T4: (unchanged)
- 🎯T6: (unchanged)

## Gap Report

### 🎯T4 Per-project policy  [effective 2.0]
Gap: **not started**
No per-project config support. No code references to project root or repo-level
config. Acceptance criteria: `.doit/config.yaml` in repo, tighten-only
semantics, `engine.New` accepts project root.

### 🎯T3 Starlark L1 rules  [effective 1.5]
Gap: **not started**
No Starlark integration in code. Only referenced in design docs and TODO.
Large scope: embed interpreter, rule loading, test validation, L3→L1
promotion, migrate existing Go rules.

### 🎯T6 Clean up legacy code paths  [effective 1.0]
Gap: **significant**
Unblocked. ~1685 lines across `internal/daemon/`, `internal/client/`,
`internal/ipc/` plus unicode operators and pipeline execution code.
Straightforward deletion with test fixup.

## Recommendation

Work on: **🎯T4 Per-project policy**

Reason: Highest effective weight (2.0) among active targets. Relatively
low cost (cost 1) — config layering with tighten-only semantics. Enables
repo-specific gatekeeper behaviour without modifying global policy.

## Suggested action

Add per-project config support to `engine.New`: accept an optional project
root path, look for `.doit/config.yaml` in that directory, merge it with
global config using tighten-only semantics (repo config can add rules and
restrict tiers but cannot remove global rules or enable disabled tiers).
Start by reading `internal/config/config.go` and `engine/engine.go` to
understand the current config flow, then extend `Options` with a
`ProjectRoot` field.

Type **go** to execute the suggested action.

<!-- convergence-deps
evaluated: 2026-03-08T01:00:00Z
sha: e8c76a0

🎯T4:
  gap: not started
  assessment: "No per-project config support in code."
  read: []

🎯T3:
  gap: not started
  assessment: "No Starlark integration in code."
  read: []

🎯T6:
  gap: significant
  assessment: "Unblocked. ~1685 lines of legacy code to remove."
  read: []
-->
