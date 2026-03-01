# doit — TODO

## Policy Migration (L3 → L2 → L1 promotion)

- [ ] Analyse L3 decision history for uniform patterns eligible for L2 promotion
- [ ] Implement semantic similarity grouping (e.g. `go test ./...` variants)
- [ ] Detect conditional branching (same command approved/denied based on flags)
- [ ] Propose new L2 entries from stable L3 patterns (human approval required)
- [ ] Promote stable L2 entries to L1 deterministic rules

## Gatekeeper Self-Audit

- [ ] Periodic holistic review of rule set and learned policy
- [ ] Detect rules that are dangerous in combination
- [ ] Flag rules that have drifted from current project reality
- [ ] Identify L3 patterns that should have been promoted but weren't
- [ ] Surface inconsistencies between rules

## Gatekeeper Capabilities

- [ ] Read-only repo access for the gatekeeper to verify worker claims
  (e.g. "this is a generated directory" → inspect `.gitignore`, build config)
- [ ] Hardcoded allowlist for gatekeeper-internal operations (bootstrap trust)

## Global vs Repo-Level Policy

- [ ] Per-project config (currently global only)
- [ ] Repo-level policy that can tighten but not loosen global policy
- [ ] Auto-discover repo context from project structure, Makefile, `.gitignore`

## Out-of-Band User Interface

- [ ] Escalation notifications bypassing the worker agent
- [ ] Approval queue (web UI, native, or menu bar widget)
- [ ] Spaced repetition review digest for non-urgent items
- [ ] Periodic audit findings digest

## Extensibility

- [ ] Embedded scripting engine (Starlark) for user-defined capabilities
- [ ] Config-defined capabilities (YAML)
