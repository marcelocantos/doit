# Audit Log

Chronological record of audits, releases, documentation passes, and other
maintenance activities. Append-only — newest entries at the bottom.

## 2026-02-25 — initial-implementation (reconstructed)

- **Commit**: `3209593`
- **Outcome**: Initial implementation of doit capability broker with two-level
  pipeline parser, audit log, config, and core builtin capabilities. Compound
  command operators (＆＆, ‖, ；) added same day.

## 2026-02-26 — /audit (reconstructed)

- **Commit**: `7dc1fb1`
- **Outcome**: Full codebase audit performed ahead of open-source release.
  Findings addressed: security/safety fixes across pipeline, audit, and CLI
  layers. Rules system with hardcoded and config-driven argument validation
  added; `--retry` flag wired through for config-rule bypass.
- **Deferred**:
  - `audit.max_size_mb` not enforced
  - Test coverage gaps (5 packages at 0%)
  - Per-project config (currently global only)
  - `doit --audit tail` count not configurable

## 2026-02-27 — /docs open-source-release (reconstructed)

- **Commit**: `9c7d55a`
- **Outcome**: Documentation pass for open-source release: README.md,
  CLAUDE.md, and agents-guide.md written. STABILITY.md added to track pre-1.0
  API surface.

## 2026-02-28 — /release v0.1.0 (reconstructed)

- **Commit**: `b575972`
- **Outcome**: Release CI workflow added (`.github/workflows/release.yml`),
  build fixed to copy agents-guide.md before build (`60e9f1f`). v0.1.0 tagged
  and released on GitHub; Homebrew tap published at
  `marcelocantos/tap/doit`.

## 2026-04-08 — /audit

- **Commit**: `35dea14`
- **Outcome**: 15 findings (4 high, 6 medium, 4 low, 1 info). Report: docs/audit-2026-04-08.md. Key issues: no CI for push/PR, duplicate `hasAnyFlag`, dead code (`resolveError`, `DaemonConfig`), stale docs (dependency count, Go version).
- **Deferred**:
  - NOTICES/THIRD_PARTY file for binary distributions (info)

## 2026-04-08 — /release v0.2.0

- **Commit**: `70c5abd`
- **Outcome**: Released v0.2.0 (darwin-arm64, linux-amd64, linux-arm64).
  Major architectural evolution: MCP server, three-level policy engine,
  Starlark L1 rules, per-project config, legacy cleanup. All 15 audit
  findings addressed. Homebrew formula updated.

## 2026-04-09 — /release v0.3.0

- **Commit**: `d94df09`
- **Outcome**: Released v0.3.0 (darwin-arm64, linux-amd64, linux-arm64).
  Single binary consolidation, MCP elicitation for policy decisions,
  two-phase rule promotion, admin MCP tools. Homebrew formula updated.

## 2026-04-09 — /release v0.4.0

- **Commit**: `(pending)`
- **Outcome**: Released v0.4.0 (darwin-arm64, linux-amd64, linux-arm64).
  Fixed stale --retry references in error messages, rewrote agents-guide
  and README for MCP-first model. Homebrew formula updated.

## 2026-04-12 — /release v0.5.0

- **Commit**: `deed084`
- **Outcome**: Release v0.5.0 (darwin-arm64, linux-amd64, linux-arm64).
  Major internal changes: pipeline parser removed (shell handles all
  composition), L3 rebuilt on one-shot `claude -p` (replacing claudia
  Session mode), two-tier L3 cascade (sonnet fast → opus deep) with L3
  enabled by default, work sessions (`doit_session_start/end/status`),
  L2 policy management tools (`doit_policy_list/delete/review`),
  self-audit (`doit_self_audit`), project-context repo reads
  (`doit_repo_read`), and `doit_check_config` for deployment verification.
  Engine cleanup: `EvalResult` no longer exposes `Segments`/`Tiers`
  (segment analysis is a detail of individual policy layers);
  `RecordDecision` signature simplified. Stderr logging suppressed so
  MCP clients don't flag it as error output. Docs refreshed:
  STABILITY.md snapshot to v0.5.0 with the full 16-tool surface,
  CLAUDE.md architecture map updated, README/agents-guide tool tables
  completed.
