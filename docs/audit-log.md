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

## 2026-04-19 — /release v0.6.0

- **Commit**: `d63ec93`
- **Outcome**: Released v0.6.0 (darwin-arm64, linux-amd64, linux-arm64).
  Three new capability groups landed this release:
  - **Shell-script content-hash approval** (🎯T27): tier-0 gate before
    L1/L2/L3 that elicits user approval on first encounter with a shell
    script, keyed by SHA-256 of the content. Approvals persist at
    `~/.config/doit/script-approvals.yaml`. Modifying the script forces
    re-approval. New MCP tools: `doit_approvals_list`,
    `doit_approvals_revoke`. New audit fields: `script_hash`, `script_path`.
  - **Time expectations + timeout enforcement** (🎯T26.1): `timeout_seconds`
    and `expected_duration_seconds` on `doit_execute` / `doit_dry_run`.
    Runtime kills the whole process group on expiry (SIGKILL, exit 137).
    Audit entries record expected vs actual and a `timed_out` flag.
  - **L1/L2 duration-aware rules** (🎯T26.2, 🎯T26.3): Starlark `check`
    can opt into a 3rd `meta` param for the expectations; built-in L1
    rule `flag-duration-mismatch` flags `sleep N` where N > 2×expected;
    L2 learns per-pattern p50/p95 from the audit log (persisted at
    `~/.config/doit/duration-stats.yaml`) and flags `duration-anomaly`
    / `timeout-too-short` mismatches against the learned distribution.
    New MCP tool: `doit_durations_list`.
  STABILITY.md snapshot refreshed to v0.6.0; README documents the new
  MCP tools and features.
- **Deferred**:
  - `--help-agent` CLI flag is still missing on the doit binary
    (pre-existing gap; not blocking, captured for a future release).

## 2026-04-25 — /release v0.8.0

- **Commit**: `f6d97ff`
- **Outcome**: Released v0.8.0 (darwin-arm64, linux-amd64, linux-arm64).
  Threat-model-driven safety follow-ons to v0.7.0 land this release:
  - **🎯T33** — `doit_check_config` reports the full safety contract: every
    one of the seven load-bearing configuration items the threat model
    names is now surfaced with a stable §N marker, the current value, and
    the safety-model interpretation. Settings weakened from defaults
    (`[FAIL]` / `[WARN]`) are visually distinct from informational items
    that describe user responsibilities (`[INFO]`).
  - **🎯T34** — Startup warning for sibling MCP servers with
    execution-adjacent primitives (filesystem-write+chmod, shell-snippet
    runners, language interpreters, HTTP-to-localhost). Suppressible
    per-server via the new `policy.acknowledged_sibling_servers: [...]`
    config field. Backed by a name/pattern classification heuristic in
    the new `internal/mcpinventory` package.
  - **🎯T35** — L3 prompt-injection surface enumerated in
    `docs/l3-injection.md` with per-input trust level, position,
    mitigation, and gap classification. The L3 prompt template now wraps
    every agent-supplied field (command, cwd, justification, safety
    argument, session scope, session description) in XML data tags with
    full XML character escaping; the model is instructed to treat tag
    contents as data only. A 10-payload prompt-injection regression
    corpus lives in `internal/llm/testdata/injection_corpus.yaml` and is
    exercised by the renderer test on every CI run.
  - **🎯T29** — Learned duration statistics now key on
    `(cap, subcmd, project_id)` rather than the global `(cap, subcmd)`,
    eliminating false-positive anomaly flags between projects of
    different sizes. Project-context-less commands share a fallback
    bucket.
  - **🎯T30** — `rm` tier reflects reversibility via git-tracked status:
    a non-recursive `rm` on a tracked file is now write-tier (recoverable
    via `git checkout HEAD -- <path>`) rather than dangerous-tier.
    Untracked, recursive, and outside-repo cases remain dangerous.
    Hardcoded catastrophic rules still fire regardless of tier.
  STABILITY.md snapshot bumped to v0.8.0 with the new
  `acknowledged_sibling_servers` config field, the per-target `rm` tier
  table, and the project-keyed duration aggregator. New pre-1.0 gap:
  third-party attribution (NOTICES) for transitive Go-module dependencies
  in binary distributions.

## 2026-04-21 — /release v0.7.0

- **Commit**: `2e933f2`
- **Outcome**: Released v0.7.0 (darwin-arm64, linux-amd64, linux-arm64).
  Single-feature release — closes the pre-existing `--help-agent` gap
  noted in the v0.6.0 deferred list (🎯T28). The `doit` binary now prints
  the CLI reference followed by the full embedded `agents-guide.md` when
  invoked with `--help-agent`. Embedding uses `go:embed` from a new
  top-level `doit` package at the module root — a workaround for
  `go:embed`'s no-parent-directories rule that avoids a pre-build copy
  step. STABILITY.md snapshot bumped to v0.7.0 (the `--help-agent`
  catalogue entry itself landed in PR #25 under v0.6.0 in-flight).
