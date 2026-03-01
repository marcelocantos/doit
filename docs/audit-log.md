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
