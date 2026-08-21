# Entropy audit — doit

**Date:** 2026-08-22
**Mode:** full (entropy + hygiene)
**Auditor:** Grok entropy-audit owner
**Snapshot:** `github.com/marcelocantos/doit` · branch `master` · `827fb63d6258f204466cc95ccedc113f1f676b78` (`v0.9.0-2-g827fb63`)
**Working tree at start:** clean (`git status --porcelain=v1 -b` showed only `## master...origin/master [behind 1]`)
**HEAD subject:** `Fable-5 deep audit: doit (1 critical, 8 high) — findings + targets (#47)`
**Prior baseline:** `docs/audit/fable-2026-07.md` (security-focused). This report is the first entropy-audit-contract snapshot; it re-verified Fable-5 findings against current source rather than treating that report as evidence.

## Executive summary

doit is a single Go MCP server whose purpose is to mediate every agent command through a three-level policy engine and a hash-chained audit log. Package boundaries are clean and acyclic. The structural problem is not folder layout: **the live decision function is fail-open, and the advertised enforcement plane is a second, unwired copy of the same ideas.**

Headline mechanism: `Engine.Execute` / `ExecuteStreaming` only intercept Deny and L3 Escalate-with-token. Any other non-Allow result — including the ordinary L1/L2 `Escalate` that remains when L3 is disabled — falls through to `sh -c`. Meanwhile `Registry.CheckTier`, `Registry.CheckRules`, and `Capability.Validate` are never called on the execution path, so `tiers.dangerous: false`, the hardcoded `RuleSet`, and T24's metacharacter gate are decorative. L1/L2 inspect `strings.Fields(command)[0]` while the shell executes the rest. Those three facts compose: an unrecognised or compound command in an L3-off (or elicitation-failed) deployment runs.

Highest-consequence findings:

- **ENT-001 (P0):** Escalate/uncertain results execute. Tests encode this as expected behaviour (`TestExecute_SimpleCommand` runs `cat` under L3-off). Maps to open 🎯T40.
- **ENT-002 (P1):** Advertised tier/rule/Validate controls are dead on the shipped path; `doit_check_config` §4 still reports them as binding. 🎯T24 is marked achieved while `Ls.Validate` is `return nil` and never invoked.
- **ENT-003 (P1):** Approval tokens are engine-minted, consumed by dry-run/`doit_approve`, and replayable on the library `Execute` path. 🎯T41/T46/T47.
- **ENT-004–ENT-006 (P1):** Audit chain advances before durable write and panics on short hashes; L2 YAML is last-writer-wins; `doit_repo_read` follows symlinks and trusts agent `project_root`.

Unverified residue: live `claude -p` L3 behaviour (no live-provider gate run this audit); whether any in-tree library consumer besides tests calls `Engine.Execute` directly; origin/master is one commit ahead and was not pulled.

## Scope and exclusions

**In scope:** Go module `github.com/marcelocantos/doit` as of HEAD — `cmd/doit`, `engine`, `mcptools`, `internal/*`, `rules/*.star`, CI/release workflows, docs, `bullseye.yaml`, `STABILITY.md`.

**Languages detected from manifests:** Go 1.26.1 (`go.mod`). Starlark rule files are data, not a second runtime. No Python/Rust/C++/SQL/web app. Makefile recipes only.

**Excluded / named, not silent:**

- `.claude/worktrees/` — local agent worktrees; gitignored; not part of the shipped tree.
- `bin/doit` — gitignored build artefact.
- `docs/audit/fable-2026-07.md` and earlier audits — used as history, not as current evidence.
- Generated/vendored trees: none in-repo (`go.mod` pulls modules into the module cache).
- Live L3 (`claude -p` against a real model) — not exercised; unit tests mock the prompter.

## Commands run

| Command | Version / notes | Exit | Shipped vs auxiliary | Limitations |
|---|---|---|---|---|
| `git rev-parse HEAD`; `git status --porcelain=v1 -b`; `git log --oneline -20`; `git ls-files` | git  (repo) | 0 | provenance | Working tree clean; branch behind origin/master by 1 (not pulled). |
| `GOWORK=off go version` | go1.26.4 darwin/arm64 | 0 | toolchain | Parent `~/work/github.com/marcelocantos/go.work` would otherwise make `go list ./...` fail (`directory prefix . does not contain modules…`). All Go commands used `GOWORK=off`. |
| `GOWORK=off go list ./...` and import graph | 15 packages | 0 | shipped graph | No cycles. |
| `GOWORK=off go vet ./...` | — | 0 | shipped | Declared `make vet` path. |
| `GOWORK=off go test ./...` | — | 0 | shipped (`make test`) | All packages ok; `cmd/doit` has no tests. |
| `GOWORK=off go test ./... -cover` | coverage below | 0 | auxiliary metric | Coverage locates gaps; not a verdict. |
| `staticcheck ./...` | built with go1.25.0 | 1 | auxiliary | **Failed to compile** against go1.26.1 module. Residue: staticcheck is installed but unusable on this module. |
| `golangci-lint run ./...` | homebrew binary | 0 | auxiliary | 27 issues (21 errcheck, 3 staticcheck, 3 unused). No repo config; default linters. Not a CI gate. |
| `gh api repos/marcelocantos/doit` | GitHub settings | 0 | SDLC | Dependabot updates disabled; secret scanning + push protection enabled. |
| `command -v govulncheck` | — | 1 | — | Not installed; not run. Not installed during audit. |
| hygiene validator | — | n/a | — | `hygiene.yaml` absent; not initialised. |

**Coverage (auxiliary):** `engine` 62.9%; `mcptools` 49.3%; `cmd/doit` 0.0%; `internal/audit` 90.3%; `internal/cap` 93.1%; `internal/cap/builtin` 81.3%; `internal/config` 87.4%; `internal/context` 98.4%; `internal/llm` 81.6%; `internal/mcpinventory` 95.2%; `internal/policy` 85.3%; `internal/rules` 98.6%; `internal/script` 68.4%; `internal/starlark` 85.2%. High package coverage coexists with missing property tests for fail-closed execution, token provenance, audit durability, and repo-read containment.

## Dimension vector

| Dimension | State | Evidence summary | Change from baseline |
|---|---|---|---|
| Architecture topology | concern | Acyclic internal DAG; `engine`+`mcptools` are god-objects. Live policy path (`internal/policy`) is parallel to an unwired `cap.Registry` RuleSet. Shipped `cmd/doit` never sets `ProjectRoot`. | n/a (first entropy snapshot). Agrees with Fable-5 topology. |
| Redundancy / sources of truth | concern | Catastrophic-rm and git-checkout exist in L1 Go, `internal/rules` (unwired), and `rules/*.star` (not loaded by default); they have already drifted. `docs/todo.md`, 🎯T8/T24, README, and threat-model file pointers contradict code. | Fable-5 noted decorative CheckTier; dual-rule drift and stale ledger items are additional. |
| Change amplification | concern | `engine/engine.go` (1890 lines, 26 commits) and `mcptools/mcptools.go` (1434 lines, 13 commits) sit on every feature. STABILITY.md (17 commits) is a manual catalogue that must move with every MCP/schema change. | Unchanged hub; still no architecture test pinning the DAG. |
| Local code quality | concern | Readable, Go-idiomatic packages. Control-flow in `Execute` is the quality problem (fail-open). Unused leftovers (`l3SessionClient`, `logExecution`). `EngineOption` functional-options used only for tests. | Fable-5 unused `Run()` methods are gone (🎯T20). |
| Correctness / verification | concern | `go test`/`go vet` green, but tests *require* fail-open (`TestExecute_SimpleCommand`). Open 🎯T40–T47 have no regression tests. No `-race` in CI. No live L3 gate. | Tests still pass; the P0 is still untested as a failure. |
| Security / dependencies | critical | Fail-open + decorative tiers + first-token L1 + token self-issue. Small direct dep set (`mcp-go`, starlark, yaml.v3). No `govulncheck`/Dependabot. Secret scanning on. | Fable-5 critical/high items remain open as 🎯T40–T47. |
| Build / release / operations | concern | CI is build+vet+test on ubuntu only. Release uploads tarballs with `skip_checksum: true`. No SBOM/NOTICES. `make bullseye` is a local invariant hook, not CI. | CI actions bumped to Node 24 majors (87f877d); no new gates. |
| Documentation / governance | concern | STABILITY.md + threat-model are strong. `docs/todo.md` is a banned parallel ledger of already-achieved work. 🎯T8/T24 marked achieved against a different architecture. No `hygiene.yaml`. No `AGENTS.md`. | Fable-5 filed T40–T47; those remain `identified`. |

Do not collapse this vector to a score.

## Observed architecture

### Entry points and deployable units

One binary: `cmd/doit/main.go` is an MCP stdio server (`server.NewMCPServer` + `NewStdioServer`). Flags: `--config`, `--version`, `--help`, `--help-agent`. There is no CLI execute subcommand. Library consumers are expected to import `engine` (comment at `engine/engine.go:5` names jevon).

```
cmd/doit  →  engine.New(Options{ConfigPath})  →  mcptools.Register
                 │
                 ├─ config.Load / MergeProject
                 ├─ cap.Registry + builtin.RegisterAll
                 ├─ audit.Logger
                 ├─ policy.Level1 / Level2 / Level3
                 ├─ script.Store (tier-0 hash gate)
                 └─ llm.Client (`claude -p`, fast sonnet → deep opus)
```

Internal import direction (observed, `GOWORK=off go list`):

- `cmd/doit` → `engine`, `mcptools`, `mcpinventory`, root `doit` (embed of `agents-guide.md`)
- `mcptools` → `engine`, `audit`, `config`, `context`, `policy`
- `engine` → `audit`, `cap`, `builtin`, `config`, `context`, `llm`, `policy`, `script`, `starlark`
- `policy` → `audit`, `rules`, `starlark`
- `config` → `cap`, `rules`
- `builtin` → `cap`, `rules`
- `cap` → `rules`

No import cycles. `internal/` is not imported from outside the module. High fan-in: `engine`, `policy`, `rules.HasAnyFlag`. High fan-out: `engine` (knows every subsystem).

### Declared vs observed rules

**Agree:**

- Commands are opaque strings executed via `sh -c` (🎯T17; `engine.go:749-751`; `policy.Request` comment at `policy.go:42-43`).
- L1 is first-match Go rules + optional Starlark; unmatched → Escalate (`level1.go:72-121`).
- L2 matches first-token cap/subcmd of learned YAML (`level2.go:27-39`).
- L3 is one-shot `claude -p`, not a persistent claudia session (`engine.go:262-273`).
- Tighten-only project overlay exists (`config.MergeProject`).
- Audit log is SHA-256 hash-chained JSONL.

**Observed, inferred from code (not fully declared):**

- The shipped server constructs the engine **without** `ProjectRoot` (`cmd/doit/main.go:79`), so per-project `.doit/config.yaml`, T13 safe-command rules, and duration project keys never activate in the binary operators actually run.
- `cfg.ApplyTiers` / `cfg.ApplyRules` populate the registry (`engine.go:183-184`) but the exec path never consults them.
- Default `policy.level3_enabled` is **true** (`config.go:90`); README's worked example sets it **false** (`README.md:247`).

**Contradictions:**

- Threat model §3 and `doit_check_config` §4 present `tiers.dangerous` as a runtime gate; `CheckTier` has zero non-test callers.
- 🎯T8 is `achieved` as “persistent claudia session”; code and `engine.go:262-273` document the opposite.
- 🎯T24 is `achieved` as “Validate rejects shell metacharacters”; `ls.go:18` is `return nil` and `Validate` is never called from `engine`/`mcptools`.
- `docs/todo.md` still lists per-project config, Starlark, and repo-read as unchecked; those shipped as T3/T4/T15.
- `docs/threat-model.md:323` points at `docs/targets.yaml`; live ledger is `bullseye.yaml`. `.gitignore` still lists `docs/targets.md`.
- CLAUDE.md line 3 omits `mcp-go` (direct require in `go.mod`).
- README “Requires Go 1.25+”; `go.mod` is `go 1.26.1`.

**Unknown intent (owner judgment):**

- Should L3-off be a supported production mode? Tests and README treat it as normal; fail-open makes it unsafe.
- Should tokens exist at the engine API, or only as an elicitation implementation detail?
- Are `rules/*.star` examples, or the intended default `starlark_rules_dir`? Default is `""`; they load only in `internal/starlark/examples_test.go`.

## Findings

### ENT-001: Execute fails open on non-Allow policy results

- **Priority:** P0
- **Dimensions:** Security / dependencies; Correctness / verification; Architecture topology
- **Status:** observed fact
- **Evidence:**
  - `engine/engine.go:763-815` (`Execute`) and `:850-898` (`ExecuteStreaming`): intercept `Deny`, then only `Escalate && Level == 3 && tokenStore != nil`. Control then reaches `runCommand` / `runShellCommand` (`:813-815`, `:1631-1632`, `:1660`).
  - L3-off construction leaves `policyL3` and `tokenStore` nil (`engine.go:274-315`). L1 unmatched returns `{Escalate, Level 1}` (`level1.go:117-121`); L2 unmatched returns `{Escalate, Level 2}` (`level2.go:105-109`).
  - `engine/engine_test.go:80-91` `TestExecute_SimpleCommand` builds an L3-off engine (`newTestEngine` / `:21`) and asserts `cat` exits 0 — the fail-open path is the test oracle.
  - `mcptools/mcptools.go:301-305`: elicitation error “falls through to normal execution which will return the denial”; `executeAndRespond` (`:548-550`) calls `Execute`, which does not deny L1/L2 escalate.
  - Open 🎯T40. Independently confirmed by Fable-5 F1 against the same control flow; line numbers still match.
- **Mechanism:** The policy chain is not a total function. Escalate means “no opinion”. Execute treats “no opinion” as Allow except for the narrow L3+token case. Any deployment without a live L3 (documented, default in tests, shown in README) therefore runs novel and compound commands. Combined with ENT-002 and first-token L1, `chmod`, `rm --recursive`, and `x && rm -rf /` are in this class.
- **Blast radius:** Every `doit_execute` / library `Execute` under L3-off or nil `policyL3`; elicitation-incapable MCP clients when L3 is also off. Destructive commands that L1 does not literally match.
- **Counterevidence checked:** DefaultConfig enables L3 (`config.go:90`), so a stock MCP server with working `claude` and elicitation is fail-closed on L3 Escalate (issues a token, does not run). That does not close L3-off, library Execute, or the elicitation-error comment. No test asserts a marker file is absent.
- **Smallest coherent remediation:** After Deny, treat any `Decision != Allow` as terminal in both Execute methods; never reach `runCommand`. If a token must be issued, issue it and return. Change `handleExecute`'s elicitation-error path to return an error. Invert `TestExecute_SimpleCommand` (and pipeline/env siblings) so they no longer require unapproved commands to run; put those cases on an explicit Allow (Retry or L1 allow rule).
- **Verification:** Engine with `level3_enabled: false`; `Execute("touch MARKER")` must exit non-zero and leave no file. Same for `ExecuteStreaming`. MCP elicitation failure must not run the command.
- **Ratchet candidate:** Regression test named in 🎯T40 acceptance, wired into `make test` / CI (already runs `go test ./...`). Optional architecture test: `Execute` must not call `runShellCommand` unless `pResult.Decision == Allow`.

### ENT-002: Advertised tier, RuleSet, and Validate controls are unwired

- **Priority:** P1
- **Dimensions:** Security / dependencies; Redundancy / sources of truth; Documentation / governance
- **Status:** observed fact
- **Evidence:**
  - `cap.Registry.CheckTier` (`capability.go:151-158`) and `CheckRules` (`:178-185`): non-test callers = none (`rg '\.CheckTier\(|\.CheckRules\(' --glob '!*_test.go'` empty).
  - `Capability.Validate`: production callers = none; tests only in `builtin_test.go`. `Ls.Validate` is `return nil` (`internal/cap/builtin/ls.go:18`).
  - `EffectiveTier` is computed in `evaluatePolicy` (`engine.go:1545-1555`) “only for audit log coarse-filtering”.
  - Config still fills the dead plane: `cfg.ApplyTiers(reg)` / `cfg.ApplyRules(reg)` (`engine.go:183-184`), `rules.Hardcoded()` (`hardcoded.go:15-18`), `NewRegistry` installs hardcoded rules (`capability.go:117-128`).
  - `checkDangerousTier` (`mcptools/mcptools.go:1205-1217`) reports “Dangerous tier is disabled (default)” as a satisfied safety property and warns that enabling it means operations “now run without per-command tier gating” — implying gating exists when disabled.
  - Threat model §3 (`docs/threat-model.md:86-92`) states the disabled dangerous tier gates `rm`/`chmod`/destructive git.
  - 🎯T24 achieved; acceptance requires shared metacharacter rejection from every `Validate()`. Not present.
- **Mechanism:** Two enforcement planes. The live plane is `policy.Level1/2/3`. The advertised plane is registry tiers + RuleSet + Validate. Operators and `doit_check_config` read the advertised plane. Dead safety code manufactures confidence.
- **Blast radius:** Any operator relying on `tiers.dangerous: false` or capability `Validate` as a second line of defence. Compounds ENT-001.
- **Counterevidence checked:** 🎯T17/T20 explicitly demoted tiers to advisory metadata for listing and a coarse “disable dangerous tier” switch. The switch was never re-homed onto `evaluatePolicy`. Unit tests of `CheckTier`/`CheckRules` pass in isolation, which hides the missing call site.
- **Smallest coherent remediation:** Pick one: (a) call `CheckTier(EffectiveTier(...))` and `CheckRules` from `evaluatePolicy` and fail closed on error; implement T24's shared `Validate` helper and call it; or (b) delete `CheckTier`/`CheckRules`/registry RuleSet from the exec story, rewrite `doit_check_config` §4 and threat-model §3 so they do not claim per-command gating, and reopen 🎯T24.
- **Verification:** `chmod -R 777 /tmp` (or equivalent) must `deny` when `tiers.dangerous: false` and `escalate`/`allow` only when enabled — or check_config must stop claiming the gate. `rg CheckTier` on non-test code must be either a real call site or absent with docs updated.
- **Ratchet candidate:** Test that `Evaluate` decisions differ under `tiers.dangerous: true` vs `false` for a dangerous-tier first token; or a docs/check_config golden that does not contain “per-command tier gating”.

### ENT-003: Approval-token lifecycle is inverted

- **Priority:** P1
- **Dimensions:** Security / dependencies; Correctness / verification
- **Status:** observed fact (MCP replay currently fail-closed only because of the consume bugs)
- **Evidence:**
  - Issue with no human step: `engine.go:779-797` `tokenStore.Issue` on L3 Escalate; token returned on `Result.EscalateToken` and printed as `approval-token:`.
  - Consume on every validate: `TokenStore.Validate` deletes immediately (`internal/policy/tokens.go:80-81`) “single use regardless of outcome”.
  - Dry-run burns the token: `handleExecute` always `eng.Evaluate` first (`mcptools.go:274`); `Evaluate` → `evaluatePolicy` → `Validate` (`engine.go:1527-1542`). Subsequent `Execute` sees “unknown or expired”.
  - `doit_approve` burns it too: `ValidateApproval` (`engine.go:1501-1507`) → same `Validate`; handler then claims “Command is now authorized.” (`mcptools.go:635-639`).
  - A single `Execute(approved=engine-issued token)` skips L1/L2/L3 and returns Allow (`engine.go:1537-1542`). Fable-5 reproduced “SELF-APPROVAL CONFIRMED” on the library path.
  - Open 🎯T41, 🎯T46, 🎯T47.
- **Mechanism:** Tokens are treated as capability cookies rather than as a record of a human elicitation. Peek paths consume; the engine is the issuer. The MCP `approved=` flow and `doit_approve` then execute flow cannot succeed. Fixing consume-on-peek without a provenance flag activates self-approval on the MCP path (Fable-5 F3).
- **Blast radius:** Documented approve-then-execute and `doit_execute(approved=)` flows are dead. Library `Execute` consumers can self-approve. Future T46/T47 fixes without T41 reopen agent replay.
- **Counterevidence checked:** Tokens are 128-bit `crypto/rand`, TTL 10 minutes, args-bound, single-use, mutex-protected — the machinery is sound; the trust anchor is wrong. MCP elicitation `allow_once` uses `Retry=true` (`mcptools.go:308-310`), not the token, so the interactive happy path does not need tokens. The token API is still documented as Stable (`STABILITY.md` `doit_execute.approved`, `doit_approve`).
- **Smallest coherent remediation:** Mint tokens only from the human elicitation accept path, tagged with human provenance. `evaluatePolicy` must reject tokens lacking that flag. Add non-consuming `Peek` for Evaluate/`doit_approve`; consume only in Execute. Coordinate T41 with T46/T47 in one change.
- **Verification:** (1) `Evaluate` then `Execute` with one token → Execute allows. (2) `ValidateApproval` then `Execute` → Execute allows. (3) `Execute(approved=engine.Issue(...))` without a human flag → Deny.
- **Ratchet candidate:** The three tests above in `engine` + `mcptools`.

### ENT-004: Audit chain is neither durable nor panic-safe

- **Priority:** P1
- **Dimensions:** Correctness / verification; Security / dependencies; Build / release / operations
- **Status:** observed fact
- **Evidence:**
  - Advance-before-write: `logger.go:102` `l.seq++`; `:142` `l.prevHash = entry.Hash`; then `:150-158` open/write. Error returns do not roll back. Callers discard errors (`engine.go:726`, `:746`, and other `_, _ = e.logger.Log` sites). No `fsync`. `defer f.Close()` is unchecked (`logger.go:154`; golangci errcheck).
  - Silent skip at size cap: `logger.go:98-100` returns `(0, nil)` when `checkSize`; `sizeLimitHit` latches (`:70-72`) so rotation does not resume logging.
  - NewLogger silent genesis: `logger.go:50-57` — if the last line fails `Unmarshal`, `seq` stays 0 and `prevHash` stays genesis; no error.
  - Verify panics: `verify.go:41` and `:47` slice `entry.PrevHash[:16]` / `entry.Hash[:16]` on untrusted JSON. Empty/short hash → `slice bounds out of range`. `cmd/doit/main.go:99` creates the MCP server without `server.WithRecovery`.
  - Logger construction failure is non-fatal: `engine.go:186-189` continues with `logger = nil`.
  - Open 🎯T42, 🎯T43.
- **Mechanism:** In-memory chain state is the source of truth; disk is a best-effort replica. A failed or partial write forks the chain forever. Size-cap and construction failure drop the security-of-record while commands keep running. The verifier crashes on the tamper it exists to report. Auto-promotion (`tryPromote`) and duration learning read this log.
- **Blast radius:** All audit consumers (`doit_audit_verify`, `doit_audit_query`, L2 promotion, duration stats). Postmortem and learned policy become untrustworthy after one I/O error, crash mid-write, or adversarial short hash.
- **Counterevidence checked:** Logger mutex serialises appends; file mode 0600; hash algorithm (SHA-256 over marshalled entry with Hash empty) is sound when writes succeed. Tail already reports skipped malformed lines (`verify.go:57-83`); Query does not (ENT-014). `TestLoggerSizeLimit` documents silent skip as current behaviour.
- **Smallest coherent remediation:** Write, then assign `seq`/`prevHash`. Return `ErrAuditFull` instead of `(0, nil)`; surface it in engine (fail closed or loud). Resume from last parseable line or error on corrupt tail. Clamp hash prefixes in Verify. Install `WithRecovery`. fsync on security-critical entries is optional hardening.
- **Verification:** chmod audit file 0400 mid-run then restore — Verify must still pass. Short-hash line — Verify returns error, process lives. After MaxSizeMB, Log returns a distinct error.
- **Ratchet candidate:** Unit tests in 🎯T42/T43 acceptance; CI already runs `go test`.

### ENT-005: L2 learned-policy store drops concurrent updates

- **Priority:** P1
- **Dimensions:** Correctness / verification; Change amplification
- **Status:** observed fact
- **Evidence:**
  - `AppendEntries` (`internal/policy/store.go:133-155`) is unlocked LoadStore → append → SaveStore. SaveStore is atomic rename (no corruption) but last-writer-wins.
  - Two callers: `RecordDecision` (`engine.go:1199`) on the request goroutine (human allow_always/deny_always) and `tryPromote` (`engine.go:1839`) from `go e.tryPromote()` after L3 outcomes (`:767`, `:790`, `:818`, `:854`, `:876`, `:901`).
  - `promoteCh` single-flights tryPromote vs itself only. `l2Mu` guards in-memory pointer swap in `reloadL2` (`:1881-1889`), not the YAML RMW.
  - Unlocked nil-check: `evaluatePolicy` reads `e.policyL2 != nil` (`engine.go:1586`) then RLocks — data race vs `reloadL2` write (Fable-5 F9). L1 path immediately above copies under lock (`:1576-1578`).
  - Open 🎯T44.
- **Mechanism:** Human permanent denials and auto-promoted rules are independent writers of one YAML snapshot. Concurrent MCP workers (mcp-go stdio pool) plus background promote lose entries. A dropped `deny_always` re-escalates forever.
- **Blast radius:** L2 store at `~/.config/doit/learned-policy.yaml` (or `Level2Path`). All subsequent evaluations of the dropped command.
- **Counterevidence checked:** `script.Store` and `DurationStore` already use mutexes — the pattern exists next door. IDs are skipped if already present, which does not help two new IDs racing. `go test` does not use `-race` in CI (`ci.yml:19-22`).
- **Smallest coherent remediation:** Store struct with mutex held across Load+Save; advisory flock for cross-process. Read `policyL2` once under `l2Mu` (mirror L1). Add concurrent `AppendEntries` test under `go test -race`.
- **Verification:** N goroutines each append a unique entry; `LoadStore` length == N, stable under `-race`.
- **Ratchet candidate:** `go test -race ./internal/policy/ ./engine/` in CI.

### ENT-006: `doit_repo_read` containment is lexical and agent-rooted

- **Priority:** P1
- **Dimensions:** Security / dependencies
- **Status:** observed fact
- **Evidence:**
  - `ReadRepoFile` (`internal/context/reporead.go:59-67`): `filepath.Clean` + `HasPrefix`; `os.ReadFile` follows symlinks. No `EvalSymlinks`, `O_NOFOLLOW`, or `Lstat`.
  - `handleRepoRead` (`mcptools.go:1011-1022`) takes `project_root` from the agent; if empty, uses `os.Getwd()`. Comment: “The engine's ProjectRoot is not stored separately”. Combined with ENT-009, the server has no configured root to pin to.
  - Allowlist is basename-only (`reporead.go:21-31`: `go.mod`, `CLAUDE.md`, `.gitignore`, …).
  - Open 🎯T45. Fable-5 F6 reproduced `go.mod` → secret via symlink.
- **Mechanism:** Policy checks a cleaned path string; the kernel follows the symlink. Agent-chosen root makes any allowlisted filename on the filesystem readable (`/etc/go.mod` style, or a cloned repo of secrets).
- **Blast radius:** Contents of any file the agent can name as an allowlisted basename, including via symlink from a writable project tree. Feeds L3 if the agent forwards the bytes (prompt-injection surface in `docs/l3-injection.md`).
- **Counterevidence checked:** Path separators rejected except `.doit/config.yaml` (`reporead.go:43-45`). No executable sources on the allowlist. `internal/context` tests cover lexical escape (`../`) but not symlink or foreign root.
- **Smallest coherent remediation:** `EvalSymlinks` on file and root; reject if resolved path is outside resolved root. Ignore agent `project_root` unless it equals the engine's known root (which requires ENT-009).
- **Verification:** `ln -s /etc/passwd $root/go.mod` → `ReadRepoFile` error. `project_root=/` + `filename=go.mod` → error on the MCP tool.
- **Ratchet candidate:** Those two tests in `internal/context` + `mcptools`.

### ENT-007: L1 catastrophic-rm and flag rules miss GNU long options and non-head tokens

- **Priority:** P1
- **Dimensions:** Security / dependencies; Architecture topology
- **Status:** observed fact (long-option gap); observed fact (first-token), with T17 as declared architecture
- **Evidence:**
  - `checkRmCatastrophic` requires `parts[0] == "rm"` and `HasAnyFlag(args, "-r", "-R")` (`level1.go:228-235`).
  - `rules.HasAnyFlag` (`rules.go:55-77`) matches exact, combined shorts, short+value, and `--flag=` — not `--recursive` as an alias of `-r`.
  - Same `HasAnyFlag` is used for config flag rules (`level1.go:395`, `:423`) so `--force` on git is matched (it is a long flag listed explicitly) but `rm --recursive --force /` is not.
  - First-token design: `x && rm -rf /`, `/bin/rm -rf /`, `command rm -rf /` never enter the rm rule. T17 documents this and delegates composition to L3.
  - Under ENT-001, L3-off executes those commands.
- **Mechanism:** The “permanently blocked” L1 rule is a string prefix matcher. GNU coreutils accept `--recursive`; macOS BSD `rm` does not, so the maintainer's machine cannot reproduce the delete, but Linux release artefacts (`release.yml` linux/amd64 and arm64) can.
- **Blast radius:** Linux users; any L3-off or L3-misled evaluation of recursive rm spelled with long options or not in argv0.
- **Counterevidence checked:** T25 extended the path blacklist (system dirs, globs, `~user`) for the `rm -r` spelling (`level1.go:202-276`). `rm -rf /` still denies. T17 rejects re-introducing a shell parser; the remaining L1 duty is to match the operation however it is spelled at argv0.
- **Smallest coherent remediation:** Treat `--recursive` / `--recursive=` as `-r` (and `--force` as `-f` if needed) inside the rm rule. Optionally deny argv0 that is an `rm` path (`*/rm`). Do not re-parse pipelines; keep compound forms as Escalate that **fail closed** (ENT-001).
- **Verification:** `Evaluate("rm --recursive --force /")` and `Evaluate("rm --recursive /home")` return Deny `deny-rm-catastrophic`. Compound forms still escalate, and Execute must not run them (ENT-001).
- **Ratchet candidate:** Table test next to existing `rm -rf /` cases in `level1_test.go`.

### ENT-008: Script-hash gate hashes a path, then `sh -c` re-reads it

- **Priority:** P2
- **Dimensions:** Security / dependencies
- **Status:** observed fact (TOCTOU window); needs verification for practical exploit timing
- **Evidence:** `handleScriptGate` hashes `inv.ResolvedPath` then `runScriptCommand` runs `exec.CommandContext(..., "sh", "-c", cmdStr)` (`engine.go:584-605`, `:660-662`). `resolveScriptPath` `Clean`s only (`internal/script/detect.go:164-187`); `os.Stat` follows symlinks.
- **Mechanism:** Approval is of content A; execution is whatever the path contains at exec time (B). Symlink targets are not frozen.
- **Blast radius:** Approved `bash foo.sh` / `./foo.sh` invocations. Inner commands are already out of policy by design (STABILITY.md script-hash trust model).
- **Counterevidence checked:** Hash is SHA-256 of file bytes at gate time; modification after approval is supposed to re-prompt — that holds across invocations, not within one. Documented as Needs review.
- **Smallest coherent remediation:** Open once (`O_NOFOLLOW`), hash those bytes, exec the interpreter with the fd/contents rather than a second path read.
- **Verification:** Flip file contents between hash and exec in a tight loop; audit hash must match executed bytes (no marker under the approved hash).
- **Ratchet candidate:** Integration test after the fd-exec change; until then, accepted residual in STABILITY.md.

### ENT-009: Shipped MCP server never sets ProjectRoot

- **Priority:** P2
- **Dimensions:** Architecture topology; Documentation / governance
- **Status:** observed fact
- **Evidence:** `cmd/doit/main.go:79` `engine.New(engine.Options{ConfigPath: configPath})` — no `ProjectRoot`. Overlay and T13 rules are gated on `opts.ProjectRoot != ""` (`engine.go:172-178`, `:203-212`, `:237-243`). `doit_repo_read` cannot pin to engine root (ENT-006).
- **Mechanism:** Library-only feature advertised as product behaviour (README “Per-project config”, STABILITY.md “Discovered via Options.ProjectRoot”). The binary operators run does not pass cwd or a discovered root in.
- **Blast radius:** All MCP-server deployments: no tighten-only overlay, no project-safe L1 allows, duration stats collapse to the empty project id.
- **Counterevidence checked:** Engine tests cover `ProjectRoot` (`engine_test.go:222`, `:248`). Discovery itself works. L3 `WorkDir` falls back to `os.Getwd()` (`engine.go:277-280`) — a different, looser notion of project.
- **Smallest coherent remediation:** Pass `os.Getwd()` (or an explicit `--project-root`) into `Options.ProjectRoot` at server start; document that the server's project is the process cwd.
- **Verification:** Run `doit` from a repo containing `.doit/config.yaml` that disables write; a write-tier command must see the overlay.
- **Ratchet candidate:** `cmd/doit` test or smoke that New receives a non-empty ProjectRoot.

### ENT-010: Dual rule engines have already drifted

- **Priority:** P2
- **Dimensions:** Redundancy / sources of truth; Change amplification
- **Status:** observed fact
- **Evidence:**
  - Live L1: `policy.checkRmCatastrophic` (system paths, globs, `~user`, `:202-276`) + `policy.checkGitCheckoutAll` (`:283-311`) + `compileConfigRules` (`:379-437`).
  - Dead registry plane: `rules.Hardcoded` / `rules.checkRmCatastrophic` (`hardcoded.go:43-63`) — **no system-path/glob/`~user` extensions**. `rules.CheckGitCheckoutAll` (`hardcoded.go:24-40`) uses `args[i+2]` indexing vs L1's `args[i+1]`.
  - Example Starlark: `rules/deny_rm_catastrophic.star` also lacks T25 extensions; loaded only by `examples_test.go` because default `starlark_rules_dir` is empty.
  - Config flags compiled twice: `rules.CompileCapRule` (`rules/config.go:20-56`) for the registry, `compileConfigRules` for L1 — same YAML, two closures.
- **Mechanism:** A bugfix or T25-style extension applied to the live L1 copy is not the copy `ApplyRules` installs, nor the example Starlark agents copy. Drift is not hypothetical: T25 landed only on the policy copy.
- **Blast radius:** Future rule authors; any future rewiring of CheckRules (ENT-002 option a) would enforce the weaker hardcoded copy.
- **Counterevidence checked:** `policy.HasAnyFlag` now delegates to `rules.HasAnyFlag` (`level1.go:440-444`) — the 2026-04-08 duplicate was fixed. Starlark examples are useful documentation if labelled as such.
- **Smallest coherent remediation:** Delete or wrap the registry RuleSet so there is one compiler. Point example `.star` files at the live L1 semantics or generate them. Label `rules/` as examples in README.
- **Verification:** A single table of catastrophic paths shared by Go L1 tests and Starlark example tests; registry CheckRules either gone or using that table.
- **Ratchet candidate:** Test that `rules.Hardcoded` and `checkRmCatastrophic` agree on T25 vectors, or that Hardcoded is unreferenced from production.

### ENT-011: `engine.go` and `mcptools.go` concentrate every change

- **Priority:** P2
- **Dimensions:** Change amplification; Local code quality
- **Status:** observed fact
- **Evidence:** `engine/engine.go` 1890 lines, 26 commits (highest churn). `mcptools/mcptools.go` 1434 lines, 13 commits. Both appear in nearly every feature (policy, audit excerpts, sessions, script gate, durations, elicitation). `cmd/doit/main.go` is 112 lines and has 0% statement coverage.
- **Mechanism:** Adding a policy concern requires edits in engine orchestration, MCP tool wiring, STABILITY.md, agents-guide, and often audit schema. There is no narrower facade; `Engine` is the public API *and* the process manager *and* the policy sequencer.
- **Blast radius:** Next token/audit/fail-closed fixes (ENT-001–004) all collide in `Execute`/`evaluatePolicy`/`handleExecute`. Merge conflict and regression risk on T40–T47.
- **Counterevidence checked:** Splitting for taste is rejected by repo Go guidance (clarity over decomposition). The issue is not length; it is that fail-open, token issue, script gate, and audit logging are interleaved in one function (`Execute` ~80 lines of control flow).
- **Smallest coherent remediation:** Extract a single `enforceDecision(pResult) (block Result, ok)` used by Execute and ExecuteStreaming so fail-closed is not duplicated. Do not split the package.
- **Verification:** Both Execute methods share the helper; a test that only the helper's Allow branch reaches `runShellCommand`.
- **Ratchet candidate:** `gofmt`/`go test` plus a comment invariant on the helper; optional `linelength` is not a ratchet.

### ENT-012: Governance ledgers contradict the shipped architecture

- **Priority:** P2
- **Dimensions:** Documentation / governance; Redundancy / sources of truth
- **Status:** observed fact
- **Evidence:**
  - `docs/todo.md` still unchecked for work shipped as 🎯T3, T4, T10–T16 (Starlark, per-project config, self-audit, repo-read, sessions). CLAUDE.md:56 points at it. Global AGENTS.md bans TODO files.
  - 🎯T8 achieved “persistent claudia session” / “doit imports claudia”; `go.mod` has no claudia; `engine.go:262-273` explains the reversal.
  - 🎯T24 achieved vs ENT-002.
  - README Go 1.25+ (`README.md:37`) vs `go.mod` `go 1.26.1`. README config example `level3_enabled: false` (`README.md:247`) vs `DefaultConfig` true (`config.go:90`).
  - CLAUDE.md:3 lists yaml/starlark/`x/sys`; omits direct `mcp-go`. `x/sys` is indirect.
  - `docs/threat-model.md:323` → `docs/targets.yaml`; ledger is `bullseye.yaml`. `.gitignore` still has `docs/targets.md`.
  - No `AGENTS.md`; no `hygiene.yaml`.
- **Mechanism:** Agents and humans read CLAUDE.md, todo.md, and achieved-target text as if they described the product. That is how T24 stays “done” while Validate is a no-op, and how L3-off is copied from README into tests that lock fail-open.
- **Blast radius:** Future agents implementing “achieved” behaviour; operators copying README L3-off; entropy of the intent ledger itself.
- **Counterevidence checked:** STABILITY.md is actively maintained (17 commits) and mostly matches code. Threat model is honest about MCP sibling bypass. bullseye T40–T47 correctly track the Fable-5 holes.
- **Smallest coherent remediation:** Delete or archive `docs/todo.md`; point CLAUDE.md at bullseye. Rewrite T8/T24 names/acceptance to the actual architecture or reopen them. Fix README Go version and L3 default. Point threat-model at `bullseye.yaml`.
- **Verification:** `rg claudia` in bullseye/acceptance vs `go.mod`; `rg docs/todo.md`; README Go version == `go.mod`.
- **Ratchet candidate:** Hygiene `file:` evidence that `docs/todo.md` is absent; optional `rg` in `make bullseye`.

### ENT-013: CI and release do not gate the properties the product claims

- **Priority:** P2
- **Dimensions:** Build / release / operations; Correctness / verification; Security / dependencies
- **Status:** observed fact
- **Evidence:**
  - `.github/workflows/ci.yml`: ubuntu `go build` / `go vet` / `go test ./...` only. No `-race`, coverage floor, `govulncheck`, golangci, macOS matrix (despite darwin/arm64 being a release target).
  - `release.yml:61` `skip_checksum: true` on Homebrew releaser. STABILITY.md flags missing NOTICES/THIRD_PARTY_LICENSES as a 1.0 licence concern.
  - Dependabot security updates disabled (`gh api` security_and_analysis).
  - `cmd/doit` 0.0% coverage — ProjectRoot omission (ENT-009) and missing `WithRecovery` have no test.
  - `make bullseye` runs vet+test+build+clean-tree locally; not invoked in CI.
- **Mechanism:** The P0/P1 defects are invisible to CI because tests specify fail-open and do not race the L2 store. Release artefacts are unsigned/unchecked checksums for a security gateway installed via Homebrew.
- **Blast radius:** Every PR merge; every Homebrew install.
- **Counterevidence checked:** Secret scanning and push protection enabled. `go-version-file: go.mod` keeps CI on 1.26.1. Tests are fast and real (including MCP integration in `mcptools`, 14s).
- **Smallest coherent remediation:** Add `go test -race` for `engine` and `internal/policy`; run `make bullseye` or equivalent in CI; stop `skip_checksum`; add NOTICES before 1.0. Do not add coverage theatre.
- **Verification:** CI log contains `-race`; Homebrew formula has checksums; `NOTICES` exists when 1.0 is claimed.
- **Ratchet candidate:** CI job steps as hygiene `ci_step` evidence once `hygiene.yaml` is declared.

### ENT-014: Audit Query/QueryLatest silently skip malformed lines

- **Priority:** P3
- **Dimensions:** Correctness / verification
- **Status:** observed fact
- **Evidence:** `query.go:52-54` and `QueryLatest` `:85-87` `continue` on `json.Unmarshal` error. `Tail` returns `skipped N malformed` (`verify.go:81-82`). `doit_audit_query` is the postmortem tool (🎯T38).
- **Mechanism:** A corrupt newest deny line makes `latest=true` report an older allow or nothing, with no warning.
- **Blast radius:** Operators using `doit_audit_query` after ENT-004's partial write.
- **Counterevidence checked:** Verify fails closed on invalid JSON (`verify.go:30-31`). Query is documented as not re-verifying the chain (`STABILITY.md` T38).
- **Smallest coherent remediation:** Return a skipped count like Tail; have `handleAuditQuery` print it.
- **Verification:** Log with a corrupt last deny + earlier allow; QueryLatest(deny) must surface the skip, not a silent nil.
- **Ratchet candidate:** Unit test alongside existing query tests.

### ENT-015: Architecture-shift leftovers still compile

- **Priority:** P3
- **Dimensions:** Local code quality
- **Status:** observed fact
- **Evidence:** golangci unused: `Engine.l3SessionClient` (`engine.go:335-339`), `Engine.logExecution` (`:1757-1759`), `defaultL3MaxChars` (`internal/policy/evidence.go:13`). Comment at `engine_test.go:157` still mentions “pipeline parser (legacy path)”.
- **Mechanism:** After claudia → `claude -p` and T17 parser removal, dead symbols remain. They do not execute, but they keep the old story in godoc and grep.
- **Blast radius:** Next editor of engine.go.
- **Counterevidence checked:** Not referenced; deleting is safe if tests pass.
- **Smallest coherent remediation:** Delete the unused funcs/const; fix the test comment.
- **Verification:** `golangci-lint` unused empty on those symbols.
- **Ratchet candidate:** `unused` linter in CI (optional; not present today).

## Redundancy and competing-source-of-truth inventory

| Concept | Live owner | Other copies | Drift? |
|---|---|---|---|
| Catastrophic rm | `policy.checkRmCatastrophic` (T25 complete) | `rules.checkRmCatastrophic` (weaker); `rules/deny_rm_catastrophic.star` (weaker); threat-model text | **Yes** — T25 only on L1 |
| git checkout `.` | `policy.checkGitCheckoutAll` | `rules.CheckGitCheckoutAll` (different `--` indexing) | **Yes** |
| Config reject_flags | `compileConfigRules` in L1 | `rules.CompileCapRule` on registry | Parallel compilers; registry unwired |
| Flag matching | `rules.HasAnyFlag` | `policy.HasAnyFlag` thin wrapper | No (delegates) |
| Dangerous-tier gate | none on exec path | `CheckTier`, `doit_check_config` §4, threat-model §3, README table | **Yes** — docs claim a gate |
| L3 architecture | `claude -p` one-shot (`engine.go:262-273`) | 🎯T8 “claudia session”; CLAUDE.md still says “one-shot `claude -p`” (code-aligned) / T8 not | **Yes** in bullseye |
| Intent ledger | `bullseye.yaml` | `docs/todo.md`; stale `docs/targets.yaml` pointer | **Yes** |
| Go version | `go.mod` 1.26.1 | README 1.25+ | **Yes** |
| L3 default | `DefaultConfig` true | README example false; tests L3-off | **Yes** (example vs default) |
| agents-guide | `agents-guide.md` + `//go:embed` in `doit.go` | printed by `--help-agent` | No — single source |
| Audit schema | `internal/audit/entry.go` | STABILITY.md catalogue | Manual sync; high churn, currently aligned |

Deliberate duplication to keep: Starlark examples as a teaching copy **if** labelled and generated from or tested against L1. Hash-chain genesis string `"doit-genesis"` in one constant (`logger.go:17`).

## Healthy structure worth retaining

- **Acyclic `internal/` DAG** with a single binary entry. `go list` shows no cycles. Capability implementations are one file per command under `builtin/`.
- **T17 opaque-command rule** is consistently applied in L1/L2 comments and `policy.Request`. Do not reintroduce a shell parser to “fix” ENT-007's compound forms; fail closed instead (ENT-001).
- **Tighten-only `MergeProject`** (`config.go:204-224`) cannot enable a globally disabled tier or drop global rules.
- **Token crypto and mutexing**, script-store mutex, audit logger mutex — local concurrency hygiene is good where it exists.
- **L2/script YAML atomic rename** (`SaveStore`) prevents torn files (not lost updates).
- **Starlark sandbox** (`go.starlark.net`, json builtin only) — example tests load `rules/` successfully.
- **Threat model + `doit_check_config` + sibling STARTUP warning** (🎯T32–T34) honestly describe MCP-bypass limits, even where §4 overclaims tiers.
- **L3 XML-tag escaping and injection corpus** (`internal/llm/testdata/injection_corpus.yaml`, 🎯T35).
- **STABILITY.md** as a surface catalogue — high maintenance cost, but it is the right shape of contract for a pre-1.0 MCP tool.
- **`--help-agent` embed** (`doit.go`) keeps the guide in the binary without a pre-build copy.
- **Process-group timeout kill** (`procgroup_unix.go`, exit 137) matches the documented time-expectation contract.
- **Fable-5 → 🎯T40–T47** is the correct way to retain unverified-but-reproduced security work; this audit re-verified rather than re-inventing IDs.

## Hygiene posture

**Hygiene posture not declared.** There is no `hygiene.yaml` at the repo root. The validator was not run and was not initialised.

Informal observation (not a hygiene verdict): reality includes LICENSE (Apache-2.0), README, `.gitignore`, `go test`/`go vet` in CI, secret scanning. Missing relative to a typical floor-2 declaration: race in CI, vuln scan, Dependabot, format/lint gate, SBOM/signing/checksums, CODEOWNERS, `hygiene.yaml` itself. `make bullseye` is a local correctness hook, not fleet-aggregatable evidence.

Overlap with entropy: ENT-013's CI/release gaps are the items a future `hygiene.yaml` should declare as `enforced` or honest `planned`/`skipped`. Do not ratchet from this audit.

## Oracle coverage and residue

| Load-bearing property | Decided by | Notes |
|---|---|---|
| Packages build and unit/integration tests pass | shipped: `go test ./...`, CI, `make test` | Green at this snapshot. Encodes fail-open. |
| `go vet` clean | shipped: CI / `make vet` | Green. |
| L1 deny `rm -rf /` (short flags, argv0 `rm`) | shipped: `level1_test.go` | Green. |
| T17 compound commands do not L1-allow | shipped: `level1_test.go` | Green (escalate, not deny). |
| Fail-closed Execute on non-Allow | **nothing** | ENT-001. Tests require the opposite. |
| Token = human approval | **nothing** | ENT-003. |
| Audit chain gap-free after I/O error | **nothing** | ENT-004. Size-limit test specifies silent skip. |
| Verify never panics | **nothing** | ENT-004. |
| L2 RMW lossless | **nothing** | ENT-005. CI has no `-race`. |
| repo_read symlink confinement | **nothing** | ENT-006. |
| `rm --recursive` deny | **nothing** | ENT-007. |
| Live L3 `claude -p` contract | **nothing this run** | Mocked in unit tests. Residue. |
| Dangerous-tier runtime gate | tests of CheckTier only | Not on exec path (ENT-002). |
| Per-project overlay in the server binary | engine tests with ProjectRoot | Not used by `cmd/doit` (ENT-009). |
| Supply-chain / vuln | secret scanning only | No govulncheck, Dependabot off. |
| staticcheck | failed | Tool built with go1.25; module is 1.26.1. |

**Owner residue (intent, not mechanical work):**

1. Is L3-off a supported production mode, or test-only? If supported, ENT-001 is mandatory before any other feature.
2. Should approval tokens exist on the engine API at all, given elicitation uses `Retry`?
3. Option (a) rewire CheckTier vs (b) stop advertising it — product call.
4. Should the MCP server take process cwd as `ProjectRoot` by default?

**Failed/skipped checks:** `staticcheck` compile failure; `govulncheck` not installed; hygiene undeclared; origin/master +1 not fetched; live L3 not run.

## Remediation sequence

1. **Fail closed (ENT-001 / 🎯T40).** Shared helper in Execute + ExecuteStreaming; invert tests that require unapproved execution; elicitation-error path returns error. This is the oracle seam: every later security fix is meaningless while Escalate runs the command.
2. **Token provenance + non-consuming peek (ENT-003 / 🎯T41+T46+T47) in one change.** Do not land T46/T47 first.
3. **Either wire or delete the registry safety plane (ENT-002) and normalise `rm --recursive` (ENT-007).** Same evaluatePolicy edit window as (1) if wiring.
4. **Audit write-then-advance, Verify clamp, loud size-limit (ENT-004 / 🎯T42+T43); Query skip count (ENT-014).** Then L2 mutex+race test (ENT-005 / 🎯T44).
5. **repo_read EvalSymlinks + pin project_root (ENT-006 / 🎯T45) after server sets ProjectRoot (ENT-009).**
6. **Collapse dual rule compilers (ENT-010); delete unused leftovers (ENT-015); retire `docs/todo.md` and fix T8/T24/README (ENT-012).**
7. **CI `-race` on engine/policy; drop `skip_checksum`; NOTICES (ENT-013).** Declare `hygiene.yaml` only after those gates exist, as a separate requested change.
8. Re-run this audit on the same definitions (P0=0, CheckTier either called or undocumented, T40–T47 achieved with the tests named above).

Do not apply this sequence as part of the audit.

## Comparison appendix

Not a compare-mode run. Mapping to Fable-5 (2026-07, HEAD's parent work):

| Fable-5 | This audit | Status at 827fb63 |
|---|---|---|
| F1 fail-open | ENT-001 | still present; tests still require it |
| F2 Evaluate consumes token | ENT-003 | still present |
| F3 self-issued token | ENT-003 | still present on library Execute; MCP accidentally blocked by F2 |
| F4 logger advance-before-write | ENT-004 | still present |
| F5 Verify panic | ENT-004 | still present; still no WithRecovery |
| F6 repo_read | ENT-006 | still present |
| F7 L2 lost update | ENT-005 | still present |
| F8 doit_approve consume | ENT-003 | still present |
| F9 L2 pointer race | ENT-005 | still present |
| F10 script TOCTOU | ENT-008 | still present |
| F11 NewLogger genesis reset | ENT-004 | still present |
| F12 size-limit latch | ENT-004 | still present |
| F13 Query skip | ENT-014 | still present |
| F14 dead CheckTier | ENT-002 | still present |
| F15 `rm --recursive` | ENT-007 | still present |

New in this snapshot (entropy lenses, not Fable-5): ENT-009 ProjectRoot-less server; ENT-010 drifted dual rules; ENT-011 hubs; ENT-012 ledger contradictions; ENT-013 CI/release; ENT-015 leftovers; hygiene undeclared; `staticcheck`/Go 1.26 mismatch.
