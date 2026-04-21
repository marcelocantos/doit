# Stability

doit follows [semantic versioning](https://semver.org/). Once 1.0 ships,
breaking changes to the public API, MCP interface, configuration format,
audit log format, or Starlark rule contract will require a major version
bump. The pre-1.0 period exists to get these right.

Snapshot as of v0.7.0.

## Interaction surface catalogue

### MCP tools (primary interface)

**Core execution**

| Tool | Parameters | Stability |
|---|---|---|
| `doit_execute` | command, justification, safety_arg, cwd, approved, timeout_seconds, expected_duration_seconds | Stable |
| `doit_dry_run` | command, justification, safety_arg, cwd, timeout_seconds, expected_duration_seconds | Stable |
| `doit_approve` | token, command | Stable |

**Work sessions**

| Tool | Parameters | Stability |
|---|---|---|
| `doit_session_start` | scope (required), description, timeout_minutes | Needs review |
| `doit_session_end` | session_id (optional) | Needs review |
| `doit_session_status` | (none) | Needs review |

**Policy inspection and management**

| Tool | Parameters | Stability |
|---|---|---|
| `doit_policy_status` | (none) | Stable |
| `doit_policy_list` | (none) | Needs review |
| `doit_policy_delete` | id (required) | Needs review |
| `doit_policy_review` | (none) | Needs review |
| `doit_self_audit` | (none) | Needs review |
| `doit_list_capabilities` | tier (optional) | Stable |
| `doit_approvals_list` | (none) | Needs review |
| `doit_approvals_revoke` | hash (required) | Needs review |
| `doit_durations_list` | (none) | Needs review |

**Audit log**

| Tool | Parameters | Stability |
|---|---|---|
| `doit_audit_verify` | (none) | Stable |
| `doit_audit_tail` | count (optional, default 20) | Stable |

**Deployment and context**

| Tool | Parameters | Stability |
|---|---|---|
| `doit_check_config` | settings_path (optional) | Stable |
| `doit_repo_read` | filename (required), project_root (optional) | Needs review |

### Engine API (`engine/` package)

| Surface | Signature | Stability |
|---|---|---|
| `New(opts Options, engineOpts ...EngineOption)` | `(*Engine, error)` | Stable |
| `Options.ConfigPath` | `string` | Stable |
| `Options.ProjectRoot` | `string` | Stable |
| `Engine.Execute(ctx, req)` | `Result` | Stable |
| `Engine.Evaluate(ctx, req)` | `EvalResult` | Stable |
| `Engine.ExecuteStreaming(ctx, req, stdout, stderr)` | `Result` | Stable |
| `Engine.PolicyStatus()` | `map[string]any` | Stable |
| `Request` struct | Command, Args, Justification, SafetyArg, Cwd, Env, Approved, Retry, TimeoutSeconds, ExpectedDurationSeconds | Stable |
| `policy.Request` struct | Command, Cwd, Retry, Justification, SafetyArg, ProjectType, TimeoutSeconds, ExpectedDurationSeconds | Stable |
| `Result` struct | ExitCode, Stdout, Stderr, PolicyLevel, PolicyDecision, PolicyReason, PolicyRuleID, EscalateToken | Stable |
| `EvalResult` struct | Decision, Level, Reason, RuleID, Bypassable, ScriptApproval | Stable |
| `ScriptApprovalRequest` struct | Interpreter, Path, ContentHash, ContentPreview, SizeBytes | Needs review |
| `Engine.ApproveScript(hash, pathHint, justification)` | `(*script.Approval, error)` | Needs review |
| `Engine.RevokeScriptApproval(hash)` | `error` | Needs review |
| `Engine.ListScriptApprovals()` | `([]script.Approval, error)` | Needs review |
| `Engine.ScriptApprovalStorePath()` | `string` | Needs review |
| `Engine.DurationStorePath()` | `string` | Needs review |
| `Engine.LearnDurations()` | `(int, error)` | Needs review |
| `Engine.ListCapabilities()` | `[]CapabilityInfo` | Stable |
| `Engine.AuditPath()` | `string` | Stable |
| `Engine.RecordDecision(command, decision)` | `error` | Fluid |
| `Engine.ProposeRules(command, decision)` | `[]RuleProposal` | Fluid |
| `Engine.WriteStarlarkRule(ruleID, source)` | `error` | Fluid |
| `Engine.StartSession(scope, description, timeout)` | `(id string, error)` | Needs review |
| `Engine.EndSession(id)` | `bool` | Needs review |
| `Engine.ActiveSession()` | `*WorkSession` | Needs review |
| `WorkSession` struct | ID, Scope, Description, StartedAt, Timeout | Needs review |
| `Engine.ProjectContext()` | `*context.ProjectContext` | Fluid |

### MCP elicitation protocol

| Phase | Trigger | Options | Stability |
|---|---|---|---|
| Phase 1 (decision) | Policy escalation or bypassable deny | Allow once, Allow always, Deny, Deny always | Stable |
| Phase 2 (promotion) | "Always" choice in Phase 1 | Starlark rules at narrow/moderate/broad generality, or decline | Fluid |
| Script approval | Unapproved shell-script invocation detected | approve, deny | Needs review |

### CLI flags (MCP server binary)

| Flag | Stability |
|---|---|
| `--version` | Stable |
| `--help` | Stable |
| `--help-agent` | Stable |
| `--config <path>` | Stable |

### Configuration schema (`~/.config/doit/config.yaml`)

| Field | Type | Default | Stability |
|---|---|---|---|
| `tiers.read` | bool | `true` | Stable |
| `tiers.build` | bool | `true` | Stable |
| `tiers.write` | bool | `true` | Stable |
| `tiers.dangerous` | bool | `false` | Stable |
| `audit.path` | string | `~/.local/share/doit/audit.jsonl` | Stable |
| `audit.max_size_mb` | int | `100` | Stable |
| `rules.<cap>.reject_flags` | []string | per-capability | Stable |
| `rules.<cap>.subcommands.<sub>.reject_flags` | []string | per-subcommand | Stable |
| `policy.level1_enabled` | bool | `true` | Stable |
| `policy.level2_enabled` | bool | `true` | Stable |
| `policy.level2_path` | string | `~/.local/share/doit/policy.json` | Stable |
| `policy.level3_enabled` | bool | `true` | Stable |
| `policy.level3_fast_model` | string | `"sonnet"` | Needs review |
| `policy.level3_model` | string | `"opus"` | Needs review |
| `policy.level3_timeout` | string | `"60s"` | Stable |
| `policy.starlark_rules_dir` | string | `""` | Stable |

### Per-project configuration (`.doit/config.yaml`)

| Behaviour | Stability |
|---|---|
| Tighten-only tiers (can disable, cannot enable) | Stable |
| Additive rules (can add, cannot remove global rules) | Stable |
| Discovered via `Options.ProjectRoot` | Stable |

### Starlark rule contract (`.star` files)

| Global | Type | Required | Stability |
|---|---|---|---|
| `rule_id` | string | yes | Stable |
| `description` | string | no | Stable |
| `bypassable` | bool | no (default false) | Stable |
| `check` | function(command, args[, meta]) → dict or None | yes | Stable |
| `tests` | list of test dicts | yes | Stable |

Check return dict: `{"decision": "allow"\|"deny"\|"escalate", "reason": "..."}`.
Test dict: `{"command": "...", "args": [...], "expect": "allow"\|"deny"\|"escalate"[, "meta": {...}]}`.

`check` may declare two or three parameters. The 3-param form opts in
to a `meta` dict carrying `timeout_seconds`, `expected_duration_seconds`,
`justification`, and `safety_arg`. 2-param rules are unaffected.

### Three-level policy engine

| Level | Type | Stability |
|---|---|---|
| L1: Deterministic (Go rules + Starlark) | first-match-wins | Stable |
| L2: Learned patterns | policy store | Stable |
| L3a: Live LLM (fast triage, sonnet by default) | one-shot `claude -p` | Needs review |
| L3b: Live LLM (deep reasoning, opus by default) | one-shot `claude -p`, only when L3a escalates | Needs review |

Relevant config fields: `policy.level3_fast_model` (default `sonnet`),
`policy.level3_model` (default `opus`). Setting both to the same value
collapses the cascade to a single-tier.

### Audit log entry schema (JSON Lines)

| Field | JSON key | Type | Stability |
|---|---|---|---|
| Sequence number | `seq` | uint64 | Stable |
| Timestamp | `ts` | RFC 3339 UTC | Stable |
| Previous hash | `prev_hash` | string (hex SHA-256) | Stable |
| Command string | `pipeline` | string | Stable |
| Capability names | `segments` | []string | Stable |
| Tier per segment | `tiers` | []string | Stable |
| Retry flag | `retry` | bool (omitempty) | Stable |
| Exit code | `exit_code` | int | Stable |
| Error message | `error` | string (omitempty) | Stable |
| Duration | `duration_ms` | float64 | Stable |
| Working directory | `cwd` | string | Stable |
| Policy level | `policy_level` | int (omitempty) | Stable |
| Policy result | `policy_result` | string (omitempty) | Stable |
| Policy rule ID | `policy_rule_id` | string (omitempty) | Stable |
| Justification | `justification` | string (omitempty) | Stable |
| Safety argument | `safety_arg` | string (omitempty) | Stable |
| Script content hash | `script_hash` | string (omitempty) | Needs review |
| Script path | `script_path` | string (omitempty) | Needs review |
| Expected duration | `expected_duration_ms` | float64 (omitempty) | Needs review |
| Timed out | `timed_out` | bool (omitempty) | Needs review |
| Entry hash | `hash` | string (hex SHA-256) | Stable |

The `pipeline` field retains its name for backwards compatibility with
older audit logs, but in v0.5.0+ it holds the full command string passed
to `sh -c` — there is no pipeline parsing at the engine level.

The `segments`/`tiers` fields contain a single-element array derived from
the first token of the command, for coarse filtering during audit queries
(`Filter.Cap`). They are not a semantic decomposition of the command and
do not reflect what the shell actually runs.

These fields are deprecated as of 🎯T17 (released in v0.6.0). New writes
populate them for backwards compatibility with log readers that use
`Filter.Cap`, but they carry no policy semantics — the engine treats the full
command string as opaque. A future major release will remove them.

Genesis hash: SHA-256 of `"doit-genesis"`.

### Safety tiers

| Tier | Value | Default | Stability |
|---|---|---|---|
| read | 0 | enabled | Stable |
| build | 1 | enabled | Stable |
| write | 2 | enabled | Stable |
| dangerous | 3 | disabled | Stable |

### Built-in capabilities (19)

| Name | Tier | Stability |
|---|---|---|
| cat | read | Stable |
| chmod | dangerous | Stable |
| cp | write | Stable |
| find | read | Stable |
| git | varies | Stable |
| go | varies | Stable |
| grep | read | Stable |
| head | read | Stable |
| ls | read | Stable |
| make | build | Stable |
| mkdir | write | Stable |
| mv | write | Stable |
| rm | dangerous | Stable |
| sort | read | Stable |
| tail | read | Stable |
| tee | write | Stable |
| tr | read | Stable |
| uniq | read | Stable |
| wc | read | Stable |

### Hardcoded rules (permanent, never bypassable)

| Rule | Capability | Condition | Stability |
|---|---|---|---|
| Catastrophic rm | rm | `-r`/`-R` with `/`, `.`, `..`, `~` | Stable |

### Default config rules (bypassable with --retry)

| Rule | Capability | Rejected flags | Stability |
|---|---|---|---|
| Parallel make | make | `-j` | Stable |
| Force push | git push | `--force`, `-f`, `--force-with-lease` | Stable |
| Hard reset | git reset | `--hard` | Stable |
| Checkout all | git checkout | `.` (with or without `--`) | Stable |
| Duration mismatch | (built-in) | `sleep N` where N > 2× `expected_duration_seconds` | Needs review |

### L2-scope duration rules (bypassable with --retry)

| Rule ID | Condition | Stability |
|---|---|---|
| `duration-anomaly` | `expected_duration_seconds` below p50/5 or above p95×5 for a pattern with ≥5 samples | Needs review |
| `timeout-too-short` | `timeout_seconds` below learned p50 for the pattern | Needs review |

### Script-hash approval gate (tier-0 pre-policy)

| Surface | Notes | Stability |
|---|---|---|
| Detection scope | `bash\|sh\|zsh <path>`, `./path` with shell shebang; pipelines and compound commands fall through | Needs review |
| Hash | SHA-256 over full file contents, prefixed `sha256:` | Stable |
| Storage | `~/.config/doit/script-approvals.yaml` (per-user) | Needs review |
| Trust model | Blanket content-trust; bypasses L1/L2/L3 for the outer invocation; inner commands run under `sh -c` unmediated | Needs review |
| Audit rule IDs | `script-hash-approved`, `script-hash-matched`, `script-hash-pending`, `script-hash-revoked`, `script-hash-error` | Needs review |

### Learned duration statistics

| Surface | Notes | Stability |
|---|---|---|
| Storage | `~/.config/doit/duration-stats.yaml` (per-user) | Needs review |
| Aggregator | `policy.AggregateDurations(entries)` — successful non-timed-out runs only | Needs review |
| Distribution | p50 and p95 (linear interpolation) in milliseconds | Needs review |
| Keying | `(cap, subcmd)` from audit segments (fallback: first two words of Pipeline) | Needs review |
| Anomaly thresholds | factor = 5× (expected below p50/5 or above p95×5); min samples = 5 | Needs review |
| Refresh trigger | Background piggy-back on `tryPromote`; explicit `Engine.LearnDurations()` | Needs review |

### Exit code conventions

| Condition | Exit code | Stderr | Stability |
|---|---|---|---|
| Command succeeds | 0 | (none) | Stable |
| Command fails with code N | N | (command's own stderr) | Stable |
| doit-internal error | 2 | `doit: <error>` | Stable |

## Gaps and prerequisites for 1.0

- **Elicitation phase 2 maturity**: Rule promotion via elicitation is functional
  but the proposal generation (`ProposeRules`) uses simple pattern extraction.
  Needs real-world usage to validate rule quality.
- **L3 cascade settling**: The two-tier `sonnet → opus` cascade is new. Model
  names, prompt templates, and the fast-tier confidence threshold all need
  real-world calibration before locking in. Config fields
  `level3_fast_model` / `level3_model` are Needs review.
- **Session semantics**: Work sessions (`doit_session_start`/`_end`/`_status`)
  and their effect on L3 prompting landed in v0.5.0 and have not been
  exercised at scale. The scope/description contract may tighten before
  1.0 — in particular whether expired sessions should hard-deny follow-up
  commands or silently drop the scope prefix.
- **`doit_repo_read` allowlist**: The allowlist (`.gitignore`, `Makefile`,
  `go.mod`, …) is hardcoded. Needs review before 1.0 — likely becomes
  config-driven with per-project extensions.
- **Self-audit heuristics**: `doit_self_audit` detects contradictions,
  staleness, and duplicates with fixed thresholds (90-day stale window,
  equality-based contradiction check). These thresholds will need
  validation and likely become configurable.
- **Script-hash detection scope**: The tier-0 gate fires only for
  `bash|sh|zsh <path>` and `./<path>` with a shell shebang — pipelines,
  `bash -c "…"`, and non-shell interpreters (python, node) fall through.
  Before 1.0, decide whether to broaden the scope (shared mechanism for
  other interpreters) or keep it narrow-and-documented as the contract.
- **Anomaly-rule calibration**: The duration-anomaly / timeout-too-short
  factor (5×) and minimum-sample threshold (5) are hardcoded heuristics.
  Needs real-world calibration before 1.0 — thresholds likely become
  configurable, and the "clip and warn" semantics may want refinement
  (e.g. separate thresholds for under vs. over estimate).
- **Duration store schema stability**: The YAML shape under
  `~/.config/doit/duration-stats.yaml` is marked Needs review.
  `Replace`-style full rewrites on each learn cycle work for small
  history but may evolve to incremental updates and/or a decay function.

## Out of scope for 1.0

- **Config-defined capabilities**: Declaring new capabilities in YAML.
- **Out-of-band user interface**: Approval queue, notification widgets.
