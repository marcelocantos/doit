# Stability

doit follows [semantic versioning](https://semver.org/). Once 1.0 ships,
breaking changes to the public API, MCP interface, configuration format,
audit log format, or Starlark rule contract will require a major version
bump. The pre-1.0 period exists to get these right.

Snapshot as of v0.2.0.

## Interaction surface catalogue

### MCP tools (primary interface)

| Tool | Parameters | Stability |
|---|---|---|
| `execute` | command, justification, safety_arg, cwd, env, approved, retry | Stable |
| `dry_run` | command, justification, safety_arg | Stable |
| `policy_status` | (none) | Stable |
| `approve` | token | Stable |

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
| `Request` struct | Command, Args, Justification, SafetyArg, Cwd, Env, Approved, Retry | Stable |
| `Result` struct | ExitCode, Stdout, Stderr, PolicyLevel, PolicyDecision, PolicyReason, PolicyRuleID, EscalateToken | Stable |
| `EvalResult` struct | Decision, Level, Reason, RuleID, Segments, Tiers | Stable |

### CLI subcommands and flags (legacy, secondary interface)

| Surface | Signature | Stability |
|---|---|---|
| Direct execution | `doit <capability> [args...]` | Stable |
| Config rule bypass | `doit --retry <cmd> [args...]` | Stable |
| List capabilities | `doit --list [--tier <tier>]` | Stable |
| Help | `doit --help [<capability>]` | Stable |
| Agent guide | `doit --help-agent` | Stable |
| Audit operations | `doit --audit <verify\|show\|tail>` | Stable |
| Policy operations | `doit --policy <promote\|list\|approve\|reject>` | Needs review |
| Version | `doit --version` | Stable |

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
| `policy.level3_enabled` | bool | `false` | Stable |
| `policy.level3_model` | string | `""` | Stable |
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
| `check` | function(command, args) → dict or None | yes | Stable |
| `tests` | list of test dicts | yes | Stable |

Check return dict: `{"decision": "allow"\|"deny"\|"escalate", "reason": "..."}`.
Test dict: `{"command": "...", "args": [...], "expect": "allow"\|"deny"\|"escalate"}`.

### Three-level policy engine

| Level | Type | Stability |
|---|---|---|
| L1: Deterministic (Go rules + Starlark) | first-match-wins | Stable |
| L2: Learned patterns | policy store | Stable |
| L3: Live LLM | escalation with token | Needs review |

### Audit log entry schema (JSON Lines)

| Field | JSON key | Type | Stability |
|---|---|---|---|
| Sequence number | `seq` | uint64 | Stable |
| Timestamp | `ts` | RFC 3339 UTC | Stable |
| Previous hash | `prev_hash` | string (hex SHA-256) | Stable |
| Pipeline description | `pipeline` | string | Stable |
| Capability names | `segments` | []string | Stable |
| Tier per segment | `tiers` | []string | Stable |
| Retry flag | `retry` | bool (omitempty) | Stable |
| Exit code | `exit_code` | int | Stable |
| Error message | `error` | string (omitempty) | Stable |
| Duration | `duration_ms` | float64 | Stable |
| Working directory | `cwd` | string | Stable |
| Entry hash | `hash` | string (hex SHA-256) | Stable |

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

### Exit code conventions

| Condition | Exit code | Stderr | Stability |
|---|---|---|---|
| Command succeeds | 0 | (none) | Stable |
| Command fails with code N | N | (command's own stderr) | Stable |
| doit-internal error | 2 | `doit: <error>` | Stable |

## Gaps and prerequisites for 1.0

- **`doit --audit tail` hardcoded to 20 entries**: Should accept an optional
  count argument before locking the CLI surface.
- **L3 policy UX**: The L3 escalation/approval flow (token-based) needs more
  real-world usage before declaring stable.
- **`--policy` subcommands**: promote/list/approve/reject interface is
  functional but may need refinement.

## Out of scope for 1.0

- **Config-defined capabilities**: Declaring new capabilities in YAML.
- **Append redirect (`››`)**: Not yet needed. Can be added without breaking
  changes.
- **Out-of-band user interface**: Approval queue, notification widgets.
