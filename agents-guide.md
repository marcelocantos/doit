# doit — Agent Usage Guide

*You can also view this guide at any time by running `doit --help-agent`,
which prints the CLI reference followed by this document.*

## Security model — doit is the sole execution path

**Never use Bash directly. All commands must go through `doit_execute`.**

doit's security model depends on being the sole execution path. If an agent
has direct Bash access alongside doit, the policy engine, audit log, and safety
tiers are all bypassable. To enforce this, Claude Code must be configured to
deny the Bash tool:

```json
{
  "permissions": {
    "deny": ["Bash"]
  }
}
```

Place this in `.claude/settings.json` (project scope) or `~/.claude/settings.json`
(user scope). With doit registered as an MCP server, `doit_execute` replaces
Bash as the execution path — with policy enforcement, audit logging, and
interactive escalation built in.

Use `doit_check_config` to verify the deployed configuration against the
threat-model safety contract — every load-bearing setting (Bash denial, doit
registration, dangerous-tier state, policy-store permissions, L3 model choice,
sibling MCP servers, project-config presence) is reported with its safety-model
interpretation, with WARN/FAIL flagged distinctly from informational items.

---

doit is an MCP server that mediates command execution through a three-level
policy engine. All commands are executed via MCP tools — there is no CLI
interface for command execution.

## MCP tools

### Core execution

| Tool | Purpose |
|---|---|
| `doit_execute` | Execute a command through the policy engine |
| `doit_dry_run` | Evaluate a command without executing (policy check only) |
| `doit_approve` | Validate an approval token for a previously escalated command |

### Work sessions

| Tool | Purpose |
|---|---|
| `doit_session_start` | Start a work session with a declared scope. L3 evaluations during the session reuse the scope to decide faster and with more context. |
| `doit_session_end` | End the active work session |
| `doit_session_status` | Show the active session (or "no active session") |

### Policy inspection and management

| Tool | Purpose |
|---|---|
| `doit_policy_status` | Show policy engine state (enabled levels, rule counts, L3 models) |
| `doit_policy_list` | List L2 learned policy entries (match criteria, decision, provenance, review schedule) |
| `doit_policy_delete` | Delete an L2 learned entry by ID |
| `doit_policy_review` | List L2 entries that are overdue for review |
| `doit_self_audit` | Run a self-audit of the rule set — contradictions, stale entries, missing Starlark IDs, duplicate coverage |
| `doit_list_capabilities` | List registered capabilities and their tiers |
| `doit_approvals_list` | List approved shell-script content hashes |
| `doit_approvals_revoke` | Revoke a script-content-hash approval |
| `doit_durations_list` | List learned per-pattern duration statistics |

### Audit log

| Tool | Purpose |
|---|---|
| `doit_audit_verify` | Verify audit log hash chain integrity |
| `doit_audit_tail` | Show recent audit log entries |
| `doit_audit_query` | Query the audit log with filters for postmortem analysis |

### Deployment and context

| Tool | Purpose |
|---|---|
| `doit_check_config` | Verify deployment config against the threat-model safety contract (every load-bearing setting reported with its safety-model interpretation; weakened-from-default settings flagged distinctly from informational items) |
| `doit_repo_read` | Read an allowlisted project file (`.gitignore`, `Makefile`, `go.mod`, `package.json`, `Cargo.toml`, `pyproject.toml`, `CLAUDE.md`, `.doit/config.yaml`) for claim verification during L3 reasoning |

## Work sessions

When you're about to do a coherent chunk of work — e.g., "build and test doit
in `~/work/.../doit`" — call `doit_session_start` first with a narrow `scope`
and one-paragraph `description`. L3 evaluations inside the session reuse the
scope, so subsequent commands that fit the declared work are approved faster
and with more accurate reasoning. Call `doit_session_end` when you're done.

Sessions auto-expire after `timeout_minutes` (default 30). Use
`doit_session_status` to check the active session.

## Executing commands

Use `doit_execute` for all command execution. Commands are passed as shell
strings and executed via `sh -c`:

```json
{"command": "git status", "cwd": "/path/to/repo"}
{"command": "grep -r TODO src/", "justification": "searching for open items"}
```

Shell features (pipes, redirects, `&&`, `||`) work naturally:

```json
{"command": "grep -r TODO src/ | head -20"}
{"command": "make build && git add -A"}
```

### Time expectations

Two optional fields let you declare how long a command should take:

- `timeout_seconds` — hard ceiling. When set, doit kills the entire
  process group on expiry (exit code `137`, SIGKILL). Use this for
  any command that *could* hang (network requests, watchers,
  servers in foreground).
- `expected_duration_seconds` — soft estimate, recorded in the audit
  log alongside the actual duration. Does not affect execution, but
  future L1/L2 rules may flag mismatches.

```json
{"command": "curl https://slow.example.com/data", "timeout_seconds": 30}
{"command": "make test", "expected_duration_seconds": 15}
{"command": "npm install", "timeout_seconds": 180, "expected_duration_seconds": 60}
```

Zero or omitted means no timeout / no estimate. Timeouts propagate to
the entire process group, so `bash foo.sh` is killed along with any
children the script spawned.

A built-in L1 rule (`flag-duration-mismatch`, bypassable) deny-flags
commands whose duration is knowable from the command itself (today:
`sleep N`) and obviously exceeds the declared
`expected_duration_seconds`. The threshold is 2× — `sleep 30` with
`expected_duration_seconds=10` is flagged; `sleep 20` is not. Starlark
rules may opt in to expectation-aware logic by declaring a third
`meta` parameter on their `check` function; `meta` is a dict carrying
`timeout_seconds`, `expected_duration_seconds`, `justification`, and
`safety_arg`.

doit also learns per-pattern durations from the audit log as a side
effect of successful executions. The aggregator groups by capability
and subcommand (e.g. `git status`, `make test`) and records p50 and
p95 in milliseconds, persisted at
`~/.config/doit/duration-stats.yaml`. Two L2-scope rules use this
store:

- `duration-anomaly` (bypassable) — fires when
  `expected_duration_seconds` is below p50/5 or above p95×5 for a
  pattern with ≥5 successful samples. Catches agents that wildly
  mis-estimate.
- `timeout-too-short` (bypassable) — fires when `timeout_seconds` is
  below p50, i.e. the agent would kill a normal run before it finished.

Both are skipped under `--retry`. Use `doit_durations_list` to inspect
the learned distributions.

## Safety tiers

Each capability has a safety tier: read, build, write, or dangerous.
Dangerous-tier capabilities (rm, chmod, git push) are disabled by default.
If a command is rejected due to its tier, do not attempt to bypass it.

Use `doit_list_capabilities` to see all capabilities and their tiers.

## Policy decisions via elicitation

When the policy engine blocks a bypassable rule or escalates a decision,
doit presents an interactive dialog to the user with four options:

- **Allow once** — execute this command, no policy change
- **Allow always** — execute and record the decision for future matching
- **Deny** — don't execute
- **Deny always** — don't execute and record the decision

After "Allow always" or "Deny always", a follow-up dialog may propose
creating a permanent Starlark rule at varying generality levels.

### Three types of denials

1. **Hardcoded rule** — A safety rule permanently blocks the operation
   (e.g., `rm -rf /`). Cannot be bypassed. Do not retry.
2. **Config rule** — A configurable rule blocks the operation (e.g.,
   `make -j`, `git push --force`). The user will be prompted to
   override via elicitation.
3. **Policy escalation** — The policy engine needs human review. The
   user will be prompted with the policy reasoning and options.

## Shell-script content-hash approval

The single-command inspection doit performs for `bash foo.sh` or
`./foo.sh` tells the policy engine nothing about what the script will
do once it starts running. To close this gap, doit runs a dedicated
content-hash gate *before* L1/L2/L3 whenever the command is a plain
shell-script invocation.

### Scope

The gate fires for commands of exactly these forms (after shell-word
tokenisation):

- `bash <path> [args…]`, `sh <path> [args…]`, `zsh <path> [args…]`
  (including path-qualified forms like `/bin/bash foo.sh`).
- Direct execution of a file whose shebang names `bash`, `sh`, or `zsh`
  — `./foo.sh`, `/abs/path/foo.sh`, `../foo.sh`.

The gate does **not** fire for:

- Pipelines (`bash foo.sh | cat`), compound commands (`… && …`, `… ; …`),
  redirects (`> out`), subshells, command substitution, or any form
  that contains shell metacharacters. These fall through to normal L1/L2/L3.
- Inline interpreter invocations like `bash -c "…"` — there is no file to
  hash, so the normal policy chain evaluates the outer `bash -c` instead.
- Non-shell interpreters (`python script.py`, `node app.js`). These may
  share the mechanism in a future iteration; for now they are evaluated
  by the normal policy chain.

### Trust model

Hash approval is **blanket trust for a specific byte sequence**. When
you approve `foo.sh`, you are authorising every command the script
might run on your behalf — the shell that executes the script is not
mediated by doit. Read the preview carefully before approving.

- First encounter: doit hashes the resolved script (SHA-256), shows
  the path, size, hash, and a truncated content preview via MCP
  elicitation, and asks the user to approve or deny.
- Subsequent invocations of the same content bypass elicitation and
  run directly. Each bypass is audited with `policy_rule_id =
  script-hash-matched` and carries both `script_hash` and
  `script_path` fields.
- Modifying the script changes the hash. The next invocation re-fires
  the elicitation.
- Approvals are keyed by hash alone — they apply across any path or
  project where the identical content appears.

### Managing approvals

Approvals are stored at `~/.config/doit/script-approvals.yaml`. Use
`doit_approvals_list` to inspect and `doit_approvals_revoke` to remove
an entry. Revocation is also audited.

## Audit log

All invocations are logged to a tamper-evident audit trail (SHA-256 hash
chain). Use `doit_audit_verify` to check integrity and `doit_audit_tail`
to view recent entries.

### Postmortem queries with `doit_audit_query`

`doit_audit_query` accepts filter parameters for targeted lookups. All
filters are ANDed. Results are returned oldest-first, up to `limit`
(default 20, max 200).

```
# The last thing doit refused
doit_audit_query(policy_result="deny", latest=true)

# All L3 escalations in the last hour, with the L3 prompt + response
doit_audit_query(policy_level=3, since="1h", include="l3")

# The elicitation chain that created a particular rule
doit_audit_query(parent_seq=<seq from policy_rule_id lookup>, include="elicitation")
```

Key parameters:

- `policy_result` — allow, deny, escalate, allow_once, allow_always, deny_once, deny_always, proposal_accepted, proposal_declined
- `policy_level` — 1, 2, or 3
- `rule_id` — exact match against the `policy_rule_id` field
- `cwd_substring` / `project_root` — scope by working directory
- `since` / `until` — relative duration ("1h", "30m") or RFC3339 timestamp
- `exit_code` — integer value or `"nonzero"` for any non-zero exit
- `cap` — capability name (exact match against any element of `segments`)
- `command_substring` — substring match against the `pipeline` field
- `parent_seq` — returns child (elicitation) entries linking back to the given sequence number
- `latest` — return only the single most recent matching entry
- `include` — comma-separated: `l3` (L3Fast/L3Deep), `excerpts` (stdout/stderr), `elicitation` (prompt/rule source). Default omits these large fields.

Script-hash events carry two additional fields:

- `script_hash` — the approved content hash (`sha256:…`)
- `script_path` — the resolved script path at the time of the event

The `policy_rule_id` distinguishes the event type: `script-hash-approved`
(initial approval), `script-hash-matched` (subsequent bypass),
`script-hash-pending` (escalation surfaced to user), `script-hash-revoked`
(approval revoked), `script-hash-error` (detection or hashing failure).

## Important rules

1. Always use `doit_execute` instead of running commands directly.
2. Respect hardcoded denials — do not retry.
3. For config rule denials, the user will be prompted automatically.
4. Use `doit_dry_run` to check policy before executing if uncertain.
5. Use `doit_list_capabilities` to discover available capabilities.
6. Every invocation is audited. Work transparently.
