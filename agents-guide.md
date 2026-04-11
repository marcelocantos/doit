# doit — Agent Usage Guide

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

Use `doit_check_config` to verify that Bash is denied and doit is registered.

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

### Audit log

| Tool | Purpose |
|---|---|
| `doit_audit_verify` | Verify audit log hash chain integrity |
| `doit_audit_tail` | Show recent audit log entries |

### Deployment and context

| Tool | Purpose |
|---|---|
| `doit_check_config` | Verify deployment config (Bash denied, doit registered) |
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

## Audit log

All invocations are logged to a tamper-evident audit trail (SHA-256 hash
chain). Use `doit_audit_verify` to check integrity and `doit_audit_tail`
to view recent entries.

## Important rules

1. Always use `doit_execute` instead of running commands directly.
2. Respect hardcoded denials — do not retry.
3. For config rule denials, the user will be prompted automatically.
4. Use `doit_dry_run` to check policy before executing if uncertain.
5. Use `doit_list_capabilities` to discover available capabilities.
6. Every invocation is audited. Work transparently.
