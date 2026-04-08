# doit — Agent Usage Guide

doit is an MCP server that mediates command execution through a three-level
policy engine. All commands are executed via MCP tools — there is no CLI
interface for command execution.

## MCP tools

| Tool | Purpose |
|---|---|
| `doit_execute` | Execute a command through the policy engine |
| `doit_dry_run` | Evaluate a command without executing (policy check only) |
| `doit_policy_status` | Show policy engine state (enabled levels, rule counts) |
| `doit_approve` | Validate an approval token for escalated commands |
| `doit_list_capabilities` | List registered capabilities and their tiers |
| `doit_audit_verify` | Verify audit log hash chain integrity |
| `doit_audit_tail` | Show recent audit log entries |

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
