# doit

An agentic gatekeeper for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).
doit is an MCP server that mediates all command execution through a three-level
policy engine with tiered safety controls, Starlark rules, and an audited
execution trail.

## Why

Claude Code's `Bash` tool is powerful but blunt — any command can run with no
guardrails beyond the user clicking "allow". doit sits in between, providing:

- **Three-level policy engine** — L1 deterministic rules (Go + Starlark) →
  L2 learned patterns → L3 live LLM evaluation
- **Safety tiers** — each capability is classified as read, build, write, or
  dangerous. Dangerous operations (rm, chmod, git push) are disabled by default.
- **Interactive policy decisions** — when the policy engine escalates, the user
  is prompted directly via MCP elicitation with Allow once / Allow always /
  Deny / Deny always options
- **Rule promotion** — "Always" decisions can generate permanent Starlark rules
  at varying generality levels
- **Per-project config** — projects can tighten global policy via
  `.doit/config.yaml` (can add rules, cannot loosen)
- **Tamper-evident audit log** — every invocation is recorded in a SHA-256
  hash-chained log

## Install

### Homebrew

```sh
brew install marcelocantos/tap/doit
```

### From source

Requires Go 1.25+.

```sh
git clone https://github.com/marcelocantos/doit.git
cd doit
make install
```

## Quick start

Register doit as an MCP server in Claude Code:

```sh
claude mcp add --scope user --transport stdio doit -- doit
```

Restart your Claude Code session. doit's MCP tools will be available
automatically.

## MCP tools

| Tool | Purpose |
|---|---|
| `doit_execute` | Execute a command through the policy engine |
| `doit_dry_run` | Evaluate a command without executing (policy check only) |
| `doit_policy_status` | Show policy engine state |
| `doit_approve` | Validate an approval token for escalated commands |
| `doit_list_capabilities` | List capabilities and their safety tiers |
| `doit_audit_verify` | Verify audit log hash chain integrity |
| `doit_audit_tail` | Show recent audit log entries |

Commands are passed as shell strings and executed via `sh -c`, so shell
features (pipes, redirects, `&&`, `||`) work naturally.

## Safety tiers

| Tier | Examples | Default |
|---|---|---|
| read | cat, grep, head, ls, tail, wc, find, git status | enabled |
| build | make, go build | enabled |
| write | cp, mv, mkdir, tee, git add/commit | enabled |
| dangerous | rm, chmod, git push/reset/clean | **disabled** |

Tiers are configured in `~/.config/doit/config.yaml`:

```yaml
tiers:
  read: true
  build: true
  write: true
  dangerous: false
```

## Rules

### Default rules

| Capability | Blocked | Why |
|---|---|---|
| `make` | `-j` | Parallel make can mask errors |
| `git push` | `--force`, `-f`, `--force-with-lease` | Force-push destroys remote history |
| `git reset` | `--hard` | Discards uncommitted changes |
| `git checkout` | `.` | Silently discards all changes |
| `rm` | `-rf /`, `-rf .`, `-rf ~` | Catastrophic deletion (hardcoded, cannot be bypassed) |

### Rule types

- **Hardcoded rules** block permanently catastrophic operations. Cannot be
  bypassed.
- **Config rules** block risky-but-sometimes-needed operations. The user is
  prompted via elicitation to allow or deny.
- **Starlark rules** — custom L1 rules in `.star` files with embedded test
  cases. Can be generated via the rule promotion flow.

### Custom rules

Override default rules in `~/.config/doit/config.yaml`:

```yaml
rules:
  make:
    reject_flags: ["-j"]
  git:
    subcommands:
      push:
        reject_flags: ["--force", "-f", "--force-with-lease"]
      reset:
        reject_flags: ["--hard"]
```

### Per-project policy

Projects can add a `.doit/config.yaml` that tightens global policy — it can
add rules and disable tiers but cannot remove global rules or enable disabled
tiers.

## Audit log

Every invocation is recorded in a hash-chained append-only log at
`~/.local/share/doit/audit.jsonl`. Use `doit_audit_verify` to check integrity
and `doit_audit_tail` to view recent entries.

## Configuration

Config file: `~/.config/doit/config.yaml`

```yaml
tiers:
  read: true
  build: true
  write: true
  dangerous: false

audit:
  path: ~/.local/share/doit/audit.jsonl
  max_size_mb: 100

policy:
  level1_enabled: true
  level2_enabled: true
  level3_enabled: false
  starlark_rules_dir: ""

rules:
  make:
    reject_flags: ["-j"]
  git:
    subcommands:
      push:
        reject_flags: ["--force", "-f", "--force-with-lease"]
      reset:
        reject_flags: ["--hard"]
```

All fields are optional — doit uses sensible defaults when no config file exists.

## Agent integration

If you use an agentic coding tool (Claude Code, Cursor, Copilot, etc.), see
[`agents-guide.md`](agents-guide.md) for a concise MCP tool reference.

## License

Apache 2.0 — see [LICENSE](LICENSE).
