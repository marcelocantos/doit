# doit

A capability broker for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).
Add `Bash(doit:*)` to your allowed tools and every shell command flows through
a single audited binary with tiered safety controls.

## Why

Claude Code's `Bash` tool is powerful but blunt — any command can run with no
guardrails beyond the user clicking "allow". doit sits in between, providing:

- **Safety tiers** — each capability is classified as read, build, write, or
  dangerous. Dangerous operations (rm, chmod, git push) are disabled by default.
- **Argument-level rules** — configurable rules block footguns like `make -j`,
  `git push --force`, and `git checkout .` before they execute.
- **Tamper-evident audit log** — every invocation is recorded in a SHA-256
  hash-chained log that can be verified for integrity.
- **Pipeline syntax** — Unicode operators (`¦`, `›`, `‹`, `＆＆`, `‖`, `；`)
  replace shell metacharacters, letting doit validate every segment of a
  pipeline before anything runs.

## Install

Requires Go 1.21+.

```sh
git clone https://github.com/marcelocantos/doit.git
cd doit
make install    # builds and copies to $GOPATH/bin
```

Or build without installing:

```sh
make            # binary at bin/doit
```

## Quick start

1. **Configure Claude Code** to route all shell commands through doit. In your
   project's `.claude/settings.json` (or the global equivalent):

   ```json
   {
     "permissions": {
       "allow": ["Bash(doit:*)"],
       "deny": ["Bash"]
     }
   }
   ```

2. **Run commands** through doit:

   ```sh
   doit ls -la
   doit git status
   doit grep -r TODO src/
   ```

3. **Run pipelines** with the `¦` operator:

   ```sh
   doit --pipe grep -r TODO src/ ¦ sort ¦ uniq -c ¦ head -20
   ```

4. **Check available capabilities** and their tiers:

   ```sh
   doit --list
   ```

## Usage

### Direct execution

```
doit <capability> [args...]
```

### Pipelines

```
doit --pipe <cmd> [args...] ¦ <cmd> [args...] ¦ ...
```

### Redirects

Use `›` to redirect stdout to a file and `‹` to redirect stdin from a file:

```
doit --pipe sort ‹ input.txt ¦ uniq -c › results.txt
```

### Compound commands

Chain pipelines with conditional operators:

| Operator | Meaning | Equivalent |
|---|---|---|
| `＆＆` | and-then (run next if previous succeeded) | `&&` |
| `‖` | or-else (run next if previous failed) | `\|\|` |
| `；` | sequential (run next regardless) | `;` |

```
doit --pipe make build ＆＆ git add -A ＆＆ git commit -m "build ok"
```

### Listing capabilities

```
doit --list                  # all capabilities
doit --list --tier read      # only read-tier capabilities
```

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
  dangerous: false    # enable at your own risk
```

## Rules

Beyond tiers, doit enforces argument-level rules that block specific flag
combinations.

### Default rules

| Capability | Blocked | Why |
|---|---|---|
| `make` | `-j` | Parallel make can mask errors |
| `git push` | `--force`, `-f`, `--force-with-lease` | Force-push destroys remote history |
| `git reset` | `--hard` | Discards uncommitted changes |
| `git checkout` | `.` | Silently discards all changes |
| `rm` | `-rf /`, `-rf .`, `-rf ~` | Catastrophic deletion (hardcoded, cannot be bypassed) |

### Rule types

- **Hardcoded rules** block permanently catastrophic operations. They cannot be
  bypassed. Don't retry.
- **Config rules** block risky-but-sometimes-needed operations. They can be
  bypassed with `--retry` after explicit user approval:

  ```sh
  doit --retry make -j4 all
  doit --retry git push --force origin master
  ```

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

## Audit log

Every invocation is recorded in a hash-chained append-only log at
`~/.local/share/doit/audit.jsonl`.

```sh
doit --audit show       # view recent entries
doit --audit verify     # check hash chain integrity
```

Each entry records the command, capabilities used, tiers, exit code, duration,
working directory, and whether `--retry` was used. The SHA-256 hash chain makes
tampering detectable.

## Agent integration

If you use an agentic coding tool (Claude Code, Cursor, Copilot, etc.), see
[`agents-guide.md`](agents-guide.md) for a concise reference to include in your
project context, or run `doit --help-agent` for the full guide.

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

## License

Apache 2.0 — see [LICENSE](LICENSE).
