# Stability

doit follows [semantic versioning](https://semver.org/). Once 1.0 ships,
breaking changes to the public CLI interface, configuration format, audit log
format, or pipeline syntax will require a major version bump. The pre-1.0
period exists to get these right.

## Interaction surface catalogue

### CLI subcommands and flags

| Surface | Signature | Stability |
|---|---|---|
| Direct execution | `doit <capability> [args...]` | Stable |
| Pipeline | `doit --pipe [--retry] <args...>` | Stable |
| Config rule bypass | `doit --retry <cap> [args...]` | Stable |
| List capabilities | `doit --list [--tier <tier>]` | Stable |
| Help | `doit --help [<capability>]` | Stable |
| Agent guide | `doit --help-agent` | Stable |
| Audit operations | `doit --audit <verify\|show\|tail>` | Stable |
| Version | `doit --version` | Stable |

### Pipeline operators

| Operator | Unicode | Meaning | Stability |
|---|---|---|---|
| `¦` | U+00A6 | Pipe (stdout to stdin) | Stable |
| `›` | U+203A | Redirect stdout to file | Stable |
| `‹` | U+2039 | Redirect stdin from file | Stable |
| `＆＆` | U+FF06 x2 | And-then (run next if previous succeeded) | Stable |
| `‖` | U+2016 | Or-else (run next if previous failed) | Stable |
| `；` | U+FF1B | Sequential (run next regardless) | Stable |

### Configuration schema (`~/.config/doit/config.yaml`)

| Field | Type | Default | Stability |
|---|---|---|---|
| `tiers.read` | bool | `true` | Stable |
| `tiers.build` | bool | `true` | Stable |
| `tiers.write` | bool | `true` | Stable |
| `tiers.dangerous` | bool | `false` | Stable |
| `audit.path` | string | `~/.local/share/doit/audit.jsonl` | Stable |
| `audit.max_size_mb` | int | `100` | Fluid — field exists but is not enforced |
| `rules.<cap>.reject_flags` | []string | per-capability | Stable |
| `rules.<cap>.subcommands.<sub>.reject_flags` | []string | per-subcommand | Stable |

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

### Built-in capabilities

| Name | Tier | Description | Stability |
|---|---|---|---|
| cat | read | concatenate and display files | Stable |
| chmod | dangerous | change file permissions | Stable |
| cp | write | copy files and directories | Stable |
| find | read | search for files (blocks -exec/-delete) | Stable |
| git | varies | version control (per-subcommand tiers) | Stable |
| go | varies | Go toolchain (run/generate/install/tool/get are dangerous) | Stable |
| grep | read | search file contents | Stable |
| head | read | output first part of files | Stable |
| ls | read | list directory contents | Stable |
| make | build | build targets (blocks -f/-C) | Stable |
| mkdir | write | create directories | Stable |
| mv | write | move or rename files | Stable |
| rm | dangerous | remove files (requires args) | Stable |
| sort | read | sort lines of text | Stable |
| tail | read | output last part of files | Stable |
| tee | write | duplicate stdin to stdout and files | Stable |
| tr | read | translate or delete characters | Stable |
| uniq | read | report or omit repeated lines | Stable |
| wc | read | word, line, character, byte count | Stable |

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

- **`audit.max_size_mb` not enforced**: The config field exists but log rotation
  is not implemented. Must either implement it or remove the field before 1.0.
- **Test coverage**: 3 of 8 packages have tests. The pipeline parser/executor,
  audit system, and rules system are tested. The capability registry, built-in
  capabilities, CLI handlers, and config loader have zero coverage. Critical
  paths (tier checking, rule enforcement, exit code propagation) should be
  tested before 1.0.
- **Per-project config**: Currently global only (`~/.config/doit/config.yaml`).
  Per-project overrides (e.g., `.doit.yaml` in the repo root) would let
  projects ship their own safety rules. Needs design before 1.0 to avoid a
  breaking config change later.
- **`doit --audit tail` hardcoded to 20 entries**: Should accept an optional
  count argument before locking the CLI surface.

## Out of scope for 1.0

- **Embedded scripting (Starlark)**: User-defined capabilities without
  recompilation. Planned but not for the initial stable release.
- **Config-defined capabilities**: Declaring new capabilities in YAML. Deferred
  to post-1.0.
- **Append redirect (`››`)**: Not yet needed. Can be added without breaking
  changes.
- **CI pipeline**: Not a stability concern for the binary itself.
