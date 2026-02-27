# doit — Development Guide

Capability broker for Claude Code. Go project, single external dependency (`gopkg.in/yaml.v3`).

## Build

```sh
make          # build to bin/doit (parallel by default via MAKEFLAGS)
make test     # go test ./...
make vet      # go vet ./...
make smoke    # build + quick integration tests
make install  # copy to $GOPATH/bin
make clean    # rm bin/ and generated files
```

Never pass `-j` to make — the Makefile sets `MAKEFLAGS` internally.

## Architecture

```
cmd/doit/main.go          entry point, --prefixed subcommand dispatch
internal/cap/             Capability interface, Tier enum, Registry
internal/cap/builtin/     one file per capability, register.go has RegisterAll()
internal/pipeline/        two-level parser (Command → Pipeline → Segment), executor
internal/audit/           hash-chained append-only JSON lines log
internal/config/          YAML config loader (~/.config/doit/config.yaml)
internal/cli/             subcommand handlers (run, pipe, list, audit, help)
internal/rules/           hardcoded + config-driven argument validation
agents-guide.md           agent usage guide (source of truth, copied to internal/cli/ at build)
```

## Key design decisions

- **Unicode operators** (`¦`, `›`, `‹`, `＆＆`, `‖`, `；`) replace shell metacharacters so they survive unquoted in bash/zsh/fish. Defined in `internal/pipeline/types.go`.
- **`--` prefix** for doit's own subcommands (`--pipe`, `--list`, `--help`, etc.) so no capability names are reserved.
- **Safety tiers**: read < build < write < dangerous. Each capability has a fixed tier. Git uses per-subcommand tiers at runtime (`internal/cap/builtin/git.go`).
- **Rules**: hardcoded (permanent, e.g. `rm -rf /`) vs config (bypassable with `--retry`). Wired through `Registry.CheckRules()`.
- **Audit log**: SHA-256 hash chain with sequence numbers and genesis hash.
- **Seamless exit codes**: `ExitError` in `builtin/external.go` propagates exit codes without extra stderr noise.

## Type hierarchy

```
Command → []CommandStep (connected by ＆＆/‖/；)
  CommandStep → Pipeline + Operator
    Pipeline → []Segment + RedirectIn/RedirectOut (connected by ¦)
      Segment → CapName + Args
```

`ParseCommand` splits on compound operators first, delegates to `Parse` per section.
`ExecuteCommand` runs pipelines sequentially with operator-based flow control.

## Adding a capability

1. Create `internal/cap/builtin/<name>.go` implementing the `cap.Capability` interface.
2. Register it in `internal/cap/builtin/register.go`.
3. Set the appropriate tier (read/build/write/dangerous).
4. Add argument validation in `Validate()` for any dangerous flag patterns.

## Generated files

`internal/cli/help_agent.md` is generated from `agents-guide.md` during build.
It is gitignored — do not edit it directly.
