# doit — Development Guide

Agentic gatekeeper for Claude Code. Go project. External dependencies: `gopkg.in/yaml.v3`, `go.starlark.net`, `golang.org/x/sys`.

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
cmd/doit/main.go          MCP server entry point (stdio transport)
engine/                   public API: policy chain, MCP-facing execution, sessions
mcptools/                 MCP tool registration and integration tests
internal/cap/             Capability interface, Tier enum, Registry
internal/cap/builtin/     one file per capability, register.go has RegisterAll()
internal/audit/           hash-chained append-only JSON lines log
internal/config/          YAML config loader (~/.config/doit/config.yaml, per-project policy)
internal/context/         project context discovery and allowlisted repo reads
internal/rules/           hardcoded + config-driven argument validation
internal/starlark/        Starlark rule loader, evaluator, and generator
internal/policy/          three-level policy engine (L1/L2/L3), session prefix, self-audit, promotion
internal/llm/             one-shot `claude -p` client used by L3
agents-guide.md           agent usage guide
```

## Key design decisions

- **MCP-first architecture**: `doit` exposes an MCP server (stdio transport) as the primary agent interface. Commands are executed via `sh -c` — the shell handles all composition (`&&`, `|`, `;`, redirects). doit no longer parses the command string into segments at the engine level; segment analysis, if any, is an internal detail of each policy layer.
- **Three-level policy engine**: L1 (deterministic Starlark rules) → L2 (learned patterns) → L3 (live LLM). L3 runs as a two-tier cascade — a fast sonnet triage falls through to an opus deep-reasoning step only on genuinely ambiguous cases. Each L3 call is a one-shot `claude -p` invocation (stateless; no persistent session). L3 can promote decisions to L1 by generating Starlark code for human review.
- **Starlark for L1 rules**: sandboxed, deterministic, Python-like (LLMs write it well), Go-embeddable. Lives in `internal/starlark/`.
- **Per-project policy config**: projects can override global policy via a local config file (checked into VCS).
- **Safety tiers**: read < build < write < dangerous. Each capability has a fixed tier. Git uses per-subcommand tiers at runtime (`internal/cap/builtin/git.go`).
- **Rules**: hardcoded (permanent, e.g. `rm -rf /`) vs config (bypassable with `--retry`). Wired through `Registry.CheckRules()`.
- **Audit log**: SHA-256 hash chain with sequence numbers and genesis hash.
- **Seamless exit codes**: `ExitError` in `builtin/external.go` propagates exit codes without extra stderr noise.

## Adding a capability

1. Create `internal/cap/builtin/<name>.go` implementing the `cap.Capability` interface.
2. Register it in `internal/cap/builtin/register.go`.
3. Set the appropriate tier (read/build/write/dangerous).
4. Add argument validation in `Validate()` for any dangerous flag patterns.

## TODO

Open work items are tracked in `docs/todo.md`.

