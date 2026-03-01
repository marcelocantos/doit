# doit v2: Agentic Gatekeeper

## Status

Draft — design discussion, not yet approved for implementation.

## Problem

doit v1 is a static rule-based command broker. It maintains a fixed set of
capabilities, each with a hardcoded tier and optional flag-rejection rules.
This approach has fundamental scaling problems:

1. **Combinatorial shell complexity.** Every new shell construct (`for`,
   `while`, `if`, `$(...)`, `<(...)`, heredocs, process substitution) requires
   new parsing logic. Composition makes it worse — a `for` loop containing a
   pipe containing a subshell is beyond what static rules can meaningfully
   analyse.

2. **Binary allow/deny.** Rules either block a command or don't. There is no
   notion of confidence, context, or accumulated trust. The `--retry` escape
   hatch is a blunt instrument.

3. **No learning.** The same command pattern gets evaluated the same way on the
   millionth invocation as the first. There is no mechanism to build trust over
   time.

4. **Human bottleneck.** In practice, agents wait for human approval — sometimes
   for tens of minutes — because the human is focused elsewhere. A system that
   could autonomously approve routine operations would dramatically improve
   throughput.

## Core Insight

The worker agent that generates commands has **goal pressure** — it is trying to
accomplish a task, which biases it toward permissiveness. A separate gatekeeper
agent, with no task goal in its context, can evaluate commands with **safety as
its sole motivation**. This is the same principle behind code review: the
reviewer isn't invested in shipping the feature, so they catch things the author
overlooks.

## Design

### Architecture Overview

```
Worker Agent
    │
    │  request: command + justification + safety argument
    │
    ▼
doit CLI (thin client)
    │
    │  unix socket IPC
    │
    ▼
doit daemon (persistent process)
    ├── Level 1: Fast-path rules (deterministic, <1ms)
    ├── Level 2: Learned policy lookup (past decisions, <10ms)
    └── Level 3: LLM gatekeeper (novel/complex cases, ~1-5s)
          │
          ▼
      Allow / Deny / Escalate to User
```

### Structured Requests

The worker agent does not simply submit a bare command string. Each request
includes:

- **Command**: the shell command or pipeline to execute.
- **Justification**: why this command is needed ("I need to verify the tests
  pass before committing").
- **Safety argument**: why the worker believes this is safe ("this is a
  read-only operation on the local repository, no side effects").

This has two benefits. First, it forces the worker agent to reason about safety
explicitly — the act of constructing the justification may catch problems before
they reach the gatekeeper. Second, it gives the gatekeeper rich signal for
evaluation. A bare `rm -rf build/` is ambiguous; the same command with "cleaning
build artifacts before rebuild, this is a generated directory that `make`
recreates" is obviously fine.

Over time, the learned policy captures justification patterns too. "Commands
that clean well-known build directories are always fine" becomes a distillable
rule.

### Daemon Architecture

The doit binary serves dual roles:

- **CLI mode**: when invoked by the worker agent, it acts as a thin client. It
  serialises the request (command + justification + safety argument), sends it
  over a unix socket, and receives back allow/deny/escalate.
- **Daemon mode**: a persistent background process that maintains model context,
  loaded policy, and project knowledge in memory.

On first invocation, the CLI detects that no daemon is listening on the socket
and respawns itself as a daemon. Subsequent invocations connect to the running
daemon. The daemon idle-timeouts after a configurable period of inactivity to
free resources.

This architecture eliminates LLM cold-start costs. The daemon maintains a warm
context with the project's structure, the policy state, and recent decision
history. Command evaluation latency is dominated by LLM thinking time (for level
3) rather than connection setup.

### Three-Level Evaluation

Every command request flows through three levels. If any level reaches a
definitive decision, subsequent levels are skipped.

#### Level 1: Fast-Path Rules (deterministic)

Deterministic rules that handle the high-volume, unambiguous cases. These are
equivalent to the current v1 rules but generated and maintained by the system
rather than hand-written. Each rule consists of:

- **Pattern**: what commands it matches.
- **Decision**: allow or deny.
- **Justification**: why this rule exists.
- **Test suite**: example commands that should and should not match, serving as
  both validation and documentation.

All level 1 rules require **human approval** before activation. The gatekeeper
proposes rules; the human reviews and approves them. Rules may be expressed as
configuration (YAML/JSON patterns) or as executable logic (TypeScript or similar)
for cases requiring more expressive matching.

Examples of rules that should reach level 1 quickly:
- Pure read-only commands (`grep`, `cat`, `head`, `tail`, `ls`, `find`, `wc`,
  `sort`, `tree`) are safe regardless of arguments.
- Pipelines composed entirely of level-1-safe commands inherit that safety.
- `rm -rf /` and variants are permanently denied.

#### Level 2: Learned Policy (structured memory)

A store of past decisions that the gatekeeper consults before invoking the LLM.
Each entry records:

- **Pattern**: a description of the command shape (more semantic than syntactic).
- **Decision**: allow, deny, or escalate.
- **Reasoning**: why this decision was made.
- **Confidence**: how certain the gatekeeper is.
- **Provenance**: whether this was an autonomous gatekeeper decision or a human
  override.
- **Review history**: timestamps of past reviews, approval count.
- **Next review**: when this entry should be re-examined.

The learned policy is stored in a human-readable format (YAML or similar),
editable by the user, and naturally loadable into the gatekeeper's context.

New entries in the learned policy also require **human review** — the gatekeeper
flags them for audit, and they don't take effect until approved.

Examples of patterns that live at level 2:
- "`go test` with any flags in a Go project" → allow (repo-specific context).
- "`git rm` of files in `build/` or `dist/`" → allow (conditional on path).
- "`git rm` of authored source files" → escalate to user.
- "`git push --force`" → deny.

#### Level 3: Full LLM Reasoning (novel cases)

Commands that don't match any level 1 rule or level 2 policy entry are evaluated
by the LLM gatekeeper with full reasoning. The gatekeeper has access to:

- The command and the worker's justification/safety argument.
- The project structure and relevant files (read-only access to the repo).
- The full policy state (levels 1 and 2).
- Recent decision history.

The gatekeeper can:
- **Allow**: the command proceeds.
- **Deny**: the command is blocked, with an explanation returned to the worker.
- **Escalate**: the command requires human approval. The gatekeeper includes its
  own assessment to help the human decide.

Cases that may permanently require level 3:
- Ad-hoc multiline scripts generated by the worker agent.
- Complex `bash -c` invocations.
- `curl | sh` patterns.
- Any command where the risk surface is too dynamic for a static rule.

### Policy Migration

Policies migrate downward through the levels as patterns stabilise:

```
Level 3 (LLM)  →  Level 2 (learned)  →  Level 1 (deterministic)
   novel              stabilising             codified
```

The migration criteria are not purely frequency-based. The gatekeeper analyses
the **structure** of its decision history:

- **Uniformity**: if every invocation of a command pattern has been approved with
  the same reasoning, that is a strong signal for promotion. High uniformity +
  high frequency = fast migration.
- **Variation within a theme**: `go test ./...`, `go test -v ./pkg/...`,
  `go test -run TestFoo` look syntactically different but are semantically "run
  Go tests with various filters." Semantic similarity matters more than syntactic
  similarity.
- **Conditional branching**: when the same command name has both approvals and
  denials, the gatekeeper identifies the discriminating features. "`git push`
  was approved 20 times but denied 3 times — the denials all involved
  `--force`." That yields a conditional rule, not a simple one.
- **Novelty detection**: a command syntactically similar to approved patterns but
  with a novel element still gets scrutiny. `grep -r password .` looks like a
  grep, but the intent may warrant flagging.

The gatekeeper should very quickly conclude that reading files is safe, that
piping safe commands through `sed`/`awk`/`grep`/`tail`/`head` is safe. It should
take considerably longer to decide that `git rm` operations are safe, and arrive
at a nuanced conditional policy (safe for generated files, escalate for authored
source). Complex ad-hoc scripts may never leave level 3.

#### Compositionality

A pipeline where every segment is individually level-1-safe is itself safe. This
handles `grep foo ¦ sort ¦ head -20` immediately without evaluating the pipeline
as a whole. Mixed pipelines — `dangerous_command ¦ grep error` — require
consideration: the pipe constrains the output but does not make the source
command safer.

### Spaced Repetition Review

No approval is permanent. Every rule and policy entry has a review schedule
following a spaced repetition algorithm:

1. A freshly approved rule is reviewed after **1 week**.
2. If confirmed, next review in **2 weeks**.
3. Then **1 month**, **2 months**, **4 months**, etc.
4. The interval never reaches infinity — even deeply trusted rules eventually
   come back for review.

If a rule is modified or the project context changes significantly (e.g. the
repo starts handling credentials), the gatekeeper's periodic audit can flag rules
for **early re-review**, resetting their interval.

Rules that have been approved, reviewed, and reconfirmed through many cycles
become part of the system's DNA — high-confidence, long-interval, but still
periodically revisited.

### Auditing

The gatekeeper periodically audits its own rule set and learned policy. This is
distinct from individual rule reviews — it is a holistic examination:

- Are there rules that made sense in isolation but are dangerous in combination?
- Have rules drifted from current project reality?
- Are there patterns in level 3 decisions that should have been promoted but
  weren't?
- Are there rules that seem inconsistent with each other?

Anything the gatekeeper deems questionable is brought to the user's attention.

### Gatekeeper Capabilities

The gatekeeper needs its own capabilities to validate claims from the worker
agent. At minimum:

- **Read-only repo access**: verify claims like "this is a generated directory"
  or "this file is not authored source" by inspecting the filesystem, git
  status, `.gitignore`, build configuration, etc.

More expansive gatekeeper capabilities (e.g. running `git status`, checking file
metadata) may be warranted. These could themselves be subject to policy — the
gatekeeper approving its own actions through a separate policy instance. This
risks infinite regress, but there is a natural termination condition: the
gatekeeper's own action set is small and well-defined (mostly read-only), so a
hardcoded allowlist for gatekeeper-internal operations is a reasonable bootstrap.

This topic warrants further deliberation before implementation.

### Global vs Repo-Level Policy

Policy exists at two scopes:

- **Global policy**: universal truths. "Never `rm -rf /`." "Read-only file
  operations are safe." These apply everywhere.
- **Repo policy**: project-specific context. "This is a Go project, `go test` is
  safe here." "The `build/` directory is generated." These live alongside the
  repo or in a per-repo section of the policy store.

A repo can **tighten** global policy or add repo-specific context. A repo
**cannot loosen** global policy by default — a malicious or compromised
repository should not be able to declare "`git push --force` is fine here."

The gatekeeper discovers repo-level context naturally by reading the project
structure, Makefile, `.gitignore`, etc.

### User Interface

There are two channels for human interaction, serving different purposes:

#### In-Band (through the agent conversation)

Hard denials are communicated in-band so the worker agent knows to change
approach. The worker receives a structured response: denied, with the
gatekeeper's reasoning, so it can adjust its strategy.

#### Out-of-Band (direct to user)

Escalations and policy reviews reach the user directly, bypassing the worker
agent. This avoids relying on the untrusted worker to faithfully relay the
gatekeeper's concerns. Possible channels:

- macOS notifications with approve/deny actions.
- A menu bar widget or lightweight TUI served by the daemon.
- A persistent approval queue (web UI or native).
- Periodic digests for non-urgent items (rule reviews, audit findings).

The out-of-band channel is also the natural home for the spaced-repetition rule
review workflow — a digest that appears when convenient rather than interrupting
flow.

The exact form of the out-of-band UI is a design decision to be resolved during
implementation. The daemon architecture provides a natural home for serving it.

## Relationship to doit v1

This design subsumes the current v1 architecture:

- **Capabilities** remain as the unit of execution, but the per-capability tier
  system and flag-rejection rules are replaced by the three-level policy engine.
- **The audit log** remains and is extended with richer fields (justification,
  safety argument, gatekeeper reasoning, decision level, confidence).
- **Unicode operators** and the pipeline execution engine remain — the daemon
  still needs to run commands, and streaming execution with `io.Pipe` is sound.
- **`--pipe` is eliminated.** All invocations go through `ParseCommand`. A
  single-capability, no-operator command is just a degenerate case.
- **`--retry` is eliminated.** The learning system replaces the manual bypass
  mechanism.

The transition could be incremental: start by adding the daemon and structured
requests while keeping the static rules as the initial level 1, then layer in
the LLM gatekeeper and learning system.

## Open Questions

1. **LLM selection for the gatekeeper.** What model? The gatekeeper needs good
   reasoning but is called frequently. A fast, capable model (Haiku-class for
   routine decisions, Sonnet-class for complex ones) with automatic routing may
   be appropriate.

2. **Cold start policy.** Should doit ship with a default learned policy
   (bootstrapped from common patterns) so day-one UX isn't agonizing? Or is the
   strict-start, learn-fast approach acceptable given that latency is already
   better than waiting for human approval?

3. **Gatekeeper self-trust.** How far should the gatekeeper's own capabilities
   extend? Read-only repo access is clear. Anything beyond that needs the
   recursive trust question resolved.

4. **Rule language.** For level 1 rules that need expressive logic, what is the
   right language? TypeScript is expressive and widely known. A DSL could be
   simpler but less flexible. Starlark was already considered for doit
   extensibility.

5. **Multi-user / multi-agent.** If multiple worker agents are active
   concurrently, does the gatekeeper maintain separate trust profiles per agent,
   or is trust global?

6. **Cost model.** LLM calls cost money. The three-level system minimises this
   over time, but early usage will be LLM-heavy. Is there a budget mechanism, or
   is cost purely managed by migration speed?

7. **Offline fallback.** What happens when the LLM is unavailable? The daemon
   could fall back to levels 1 and 2 only, denying anything that would require
   level 3. This is conservative but safe.
