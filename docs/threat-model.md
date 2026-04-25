# doit Threat Model

*Pre-1.0 safety contract. Describes what doit defends against, what it does not,
and what the defences depend on.*

---

## Introduction

doit is an MCP server that interposes between a Claude Code agent and the OS
shell. Its core design assumption is that every command an agent runs flows
through `doit_execute`, where the three-level policy engine (L1 deterministic
→ L2 learned → L3 LLM) evaluates it and the audit log records it. When that
assumption holds, doit provides meaningful coverage. When it does not, all
controls are bypassed.

This document describes both cases honestly.

---

## Trust Boundaries

Four principals are involved in a doit-mediated execution:

1. **User** — the human who installed and configured doit. Trusted fully.
   Owns all configuration, approves policy decisions via MCP elicitation,
   and can override any bypassable rule.

2. **Agent** — the Claude Code instance (or equivalent) running in the user's
   shell. Trusted to route execution through `doit_execute` because the user
   configured it that way. The agent is *not* inherently trusted — it can
   be misled, hallucinate, or be manipulated via prompt injection. doit
   does not assume the agent is acting correctly.

3. **doit policy engine** — the go binary running as an MCP server. Trusted
   to enforce L1/L2 rules faithfully. Trusted to invoke the OS faithfully
   once a command is approved. **Not** assumed to be tamper-proof at the
   filesystem level — an attacker with user-level write access can modify
   config, Starlark rules, or the L2 policy store.

4. **L3 evaluator** — the external LLM invoked by `claude -p` when L1 and L2
   do not reach a decision. This is the weakest link in the chain. It is an
   LLM: it can be manipulated via prompt injection in the command string,
   the justification, or the safety argument. Its decisions are bypassable
   by the user and are not authoritative — they only take effect when the
   user confirms via elicitation. Nonetheless, a consistently misleading L3
   evaluator can produce systematically wrong L2 learned decisions if the
   user approves them without scrutiny.

   The two-tier L3 cascade (fast sonnet → deep opus) reduces this risk
   slightly — the deep model cross-checks the fast model — but does not
   eliminate it. Both models are subject to prompt injection.

---

## What doit Defends Against

When doit is the sole execution path (see [Configuration Assumptions](#configuration-assumptions)):

### 1. Accidental catastrophic commands

L1 hardcoded rules permanently block a small set of irreversible operations
that have no legitimate use in an automated context:

- `rm -r /`, `rm -r .`, `rm -r ..`, `rm -r ~` (recursive removal of root,
  cwd, parent, or home).

These rules cannot be bypassed with `--retry` or user elicitation. There is
exactly one hardcoded rule today; others could be added.

### 2. Common risky patterns (default config rules)

The default configuration blocks patterns that are safe in human hands but
dangerous when an agent runs them without context:

- `git push --force` / `--force-with-lease` — destroys remote history
- `git reset --hard` — discards uncommitted changes without warning
- `git checkout .` — silently discards all changes
- `make -j` — parallel make can mask build errors
- `sleep N` where N exceeds 2 × `expected_duration_seconds` — anomaly flag

These are bypassable: the user is prompted via MCP elicitation and can choose
Allow once, Allow always, Deny, or Deny always. Config rules can also be
removed from `~/.config/doit/config.yaml`.

### 3. Dangerous-tier capabilities (disabled by default)

The `dangerous` tier is disabled by default and gates `rm`, `chmod`, and
the destructive git subcommands (`push --force`, `reset --hard`, `clean
-fd`, `stash drop`). An agent cannot invoke these without the user
explicitly enabling the `dangerous` tier in config, or the user approving
via elicitation when the capability is already enabled.

### 4. Unrecognised commands (policy escalation)

Commands whose first token does not match a registered capability, or whose
behaviour is ambiguous under L1 rules, escalate to L2 or L3. L3 evaluates
the full command string against safety heuristics, then presents the result
to the user for confirmation. This catches at least some novel or unexpected
commands — though L3 can be misled (see [Limits](#what-doit-does-not-defend-against)).

### 5. Shell-script opacity (content-hash approval gate)

A plain `bash foo.sh` invocation hides all the commands inside the script.
doit adds a tier-0 gate before L1/L2/L3: it hashes the script contents
(SHA-256), shows a preview to the user, and requires explicit approval. The
same hash is accepted on subsequent runs without re-prompting. Modifying the
script changes the hash and forces re-approval.

This is not a deep defence — approved scripts run without further policy
mediation — but it forces the user to consciously authorise each unique script
body.

### 6. Tamper-evident audit trail

Every `doit_execute` invocation is appended to a SHA-256 hash-chained log at
`~/.local/share/doit/audit.jsonl`. The chain is verifiable via
`doit_audit_verify`. The log records command, cwd, policy decision, rule ID,
justification, safety argument, exit code, and duration.

The audit log does not prevent anything from running. It detects after the
fact whether the log has been tampered with, and provides a record for human
review.

---

## What doit Does NOT Defend Against

### 1. Execution outside `doit_execute` — the fundamental bypass

**doit is trivially bypassed if the agent has any other execution path.**

The `deny: ["Bash"]` setting in Claude Code's permissions removes the built-in
Bash tool, forcing the agent to use `doit_execute` instead. But this blocks
only the Bash tool. Other execution paths exist and are not covered:

- **Other MCP servers with execution-adjacent primitives.** In 2025–2026,
  agents routinely have many MCP servers installed simultaneously. Any server
  that exposes file writes + chmod + a shell invocation, or that can call a
  language runtime (Python, Node, Ruby), or that wraps an external API capable
  of reaching local services, constitutes an execution path that bypasses doit
  entirely. doit is not in the loop for any of these. Examples of common
  patterns:
  - A filesystem MCP server that writes a file to `/tmp/exploit.sh`, then a
    language-runtime MCP server that executes it.
  - An HTTP client MCP server that calls `http://localhost:PORT` to reach a
    local service (triggering side effects the user did not authorise).
  - A "run code" MCP server (jupyter-style) that executes arbitrary Python
    or JavaScript.
  - An SSH MCP server that opens a shell on a remote machine.

  **doit has no visibility into any of these.** The user must audit their full
  MCP server inventory and decide which combinations are acceptable.

- **`doit_execute` used to shell out to another agent.** An agent could, in
  principle, call `doit_execute` with a command like `claude -p "<prompt to
  subagent>"`, causing a subagent to run outside doit's scope. doit would
  audit the outer `claude` invocation but would have no visibility into what
  the subagent does.

- **`Write` tool + chmod + direct execute via another MCP.** Even without a
  separate execution MCP, writing a file and making it executable are both
  potentially available through write-tier capabilities — if the user has
  enabled the `dangerous` tier (chmod), an agent can stage and execute
  arbitrary code.

- **`doit_execute` with `bash -c "…"`** executing inline commands. Inline
  shell strings pass through L1/L2/L3 evaluation as opaque text. L1 Starlark
  rules and config rules inspect the first token of the command; they do not
  parse compound inline strings deeply. L3 evaluates the full string, but is
  subject to prompt injection. This is a known gap documented in
  [STABILITY.md](../STABILITY.md) under script-hash detection scope.

### 2. Prompt injection into L3

The L3 evaluator receives the command string, cwd, justification, and safety
argument verbatim in its prompt. An adversarially crafted command or
justification can attempt to manipulate the LLM into issuing an "allow"
decision. The L3 result is still subject to user confirmation via elicitation
in most cases — but if the user has established a broad L2 "allow always"
pattern that matches the injected command, it may bypass L3 entirely.

Prompt injection into L3 does not guarantee a bypass (the user still sees the
elicitation), but it can produce misleading reasoning that influences the
user's decision.

### 3. Attacks on the policy store itself

L1 Starlark rules live in files on disk. L2 learned decisions live in a YAML
file (`~/.local/share/doit/policy.json` by default). An attacker with
user-level write access can:

- Modify or delete Starlark `.star` files to remove L1 rules.
- Inject a permissive L2 entry directly into the policy store.
- Replace the doit binary with a version that omits checks.
- Truncate or forge the audit log (the hash chain detects *subsequent* reads
  but cannot prevent writes by a process with file access).

doit does not attempt to prevent these attacks. It assumes the user's account
and filesystem are not already compromised. If they are, the attacker has
user-level access and can bypass doit without any special knowledge.

### 4. Supply-chain attacks on the doit binary

doit is distributed via Homebrew tap. A compromised tap, a compromised build
pipeline, or a man-in-the-middle attack on the Homebrew download could deliver
a modified binary. doit does not verify its own integrity at runtime.
Homebrew's formulae are version-pinned and the source is on GitHub at
https://github.com/marcelocantos/doit — users who care about supply chain
should build from source and verify the commit.

### 5. Denial of service against the policy engine

The doit process can be killed, hung, or starved of resources. This does not
cause a "fail open" scenario — the agent cannot execute commands if doit is
unresponsive — but it can deny the agent the ability to do useful work. doit
provides no defence against this.

### 6. Session-scope manipulation

Work sessions (`doit_session_start`) prepend a scope and description to every
L3 prompt. An agent that declares a broad or misleading scope ("general
development work") can cause L3 to approve commands it would otherwise
scrutinise. The session description is agent-supplied and is not validated
against what actually happens during the session.

---

## Configuration Assumptions

The safety model depends on the following being true. `doit_check_config`
reports the state of every numbered item below — `[FAIL]` for §1–§2 when the
contractual settings are missing, and `[INFO]` / `[WARN]` for §3–§7 where doit
can observe state but cannot judge intent. Run it after installation and after
any settings change.

### Asserted by `doit_check_config` (FAIL on absence)

1. **`Bash` is in the deny list** in `~/.claude/settings.json` (user scope)
   or `.claude/settings.json` (project scope). Without this, Claude Code's
   built-in Bash tool is available and completely bypasses doit. This is the
   single most important configuration item.

2. **The doit MCP server is registered** in `~/.claude.json`. Without
   registration, `doit_execute` is not available to the agent and the user
   has no gatekeeper.

### Reported by `doit_check_config` (user's responsibility to interpret)

3. **No other MCP servers with unconstrained execution paths are registered**
   for the same session. See [Limits](#what-doit-does-not-defend-against) §1.
   doit emits a STARTUP warning for any registered sibling that matches a
   known-risky name pattern. Suppress per-server with
   `policy.acknowledged_sibling_servers` in `~/.config/doit/config.yaml`
   once you have consciously accepted the risk.

4. **The `dangerous` tier remains disabled** (`tiers.dangerous: false`, the
   default) unless the user has explicitly decided to enable it. Enabling the
   dangerous tier allows `rm`, `chmod`, and destructive git subcommands.

5. **L1 Starlark rules and the L2 policy store are not writable by untrusted
   processes.** The defaults place them under `~/.config/doit/` and
   `~/.local/share/doit/`, which are user-owned. Do not grant write access to
   these directories to any other user or process.

6. **L3 is configured to reach a trustworthy Claude model.** The default L3
   models are sonnet (fast triage) and opus (deep reasoning), invoked via
   `claude -p`. If the user has configured a different model or a custom
   `claude` binary, the security properties of L3 may differ.

7. **Per-project `.doit/config.yaml` files come from trusted sources.** doit
   applies per-project config additively on top of global config (it cannot
   loosen global rules, only tighten). However, a malicious project config
   could add rules that interact unexpectedly with global rules. Treat
   `.doit/config.yaml` as code.

---

## Recommended Mitigations

1. **Audit your MCP server inventory.** Run `doit_check_config` after every
   change to your Claude Code settings. Enumerate all registered MCP servers
   and ask: does this server expose execution-adjacent primitives? If yes,
   decide consciously whether to accept that risk or remove the server.

2. **Keep `dangerous` tier disabled.** Do not enable `tiers.dangerous: true`
   globally. If a specific operation requires it, enable it temporarily via
   per-project config, or use user elicitation (Allow once) to approve
   individual commands.

3. **Review L2 learned policies regularly.** Use `doit_policy_review` to list
   entries overdue for review. Broad or stale allow-patterns are the most
   likely way for an attacker to exploit L3 prompt injection — they can issue
   commands that match an existing broad allow rule without triggering
   elicitation.

4. **Use `doit_self_audit` to detect contradictions.** Contradictions between
   L1 and L2 rules (a Starlark rule says deny, an L2 entry says allow for the
   same command) are detected by `doit_self_audit`. Run it after adding or
   modifying rules.

5. **Inspect approved scripts before first use.** The content-hash gate
   presents a preview, but it is truncated. Read the full script before
   approving it. Use `doit_approvals_list` to see what is approved and
   `doit_approvals_revoke` to rescind approvals that are no longer needed.

6. **Pin the doit version.** The Homebrew tap tracks the latest release.
   Production environments should pin to a known-good version and upgrade
   deliberately.

---

## Scope for Future Work

The following gaps are known and not yet addressed. They are tracked as
targets in `docs/targets.yaml`.

- **Broader script-hash gate.** The tier-0 gate fires only for `bash|sh|zsh
  <path>` and `./path` with a shell shebang. Pipelines, `bash -c "…"` inline
  scripts, and non-shell interpreters (python, node) fall through to L1/L2/L3.
  Extending the gate to cover inline strings and other interpreters would close
  this gap, but makes the UX significantly heavier.

- **MCP server inventory check.** `doit_check_config` enumerates sibling MCP
  servers (§3) and classifies known-risky names. A STARTUP warning fires for
  any unacknowledged risky sibling. Operators can suppress per-server via
  `policy.acknowledged_sibling_servers` in `~/.config/doit/config.yaml`.

- **L3 prompt injection hardening.** The L3 prompt does not sanitise or escape
  the command string, justification, or safety argument. Adding a structural
  separator between the instruction section and the agent-supplied data would
  reduce (not eliminate) prompt injection risk.

- **Audit log write protection.** The audit log is append-only at the
  application level, but is writable at the OS level. Filesystem-level
  append-only attributes (e.g., `chflags uappend` on macOS) or remote
  log forwarding would make post-hoc tampering harder to conceal.

- **Config integrity verification.** A hash or signature over the Starlark
  rules directory and the L2 policy store would let doit detect at startup
  whether its config has been tampered with since the last known-good state.
