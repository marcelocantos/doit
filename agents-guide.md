# doit — Agent Usage Guide

You are using `doit`, a capability broker that mediates command execution.
Add `Bash(doit:*)` to your allow list and use `doit` for all shell operations.

## Direct execution

Run a single capability:

    doit <capability> [args...]

Examples:

    doit grep -r TODO src/
    doit ls -la
    doit git status
    doit head -20 README.md

## Pipelines

Use the `¦` (U+00A6 BROKEN BAR) operator to chain capabilities.
No quoting is needed — these are not shell metacharacters.

    doit <cmd> [args...] ¦ <cmd> [args...] ¦ ...

Examples:

    doit grep -r TODO src/ ¦ head -20
    doit git log --oneline ¦ grep fix ¦ head -5
    doit cat file.txt ¦ sort ¦ uniq -c

## Redirects

Use `›` (U+203A) to redirect stdout to a file and `‹` (U+2039) to redirect
stdin from a file. These can appear anywhere in the argument list.

    doit grep -r TODO src/ ¦ sort › /tmp/results.txt
    doit sort ‹ /tmp/input.txt ¦ uniq -c

## Compound commands

Use compound operators to chain pipelines conditionally:

- `＆＆` (and-then): run the next pipeline only if the previous succeeded
- `‖` (or-else): run the next pipeline only if the previous failed
- `；` (sequential): run the next pipeline regardless of exit code

    doit make build ＆＆ git add -A
    doit make build ‖ cat build-failed.txt
    doit git add -A ；git commit -m "auto"

Compound operators chain whole pipelines. Pipes and redirects scope to each
pipeline section:

    doit grep TODO src/ ¦ wc -l ＆＆ cat ok.txt
    doit sort ‹ input.txt › sorted.txt ＆＆ head -5 ‹ sorted.txt

## Safety tiers

Each capability has a safety tier: read, build, write, or dangerous.
Dangerous-tier capabilities (rm, chmod, git push) are disabled by default.
If a command is rejected due to its tier, do not attempt to bypass it.

    doit --list                  # show all capabilities and their tiers
    doit --list --tier read      # show only read-tier capabilities

## Rule bypass with --retry

Some commands are blocked by config rules (e.g., `make -j`, `git push --force`,
`git checkout .`). When blocked, the error message will tell you how to retry
with `--retry`. Only do this after the user has explicitly approved the operation.

    doit --retry make -j4 all
    doit --retry git push --force origin master
    doit --retry git checkout .
    doit --retry make -j4 ＆＆ git push --force

The `--retry` flag:
- Only bypasses config-based rules, never hardcoded safety rules
- Only applies to a single invocation
- Is recorded in the audit log

### Four types of denials

1. **Tier denied** — The capability's tier (e.g., dangerous) is disabled.
   Do not retry. This cannot be bypassed.
2. **Hardcoded rule** — A safety rule permanently blocks the operation
   (e.g., `rm -rf /`). Do not retry. This cannot be bypassed.
3. **Config rule** — A configurable rule blocks the operation (e.g.,
   `make -j`, `git push --force`, `git checkout .`). Ask the user for
   permission, then retry with `doit --retry <cap> [args...]`.
4. **Policy escalation** — The LLM gatekeeper couldn't decide and needs
   human review. The error output includes reasoning and an approval token.
   Present the reasoning to the user. If they approve, retry with
   `doit --approved <token> <cap> [args...]`.

## Policy escalation with --approved

When Level 3 (LLM gatekeeper) is enabled and the LLM cannot confidently
allow or deny a command, it escalates to a human. The stderr output includes:
- The LLM's reasoning about the command
- An approval token (hex string)
- A retry instruction

Present the LLM's reasoning to the user and ask whether to proceed.
If the user approves, retry the exact same command with the approval token:

    doit --approved <token> <cap> [args...]

Example:

    doit --approved a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 git push --force origin master

Approval tokens:
- Are single-use — each token can only be used once
- Expire after 10 minutes
- Must match the original command arguments exactly
- Are validated by the daemon before the command runs

The `--approved` flag:
- Bypasses all policy levels (L1, L2, L3) for the validated command
- Only works with a valid, unexpired token for matching arguments
- Is recorded in the audit log with `policy_level: 3` and `rule_id: approval-token`

## Audit log

All invocations are logged to a tamper-evident audit trail. Do not attempt
to modify or delete the audit log.

    doit --audit show            # view recent entries
    doit --audit verify          # check log integrity

## Important rules

1. Always use `doit` instead of running commands directly.
2. Use `¦` for pipelines instead of shell `|`.
3. Use `›` and `‹` for redirects instead of shell `>` and `<`.
4. Respect tier denials and hardcoded blocks — do not retry.
   Config rule blocks can be retried with `--retry` after user approval.
5. Use `doit --list` to discover available capabilities.
6. Every invocation is audited. Work transparently.
