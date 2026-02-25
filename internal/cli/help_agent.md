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

Use `--pipe` with the `¦` (U+00A6 BROKEN BAR) operator to chain capabilities.
No quoting is needed — these are not shell metacharacters.

    doit --pipe <cmd> [args...] ¦ <cmd> [args...] ¦ ...

Examples:

    doit --pipe grep -r TODO src/ ¦ head -20
    doit --pipe git log --oneline ¦ grep fix ¦ head -5
    doit --pipe cat file.txt ¦ sort ¦ uniq -c

## Redirects

Use `›` (U+203A) to redirect stdout to a file and `‹` (U+2039) to redirect
stdin from a file. These can appear anywhere in the argument list.

    doit --pipe grep -r TODO src/ ¦ sort › /tmp/results.txt
    doit --pipe sort ‹ /tmp/input.txt ¦ uniq -c

## Safety tiers

Each capability has a safety tier: read, build, write, or dangerous.
Dangerous-tier capabilities (rm, chmod, git push) are disabled by default.
If a command is rejected due to its tier, do not attempt to bypass it.

    doit --list                  # show all capabilities and their tiers
    doit --list --tier read      # show only read-tier capabilities

## Audit log

All invocations are logged to a tamper-evident audit trail. Do not attempt
to modify or delete the audit log.

    doit --audit show            # view recent entries
    doit --audit verify          # check log integrity

## Important rules

1. Always use `doit` instead of running commands directly.
2. Use `doit --pipe` with `¦` for pipelines instead of shell `|`.
3. Use `›` and `‹` for redirects instead of shell `>` and `<`.
4. Respect tier denials — do not retry denied commands.
5. Use `doit --list` to discover available capabilities.
6. Every invocation is audited. Work transparently.
