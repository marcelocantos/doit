# Block git reset --hard.
# Hard reset discards all uncommitted changes.

rule_id = "deny-git-reset-hard"
description = "Reject --hard flag for git reset"
bypassable = True

def has_any_flag(args, flags):
    """Check if any arg matches any of the given flags."""
    for arg in args:
        if not arg or arg[0] != "-":
            continue
        for flag in flags:
            if arg == flag:
                return True
            if len(flag) > 2 and flag[:2] == "--" and arg.startswith(flag + "="):
                return True
    return False

def check(command, args):
    if command != "git":
        return None
    if not args or args[0] != "reset":
        return None
    if has_any_flag(args[1:], ["--hard"]):
        return {
            "decision": "deny",
            "reason": "reset: rejected --hard flag for git (config rule). config rule, bypassable",
        }
    return None

tests = [
    # Should deny
    {"command": "git", "args": ["reset", "--hard"], "expect": "deny"},
    {"command": "git", "args": ["reset", "--hard", "HEAD~1"], "expect": "deny"},
    # Should not deny (no opinion)
    {"command": "git", "args": ["reset"], "expect": "escalate"},
    {"command": "git", "args": ["reset", "--soft", "HEAD~1"], "expect": "escalate"},
    {"command": "git", "args": ["reset", "HEAD~1"], "expect": "escalate"},
    {"command": "make", "args": ["reset", "--hard"], "expect": "escalate"},
]
