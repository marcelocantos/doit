# Block git push --force and related flags.
# Force pushing can destroy remote history.

rule_id = "deny-git-push-force"
description = "Reject force push flags for git push"
bypassable = True

def has_any_flag(args, flags):
    """Check if any arg matches any of the given flags."""
    for arg in args:
        if not arg or arg[0] != "-":
            continue
        for flag in flags:
            if arg == flag:
                return True
            # Short flag combined: "-rf" matches "-r" and "-f"
            if len(flag) == 2 and flag[0] == "-" and flag[1] != "-":
                if len(arg) > 2 and arg[0] == "-" and arg[1] != "-":
                    for ch in arg[1:].elems():
                        if ch == flag[1]:
                            return True
            # Long flag with =: "--force" matches "--force=yes"
            if len(flag) > 2 and flag[:2] == "--" and arg.startswith(flag + "="):
                return True
    return False

def check(command, args):
    if command != "git":
        return None
    if not args or args[0] != "push":
        return None
    if has_any_flag(args[1:], ["--force", "-f", "--force-with-lease"]):
        return {
            "decision": "deny",
            "reason": "push: rejected force flag for git (config rule). Ask the user for explicit permission, then retry with: doit --retry git ...",
        }
    return None

tests = [
    # Should deny
    {"command": "git", "args": ["push", "--force"], "expect": "deny"},
    {"command": "git", "args": ["push", "-f"], "expect": "deny"},
    {"command": "git", "args": ["push", "--force-with-lease"], "expect": "deny"},
    {"command": "git", "args": ["push", "origin", "main", "--force"], "expect": "deny"},
    # Should not deny (no opinion)
    {"command": "git", "args": ["push"], "expect": "escalate"},
    {"command": "git", "args": ["push", "origin", "main"], "expect": "escalate"},
    {"command": "git", "args": ["pull", "--force"], "expect": "escalate"},
    {"command": "make", "args": ["push", "--force"], "expect": "escalate"},
]
