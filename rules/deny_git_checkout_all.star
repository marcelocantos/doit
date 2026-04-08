# Block git checkout . which discards all uncommitted changes.

rule_id = "deny-git-checkout-all"
description = "Block git checkout . which discards all changes"
bypassable = True

def check(command, args):
    if command != "git":
        return None
    if not args or args[0] != "checkout":
        return None
    for i, arg in enumerate(args[1:]):
        # Direct "." argument
        if arg == "." or arg == "./":
            return {
                "decision": "deny",
                "reason": "checkout: refusing to discard all changes (config rule). Ask the user for explicit permission, then retry with: doit --retry git checkout .",
            }
        # "-- ." pattern
        if arg == "--" and i + 1 < len(args[1:]):
            next_arg = args[i + 2]
            if next_arg == "." or next_arg == "./":
                return {
                    "decision": "deny",
                    "reason": "checkout: refusing to discard all changes (config rule). Ask the user for explicit permission, then retry with: doit --retry git checkout .",
                }
    return None

tests = [
    # Should deny
    {"command": "git", "args": ["checkout", "."], "expect": "deny"},
    {"command": "git", "args": ["checkout", "./"], "expect": "deny"},
    {"command": "git", "args": ["checkout", "--", "."], "expect": "deny"},
    # Should not deny (no opinion)
    {"command": "git", "args": ["checkout", "main"], "expect": "escalate"},
    {"command": "git", "args": ["checkout", "-b", "feature"], "expect": "escalate"},
    {"command": "git", "args": ["checkout", "somefile.go"], "expect": "escalate"},
    {"command": "make", "args": ["checkout", "."], "expect": "escalate"},
]
