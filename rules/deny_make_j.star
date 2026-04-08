# Block make -j flag.
# Projects set MAKEFLAGS internally; passing -j externally causes issues.

rule_id = "deny-make-j"
description = "Reject -j flag for make (projects set MAKEFLAGS internally)"
bypassable = True

def has_any_flag(args, flags):
    """Check if any arg matches any of the given flags."""
    for arg in args:
        if not arg or arg[0] != "-":
            continue
        for flag in flags:
            if arg == flag:
                return True
            # Short flag combined or with value: "-j4" matches "-j"
            if len(flag) == 2 and flag[0] == "-" and flag[1] != "-":
                if len(arg) > 2 and arg[0] == "-" and arg[1] != "-":
                    for ch in arg[1:].elems():
                        if ch == flag[1]:
                            return True
    return False

def check(command, args):
    if command != "make":
        return None
    if has_any_flag(args, ["-j"]):
        return {
            "decision": "deny",
            "reason": "rejected -j flag for make (config rule). Ask the user for explicit permission, then retry with: doit --retry make ...",
        }
    return None

tests = [
    # Should deny
    {"command": "make", "args": ["-j"], "expect": "deny"},
    {"command": "make", "args": ["-j4"], "expect": "deny"},
    {"command": "make", "args": ["-j", "8"], "expect": "deny"},
    {"command": "make", "args": ["all", "-j"], "expect": "deny"},
    # Should not deny (no opinion)
    {"command": "make", "args": ["all"], "expect": "escalate"},
    {"command": "make", "args": [], "expect": "escalate"},
    {"command": "go", "args": ["-j"], "expect": "escalate"},
]
