# Block recursive removal of root, home, or current directory.
# This is a core safety rule that is never bypassable.

rule_id = "deny-rm-catastrophic"
description = "Block recursive removal of root, home, or current directory"
bypassable = False

def has_recursive_flag(args):
    """Check if -r or -R is present (handles combined flags like -rf)."""
    for arg in args:
        if not arg or arg[0] != "-":
            continue
        if arg == "-r" or arg == "-R":
            return True
        # Combined short flags: "-rf" contains "-r"
        if len(arg) > 2 and arg[0] == "-" and arg[1] != "-":
            for ch in arg[1:].elems():
                if ch == "r" or ch == "R":
                    return True
    return False

def clean_path(p):
    """Simplified path cleaning: collapse /, ., .."""
    if p == "/" or p == "/.":
        return "/"
    if p == "." or p == "./":
        return "."
    if p == ".." or p == "../":
        return ".."
    return p

def check(command, args):
    if command != "rm":
        return None
    if not has_recursive_flag(args):
        return None
    for arg in args:
        if not arg or arg[0] == "-":
            continue
        cleaned = clean_path(arg)
        if cleaned == "/" or cleaned == "." or cleaned == "..":
            return {
                "decision": "deny",
                "reason": "refusing to recursively remove %s (permanently blocked)" % repr(arg),
            }
        if arg == "~" or arg.startswith("~/"):
            return {
                "decision": "deny",
                "reason": "refusing to recursively remove %s (permanently blocked)" % repr(arg),
            }
    return None

tests = [
    # Should deny
    {"command": "rm", "args": ["-rf", "/"], "expect": "deny"},
    {"command": "rm", "args": ["-r", "/"], "expect": "deny"},
    {"command": "rm", "args": ["-R", "/"], "expect": "deny"},
    {"command": "rm", "args": ["-rf", "."], "expect": "deny"},
    {"command": "rm", "args": ["-rf", ".."], "expect": "deny"},
    {"command": "rm", "args": ["-rf", "~"], "expect": "deny"},
    {"command": "rm", "args": ["-rf", "~/Documents"], "expect": "deny"},
    # Should not deny (no opinion)
    {"command": "rm", "args": ["-rf", "build/"], "expect": "escalate"},
    {"command": "rm", "args": ["somefile"], "expect": "escalate"},
    {"command": "rm", "args": ["-f", "/"], "expect": "escalate"},
    {"command": "ls", "args": ["-la", "/"], "expect": "escalate"},
]
