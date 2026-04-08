// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package starlark

import (
	"fmt"
	"strings"
)

// GenerateRequest describes a rule to generate as Starlark source.
type GenerateRequest struct {
	RuleID        string
	Description   string
	Bypassable    bool
	Command       string   // capability name to match (e.g. "rm", "git")
	Subcommand    string   // optional subcommand (e.g. "push")
	RejectFlags   []string // flags that trigger denial
	RejectPaths   []string // path arguments that trigger denial (cleaned via path logic)
	Decision      string   // "deny" (most common for generated rules)
	Justification string   // why this rule exists
	TestCases     []GenerateTestCase
}

// GenerateTestCase is a test case to include in the generated rule.
type GenerateTestCase struct {
	Command string
	Args    []string
	Expect  string
}

// Generate produces Starlark source code for a rule from a GenerateRequest.
// This supports L3→L1 promotion: the LLM provides the pattern and decision,
// and this function generates the Starlark code + tests for human review.
func Generate(req GenerateRequest) string {
	var sb strings.Builder

	// Header.
	fmt.Fprintf(&sb, "# %s\n", req.Description)
	if req.Justification != "" {
		fmt.Fprintf(&sb, "# Justification: %s\n", req.Justification)
	}
	sb.WriteString("\n")

	// Globals.
	fmt.Fprintf(&sb, "rule_id = %q\n", req.RuleID)
	fmt.Fprintf(&sb, "description = %q\n", req.Description)
	if req.Bypassable {
		sb.WriteString("bypassable = True\n")
	} else {
		sb.WriteString("bypassable = False\n")
	}
	sb.WriteString("\n")

	// Helper: has_any_flag.
	if len(req.RejectFlags) > 0 {
		sb.WriteString(`def has_any_flag(args, flags):
    """Check if any arg matches any of the given flags."""
    for arg in args:
        if not arg or arg[0] != "-":
            continue
        for flag in flags:
            if arg == flag:
                return True
            # Short flag combined: "-rf" matches "-r"
            if len(flag) == 2 and flag[0] == "-" and flag[1] != "-":
                if len(arg) > 2 and arg[0] == "-" and arg[1] != "-":
                    for ch in arg[1:].elems():
                        if ch == flag[1]:
                            return True
            # Long flag with =: "--force" matches "--force=yes"
            if len(flag) > 2 and flag[:2] == "--" and arg.startswith(flag + "="):
                return True
    return False
`)
		sb.WriteString("\n")
	}

	// Check function.
	sb.WriteString("def check(command, args):\n")

	// Command match.
	fmt.Fprintf(&sb, "    if command != %q:\n", req.Command)
	sb.WriteString("        return None\n")

	// Subcommand match.
	if req.Subcommand != "" {
		fmt.Fprintf(&sb, "    if not args or args[0] != %q:\n", req.Subcommand)
		sb.WriteString("        return None\n")
	}

	// Flag rejection.
	if len(req.RejectFlags) > 0 {
		sb.WriteString("    reject_flags = [")
		for i, f := range req.RejectFlags {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%q", f)
		}
		sb.WriteString("]\n")

		argsExpr := "args"
		if req.Subcommand != "" {
			argsExpr = "args[1:]"
		}
		fmt.Fprintf(&sb, "    if has_any_flag(%s, reject_flags):\n", argsExpr)
		fmt.Fprintf(&sb, "        return {\"decision\": %q, \"reason\": %q}\n",
			req.Decision, req.Description)
	}

	// Path rejection.
	if len(req.RejectPaths) > 0 {
		sb.WriteString("    for arg in args:\n")
		sb.WriteString("        if not arg or arg[0] == \"-\":\n")
		sb.WriteString("            continue\n")
		sb.WriteString("        reject_paths = [")
		for i, p := range req.RejectPaths {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%q", p)
		}
		sb.WriteString("]\n")
		sb.WriteString("        if arg in reject_paths:\n")
		fmt.Fprintf(&sb, "            return {\"decision\": %q, \"reason\": %q}\n",
			req.Decision, req.Description)
	}

	sb.WriteString("    return None\n")
	sb.WriteString("\n")

	// Tests.
	sb.WriteString("tests = [\n")
	for _, tc := range req.TestCases {
		sb.WriteString("    {")
		fmt.Fprintf(&sb, "\"command\": %q, ", tc.Command)
		sb.WriteString("\"args\": [")
		for i, a := range tc.Args {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%q", a)
		}
		sb.WriteString("], ")
		fmt.Fprintf(&sb, "\"expect\": %q", tc.Expect)
		sb.WriteString("},\n")
	}
	sb.WriteString("]\n")

	return sb.String()
}
