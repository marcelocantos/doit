// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
)

// Decision represents the outcome of policy evaluation.
type Decision int

const (
	Allow    Decision = iota // command is allowed
	Deny                     // command is blocked
	Escalate                 // no opinion, defer to higher level
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Escalate:
		return "escalate"
	default:
		return "unknown"
	}
}

// Result is a structured policy decision.
type Result struct {
	Decision   Decision
	Level      int    // 1, 2, or 3
	Reason     string // human-readable explanation
	RuleID     string // which rule matched (empty if none)
	Bypassable bool   // true if the user can override this decision
}

// Request is the structured input to the policy engine.
// The engine treats Command as an opaque string; shell composition (&&, |, ;,
// redirects, subshells) is left to the shell and is never parsed by doit.
type Request struct {
	Command       string // raw command string passed to sh -c
	Cwd           string
	Retry         bool
	Justification string // why the worker needs this command
	SafetyArg     string // why the worker believes it's safe
	ProjectType   string // project type discovered from context (e.g. "go", "node")
}

// EvalInfo carries policy evaluation metadata through context for audit logging.
type EvalInfo struct {
	Level         int
	Decision      string // "allow", "deny", "escalate"
	RuleID        string
	Justification string
	SafetyArg     string
}

type evalInfoKey struct{}

// NewEvalContext returns a context with policy evaluation info attached.
func NewEvalContext(ctx context.Context, info *EvalInfo) context.Context {
	return context.WithValue(ctx, evalInfoKey{}, info)
}

// EvalFromContext retrieves policy evaluation info from a context.
// Returns nil if not set.
func EvalFromContext(ctx context.Context) *EvalInfo {
	info, _ := ctx.Value(evalInfoKey{}).(*EvalInfo)
	return info
}
