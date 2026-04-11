// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/rules"
	doitstar "github.com/marcelocantos/doit/internal/starlark"
)

// Level1 evaluates commands against deterministic rules.
type Level1 struct {
	rules     []Rule
	starlark  *doitstar.Evaluator
}

// Rule is a named, testable deterministic rule.
type Rule struct {
	ID          string
	Description string
	Bypassable  bool                       // true = can be bypassed with --retry
	Check       func(req *Request) *Result // nil = no opinion (pass to next)
}

// NewLevel1 creates a Level1 engine with built-in and config-derived rules.
func NewLevel1(cfgRules map[string]rules.CapRuleConfig) *Level1 {
	return NewLevel1WithStarlark(cfgRules, nil)
}

// NewLevel1WithStarlark creates a Level1 engine with built-in, config-derived,
// and Starlark rules. Starlark rules are evaluated after built-in rules but
// before the auto-allow safe-pipeline rule.
func NewLevel1WithStarlark(cfgRules map[string]rules.CapRuleConfig, starlarkEval *doitstar.Evaluator) *Level1 {
	l := &Level1{starlark: starlarkEval}

	// Hardcoded deny rules (never bypassable).
	l.rules = append(l.rules, Rule{
		ID:          "deny-rm-catastrophic",
		Description: "Block recursive removal of root, home, or current directory",
		Check:       checkRmCatastrophic,
	})

	// Config deny rules (bypassable with --retry).
	for capName, cfg := range cfgRules {
		l.rules = append(l.rules, compileConfigRules(capName, cfg)...)
	}

	// git checkout . rule (bypassable).
	l.rules = append(l.rules, Rule{
		ID:          "deny-git-checkout-all",
		Description: "Block git checkout . which discards all changes",
		Bypassable:  true,
		Check:       checkGitCheckoutAll,
	})

	// Auto-allow rules.
	l.rules = append(l.rules, Rule{
		ID:          "allow-safe-pipeline",
		Description: "Auto-allow pipelines where every segment is read-only",
		Check:       checkSafePipeline,
	})

	return l
}

// Evaluate runs all rules. First definitive result wins.
// Returns Escalate if no rule has an opinion.
func (l *Level1) Evaluate(req *Request) *Result {
	for _, r := range l.rules {
		if r.Bypassable && req.Retry {
			continue
		}
		if result := r.Check(req); result != nil {
			result.Bypassable = r.Bypassable
			return result
		}
	}

	// Evaluate Starlark rules.
	if l.starlark != nil {
		for _, seg := range req.Segments {
			starResult, ruleID, starBypassable := l.starlark.EvaluateCommand(seg.CapName, seg.Args, req.Retry)
			if starResult != nil {
				dec := Escalate
				switch starResult.Decision {
				case "allow":
					dec = Allow
				case "deny":
					dec = Deny
				}
				return &Result{
					Decision:   dec,
					Level:      1,
					Reason:     starResult.Reason,
					RuleID:     ruleID,
					Bypassable: starBypassable,
				}
			}
		}
	}

	return &Result{
		Decision: Escalate,
		Level:    1,
		Reason:   "no deterministic rule matched",
	}
}

// Rules returns the list of Go rules for inspection/testing.
func (l *Level1) Rules() []Rule {
	return l.rules
}

// AddProjectContextRules inserts auto-allow rules for safeCommands derived
// from project context discovery (🎯T13). Rules are inserted before the
// Starlark evaluation step so that project-specific safe commands are decided
// deterministically at L1.
//
// safeCommands is a list of command prefixes (e.g. "go test", "make") that
// should be auto-allowed. Each entry is matched against the first one or two
// tokens of the command string.
func (l *Level1) AddProjectContextRules(projectType string, safeCommands []string) {
	if len(safeCommands) == 0 {
		return
	}

	// Build a set of (cap, optional-subcommand) pairs for fast lookup.
	type cmdKey struct{ cap, sub string }
	allowed := make(map[cmdKey]bool, len(safeCommands))
	for _, sc := range safeCommands {
		parts := strings.Fields(sc)
		if len(parts) == 0 {
			continue
		}
		cap := parts[0]
		sub := ""
		if len(parts) > 1 {
			sub = parts[1]
		}
		allowed[cmdKey{cap, sub}] = true
	}

	rule := Rule{
		ID:          fmt.Sprintf("allow-project-safe-commands-%s", projectType),
		Description: fmt.Sprintf("Auto-allow safe commands for %s project", projectType),
		Check: func(req *Request) *Result {
			for _, seg := range req.Segments {
				sub := ""
				if len(seg.Args) > 0 {
					sub = seg.Args[0]
				}
				// Match cap+sub first, fall back to cap-only.
				if allowed[cmdKey{seg.CapName, sub}] || allowed[cmdKey{seg.CapName, ""}] {
					return &Result{
						Decision: Allow,
						Level:    1,
						Reason:   fmt.Sprintf("safe command for %s project", projectType),
						RuleID:   fmt.Sprintf("allow-project-safe-commands-%s", projectType),
					}
				}
			}
			return nil
		},
	}

	// Insert before Starlark evaluation (i.e., at the end of the Go-rule slice,
	// since Starlark is evaluated after the Go rules loop in Evaluate()).
	l.rules = append(l.rules, rule)
}

// StarlarkRuleCount returns the number of loaded Starlark rules.
func (l *Level1) StarlarkRuleCount() int {
	if l.starlark == nil {
		return 0
	}
	return l.starlark.RuleCount()
}

// --- Built-in rules ---

func checkRmCatastrophic(req *Request) *Result {
	for _, seg := range req.Segments {
		if seg.CapName != "rm" {
			continue
		}
		if !HasAnyFlag(seg.Args, "-r", "-R") {
			continue
		}
		for _, arg := range seg.Args {
			if arg == "" || arg[0] == '-' {
				continue
			}
			cleaned := filepath.Clean(arg)
			if cleaned == "/" || cleaned == "." || cleaned == ".." {
				return &Result{
					Decision: Deny,
					Level:    1,
					Reason:   fmt.Sprintf("refusing to recursively remove %q (permanently blocked)", arg),
					RuleID:   "deny-rm-catastrophic",
				}
			}
			if arg == "~" || strings.HasPrefix(arg, "~/") {
				return &Result{
					Decision: Deny,
					Level:    1,
					Reason:   fmt.Sprintf("refusing to recursively remove %q (permanently blocked)", arg),
					RuleID:   "deny-rm-catastrophic",
				}
			}
		}
	}
	return nil
}

func checkGitCheckoutAll(req *Request) *Result {
	for _, seg := range req.Segments {
		if seg.CapName != "git" || len(seg.Args) == 0 || seg.Args[0] != "checkout" {
			continue
		}
		for i, arg := range seg.Args[1:] {
			cleaned := filepath.Clean(arg)
			if cleaned == "." {
				return &Result{
					Decision: Deny,
					Level:    1,
					Reason:   "checkout: refusing to discard all changes (config rule, bypassable)",
					RuleID:   "deny-git-checkout-all",
				}
			}
			if arg == "--" && i+1 < len(seg.Args[1:]) {
				next := filepath.Clean(seg.Args[i+2])
				if next == "." {
					return &Result{
						Decision: Deny,
						Level:    1,
						Reason:   "checkout: refusing to discard all changes (config rule, bypassable)",
						RuleID:   "deny-git-checkout-all",
					}
				}
			}
		}
	}
	return nil
}

func checkSafePipeline(req *Request) *Result {
	if len(req.Segments) == 0 {
		return nil
	}
	for _, seg := range req.Segments {
		if seg.Tier != cap.TierRead {
			return nil
		}
	}
	return &Result{
		Decision: Allow,
		Level:    1,
		Reason:   "all segments are read-only",
		RuleID:   "allow-safe-pipeline",
	}
}

// --- Config rule compilation ---

func compileConfigRules(capName string, cfg rules.CapRuleConfig) []Rule {
	var result []Rule

	if len(cfg.RejectFlags) > 0 {
		flags := cfg.RejectFlags
		name := capName
		result = append(result, Rule{
			ID:          fmt.Sprintf("deny-%s-flags", name),
			Description: fmt.Sprintf("Reject flags %v for %s", flags, name),
			Bypassable:  true,
			Check: func(req *Request) *Result {
				for _, seg := range req.Segments {
					if seg.CapName != name {
						continue
					}
					if HasAnyFlag(seg.Args, flags...) {
						return &Result{
							Decision: Deny,
							Level:    1,
							Reason:   fmt.Sprintf("rejected flag for %s (config rule, bypassable)", name),
							RuleID:   fmt.Sprintf("deny-%s-flags", name),
						}
					}
				}
				return nil
			},
		})
	}

	for subcmd, subRule := range cfg.Subcommands {
		if len(subRule.RejectFlags) > 0 {
			flags := subRule.RejectFlags
			name := capName
			sub := subcmd
			result = append(result, Rule{
				ID:          fmt.Sprintf("deny-%s-%s-flags", name, sub),
				Description: fmt.Sprintf("Reject flags %v for %s %s", flags, name, sub),
				Bypassable:  true,
				Check: func(req *Request) *Result {
					for _, seg := range req.Segments {
						if seg.CapName != name || len(seg.Args) == 0 || seg.Args[0] != sub {
							continue
						}
						if HasAnyFlag(seg.Args[1:], flags...) {
							return &Result{
								Decision: Deny,
								Level:    1,
								Reason:   fmt.Sprintf("%s: rejected flag for %s (config rule, bypassable)", sub, name),
								RuleID:   fmt.Sprintf("deny-%s-%s-flags", name, sub),
							}
						}
					}
					return nil
				},
			})
		}
	}

	return result
}

// HasAnyFlag checks whether any element in args matches one of the given flags.
// Handles exact match, combined short flags, short flag with value, and
// long flag with =. Delegates to rules.HasAnyFlag.
func HasAnyFlag(args []string, flags ...string) bool {
	return rules.HasAnyFlag(args, flags...)
}
