// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/rules"
)

// Level1 evaluates commands against deterministic rules.
type Level1 struct {
	rules []Rule
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
	l := &Level1{}

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
			return result
		}
	}
	return &Result{
		Decision: Escalate,
		Level:    1,
		Reason:   "no deterministic rule matched",
	}
}

// Rules returns the list of rules for inspection/testing.
func (l *Level1) Rules() []Rule {
	return l.rules
}

// --- Built-in rules ---

func checkRmCatastrophic(req *Request) *Result {
	for _, seg := range req.Segments {
		if seg.CapName != "rm" {
			continue
		}
		if !hasAnyFlag(seg.Args, "-r", "-R") {
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
					Reason:   "checkout: refusing to discard all changes (config rule). Ask the user for explicit permission, then retry with: doit --retry git checkout .",
					RuleID:   "deny-git-checkout-all",
				}
			}
			if arg == "--" && i+1 < len(seg.Args[1:]) {
				next := filepath.Clean(seg.Args[i+2])
				if next == "." {
					return &Result{
						Decision: Deny,
						Level:    1,
						Reason:   "checkout: refusing to discard all changes (config rule). Ask the user for explicit permission, then retry with: doit --retry git checkout .",
						RuleID:   "deny-git-checkout-all",
					}
				}
			}
		}
	}
	return nil
}

func checkSafePipeline(req *Request) *Result {
	if req.HasRedirectOut {
		return nil // output redirect is a write operation
	}
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
					if hasAnyFlag(seg.Args, flags...) {
						return &Result{
							Decision: Deny,
							Level:    1,
							Reason:   fmt.Sprintf("rejected flag for %s (config rule). Ask the user for explicit permission, then retry with: doit --retry %s ...", name, name),
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
						if hasAnyFlag(seg.Args[1:], flags...) {
							return &Result{
								Decision: Deny,
								Level:    1,
								Reason:   fmt.Sprintf("%s: rejected flag for %s (config rule). Ask the user for explicit permission, then retry with: doit --retry %s ...", sub, name, name),
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

// hasAnyFlag checks whether any element in args matches one of the given flags.
// Handles exact match, combined short flags, short flag with value, and
// long flag with =.
func hasAnyFlag(args []string, flags ...string) bool {
	for _, arg := range args {
		if arg == "" || arg[0] != '-' {
			continue
		}
		for _, flag := range flags {
			if arg == flag {
				return true
			}
			// Short flag: "-j" matches "-j4" (value suffix) and "-rf" (combined)
			if len(flag) == 2 && flag[0] == '-' && flag[1] != '-' &&
				len(arg) > 2 && arg[0] == '-' && arg[1] != '-' {
				if strings.ContainsRune(arg[1:], rune(flag[1])) {
					return true
				}
			}
			// Long flag with =: "--force" matches "--force=yes"
			if len(flag) > 2 && flag[0:2] == "--" && strings.HasPrefix(arg, flag+"=") {
				return true
			}
		}
	}
	return false
}
