// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package starlark

// Evaluator manages a set of loaded Starlark rules and evaluates commands
// against them. It integrates with the policy chain as an L1 rule source.
type Evaluator struct {
	rules []*Rule
}

// NewEvaluator creates an evaluator from a set of loaded rules.
func NewEvaluator(rules []*Rule) *Evaluator {
	return &Evaluator{rules: rules}
}

// EvaluateCommand runs a command against all loaded Starlark rules.
// The first definitive result (allow or deny) wins.
// If bypassable rules should be skipped (retry=true), they are skipped.
// Returns nil if no rule has an opinion.
func (e *Evaluator) EvaluateCommand(command string, args []string, retry bool) (result *CheckResult, ruleID string, bypassable bool) {
	for _, rule := range e.rules {
		if rule.Bypassable && retry {
			continue
		}
		r, err := rule.Evaluate(command, args)
		if err != nil {
			// Rule evaluation error — treat as no opinion and continue.
			continue
		}
		if r != nil {
			return r, rule.ID, rule.Bypassable
		}
	}
	return nil, "", false
}

// Rules returns the loaded rules for inspection.
func (e *Evaluator) Rules() []*Rule {
	return e.rules
}

// RuleCount returns the number of loaded rules.
func (e *Evaluator) RuleCount() int {
	return len(e.rules)
}
