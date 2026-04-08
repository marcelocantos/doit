// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package starlark

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
	starlarklib "go.starlark.net/lib/json"
)

// Rule is a Starlark-defined L1 rule loaded from a .star file.
type Rule struct {
	ID          string
	Description string
	Bypassable  bool
	CheckFn     *starlark.Function
	Thread      *starlark.Thread
	Globals     starlark.StringDict
	Tests       []TestCase
}

// TestCase is a test case embedded in a .star rule file.
type TestCase struct {
	Command string
	Args    []string
	Expect  string // "allow", "deny", "escalate"
}

// CheckResult is the result of evaluating a command against a Starlark rule.
type CheckResult struct {
	Decision string // "allow", "deny", "escalate"
	Reason   string
}

// LoadRule loads a single .star rule file. It expects the file to define:
//   - A `check(command, args)` function returning a dict with "decision" and "reason" keys,
//     or None to express no opinion.
//   - A `tests` list of dicts with "command", "args", and "expect" keys.
//   - A `rule_id` string.
//   - An optional `description` string.
//   - An optional `bypassable` bool (default false).
//
// All tests are validated on load. If any test fails, the rule is rejected.
func LoadRule(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule file: %w", err)
	}
	return LoadRuleFromSource(filepath.Base(path), string(data))
}

// LoadRuleFromSource loads a rule from Starlark source code.
func LoadRuleFromSource(filename, source string) (*Rule, error) {
	thread := &starlark.Thread{Name: filename}
	predeclared := starlark.StringDict{
		"json": starlarklib.Module,
	}

	globals, err := starlark.ExecFile(thread, filename, source, predeclared)
	if err != nil {
		return nil, fmt.Errorf("exec starlark: %w", err)
	}

	// Extract rule_id.
	ruleIDVal, ok := globals["rule_id"]
	if !ok {
		return nil, fmt.Errorf("missing rule_id global")
	}
	ruleID, ok := starlark.AsString(ruleIDVal)
	if !ok {
		return nil, fmt.Errorf("rule_id must be a string")
	}

	// Extract check function.
	checkVal, ok := globals["check"]
	if !ok {
		return nil, fmt.Errorf("missing check function")
	}
	checkFn, ok := checkVal.(*starlark.Function)
	if !ok {
		return nil, fmt.Errorf("check must be a function")
	}
	if checkFn.NumParams() != 2 {
		return nil, fmt.Errorf("check function must take 2 parameters (command, args)")
	}

	// Extract optional description.
	var description string
	if descVal, ok := globals["description"]; ok {
		description, _ = starlark.AsString(descVal)
	}

	// Extract optional bypassable flag.
	var bypassable bool
	if bVal, ok := globals["bypassable"]; ok {
		bypassable = bool(bVal.Truth())
	}

	// Extract tests.
	testsVal, ok := globals["tests"]
	if !ok {
		return nil, fmt.Errorf("missing tests list")
	}
	testsList, ok := testsVal.(*starlark.List)
	if !ok {
		return nil, fmt.Errorf("tests must be a list")
	}

	tests, err := parseTests(testsList)
	if err != nil {
		return nil, fmt.Errorf("parse tests: %w", err)
	}

	if len(tests) == 0 {
		return nil, fmt.Errorf("tests list must not be empty")
	}

	rule := &Rule{
		ID:          ruleID,
		Description: description,
		Bypassable:  bypassable,
		CheckFn:     checkFn,
		Thread:      thread,
		Globals:     globals,
		Tests:       tests,
	}

	// Validate all tests.
	if err := rule.ValidateTests(); err != nil {
		return nil, fmt.Errorf("test validation failed: %w", err)
	}

	return rule, nil
}

// LoadDir loads all .star files from a directory. Returns rules that pass
// test validation. Returns an error if any rule fails to load or validate.
func LoadDir(dir string) ([]*Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read rules dir: %w", err)
	}

	var rules []*Rule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".star") {
			continue
		}
		rule, err := LoadRule(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", entry.Name(), err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ValidateTests runs all embedded test cases against the rule's check function.
func (r *Rule) ValidateTests() error {
	for i, tc := range r.Tests {
		result, err := r.Evaluate(tc.Command, tc.Args)
		if err != nil {
			return fmt.Errorf("test %d (%s %s): %w", i, tc.Command, strings.Join(tc.Args, " "), err)
		}
		got := "escalate" // nil result means no opinion = escalate
		if result != nil {
			got = result.Decision
		}
		if got != tc.Expect {
			return fmt.Errorf("test %d (%s %s): got %q, want %q", i, tc.Command, strings.Join(tc.Args, " "), got, tc.Expect)
		}
	}
	return nil
}

// Evaluate runs the check function against a command and args.
// Returns nil if the rule has no opinion (check returned None).
func (r *Rule) Evaluate(command string, args []string) (*CheckResult, error) {
	argsList := starlark.NewList(nil)
	for _, a := range args {
		if err := argsList.Append(starlark.String(a)); err != nil {
			return nil, err
		}
	}

	result, err := starlark.Call(r.Thread, r.CheckFn, starlark.Tuple{
		starlark.String(command),
		argsList,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("call check: %w", err)
	}

	if result == starlark.None {
		return nil, nil
	}

	dict, ok := result.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("check must return a dict or None, got %s", result.Type())
	}

	decisionVal, found, err := dict.Get(starlark.String("decision"))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("check result missing 'decision' key")
	}
	decision, ok := starlark.AsString(decisionVal)
	if !ok {
		return nil, fmt.Errorf("decision must be a string")
	}
	if decision != "allow" && decision != "deny" && decision != "escalate" {
		return nil, fmt.Errorf("invalid decision %q (must be allow/deny/escalate)", decision)
	}

	var reason string
	reasonVal, found, err := dict.Get(starlark.String("reason"))
	if err != nil {
		return nil, err
	}
	if found {
		reason, _ = starlark.AsString(reasonVal)
	}

	return &CheckResult{
		Decision: decision,
		Reason:   reason,
	}, nil
}

func parseTests(list *starlark.List) ([]TestCase, error) {
	var tests []TestCase
	iter := list.Iterate()
	defer iter.Done()
	var val starlark.Value
	for iter.Next(&val) {
		dict, ok := val.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("each test must be a dict, got %s", val.Type())
		}

		cmdVal, found, err := dict.Get(starlark.String("command"))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("test missing 'command' key")
		}
		cmd, ok := starlark.AsString(cmdVal)
		if !ok {
			return nil, fmt.Errorf("test command must be a string")
		}

		argsVal, found, err := dict.Get(starlark.String("args"))
		if err != nil {
			return nil, err
		}
		var args []string
		if found {
			argsList, ok := argsVal.(*starlark.List)
			if !ok {
				return nil, fmt.Errorf("test args must be a list")
			}
			argsIter := argsList.Iterate()
			defer argsIter.Done()
			var a starlark.Value
			for argsIter.Next(&a) {
				s, ok := starlark.AsString(a)
				if !ok {
					return nil, fmt.Errorf("test arg must be a string")
				}
				args = append(args, s)
			}
		}

		expectVal, found, err := dict.Get(starlark.String("expect"))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("test missing 'expect' key")
		}
		expect, ok := starlark.AsString(expectVal)
		if !ok {
			return nil, fmt.Errorf("test expect must be a string")
		}

		tests = append(tests, TestCase{
			Command: cmd,
			Args:    args,
			Expect:  expect,
		})
	}
	return tests, nil
}
