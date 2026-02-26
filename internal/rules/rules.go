package rules

import "strings"

// CheckFunc validates arguments for a named capability.
// Returns a non-nil error to block execution.
type CheckFunc func(capName string, args []string) error

// RuleSet holds an ordered list of validation rules. Hardcoded rules run first
// and cannot be removed. Config rules are appended after.
type RuleSet struct {
	hardcoded []CheckFunc
	config    []CheckFunc
}

// NewRuleSet creates a RuleSet with the given hardcoded rules.
func NewRuleSet(hardcoded ...CheckFunc) *RuleSet {
	return &RuleSet{hardcoded: hardcoded}
}

// AddConfig appends a config-driven rule.
func (rs *RuleSet) AddConfig(fn CheckFunc) {
	rs.config = append(rs.config, fn)
}

// Check runs all rules against the given capability name and args.
// Hardcoded rules always run first. When retry is true, config rules are
// skipped (the user has explicitly approved the operation).
func (rs *RuleSet) Check(capName string, args []string, retry bool) error {
	for _, fn := range rs.hardcoded {
		if err := fn(capName, args); err != nil {
			return err
		}
	}
	if retry {
		return nil
	}
	for _, fn := range rs.config {
		if err := fn(capName, args); err != nil {
			return err
		}
	}
	return nil
}

// hasAnyFlag checks whether any element in args matches one of the given flags.
// It handles:
//   - Exact match: "-f" matches "-f"
//   - Combined short flags: "-rf" matches "-r" and "-f"
//   - Short flag with value: "-j4" matches "-j"
//   - Long flag with =: "--flag=value" matches "--flag"
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
