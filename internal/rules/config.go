package rules

import "fmt"

// CapRuleConfig represents one capability's rules from YAML config.
type CapRuleConfig struct {
	RejectFlags []string                `yaml:"reject_flags"`
	Subcommands map[string]SubRuleConfig `yaml:"subcommands"`
}

// SubRuleConfig represents rules for a specific subcommand.
type SubRuleConfig struct {
	RejectFlags []string `yaml:"reject_flags"`
}

// CompileCapRule turns a single capability's config into CheckFuncs.
func CompileCapRule(capName string, cfg CapRuleConfig) []CheckFunc {
	var fns []CheckFunc

	// Top-level reject_flags for the whole capability.
	if len(cfg.RejectFlags) > 0 {
		flags := cfg.RejectFlags
		name := capName
		fns = append(fns, func(cn string, args []string) error {
			if cn != name {
				return nil
			}
			if hasAnyFlag(args, flags...) {
				return fmt.Errorf("rejected flag (config rule). Ask the user for explicit permission, then retry with: doit --retry %s ...", name)
			}
			return nil
		})
	}

	// Subcommand-level rules.
	for subcmd, subRule := range cfg.Subcommands {
		if len(subRule.RejectFlags) > 0 {
			flags := subRule.RejectFlags
			name := capName
			sub := subcmd
			fns = append(fns, func(cn string, args []string) error {
				if cn != name || len(args) == 0 || args[0] != sub {
					return nil
				}
				if hasAnyFlag(args[1:], flags...) {
					return fmt.Errorf("%s: rejected flag (config rule). Ask the user for explicit permission, then retry with: doit --retry %s ...", sub, name)
				}
				return nil
			})
		}
	}

	return fns
}
