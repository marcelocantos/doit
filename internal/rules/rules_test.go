package rules

import (
	"fmt"
	"testing"
)

func TestHasAnyFlag(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		flags []string
		want  bool
	}{
		// Exact match.
		{"exact short", []string{"-f"}, []string{"-f"}, true},
		{"exact long", []string{"--force"}, []string{"--force"}, true},
		{"no match", []string{"-v"}, []string{"-f"}, false},

		// Combined short flags.
		{"combined rf matches r", []string{"-rf"}, []string{"-r"}, true},
		{"combined rf matches f", []string{"-rf"}, []string{"-f"}, true},
		{"combined rf no match x", []string{"-rf"}, []string{"-x"}, false},

		// Short flag with value (e.g., -j4).
		{"j4 matches j", []string{"-j4"}, []string{"-j"}, true},
		{"j8 matches j", []string{"-j8"}, []string{"-j"}, true},
		{"j matches j", []string{"-j"}, []string{"-j"}, true},
		{"j4 no match k", []string{"-j4"}, []string{"-k"}, false},

		// Long flag with =.
		{"force=yes matches force", []string{"--force=yes"}, []string{"--force"}, true},
		{"initial-branch=master", []string{"--initial-branch=master"}, []string{"--initial-branch"}, true},
		{"force no equals", []string{"--force"}, []string{"--force"}, true},
		{"no match long", []string{"--verbose"}, []string{"--force"}, false},

		// Non-flag args should be skipped.
		{"non-flag path", []string{"/tmp/file"}, []string{"-f"}, false},
		{"non-flag word", []string{"hello"}, []string{"-f"}, false},
		{"empty arg", []string{""}, []string{"-f"}, false},

		// Mixed args.
		{"mixed", []string{"file.txt", "-r", "dir/"}, []string{"-r"}, true},
		{"mixed no match", []string{"file.txt", "-r", "dir/"}, []string{"-f"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasAnyFlag(tt.args, tt.flags...)
			if got != tt.want {
				t.Errorf("hasAnyFlag(%v, %v) = %v, want %v",
					tt.args, tt.flags, got, tt.want)
			}
		})
	}
}

func TestRuleSetCheck(t *testing.T) {
	errHardcoded := fmt.Errorf("hardcoded block")
	errConfig := fmt.Errorf("config block")

	t.Run("hardcoded fires first", func(t *testing.T) {
		rs := NewRuleSet(func(cap string, args []string) error {
			if cap == "rm" {
				return errHardcoded
			}
			return nil
		})
		rs.AddConfig(func(cap string, args []string) error {
			if cap == "rm" {
				return errConfig
			}
			return nil
		})

		err := rs.Check("rm", []string{"-rf", "/"}, false)
		if err != errHardcoded {
			t.Errorf("expected hardcoded error, got %v", err)
		}
	})

	t.Run("config fires when hardcoded passes", func(t *testing.T) {
		rs := NewRuleSet(func(cap string, args []string) error {
			return nil // hardcoded passes
		})
		rs.AddConfig(func(cap string, args []string) error {
			if cap == "make" {
				return errConfig
			}
			return nil
		})

		err := rs.Check("make", []string{"-j4"}, false)
		if err != errConfig {
			t.Errorf("expected config error, got %v", err)
		}
	})

	t.Run("all pass", func(t *testing.T) {
		rs := NewRuleSet(func(cap string, args []string) error { return nil })
		rs.AddConfig(func(cap string, args []string) error { return nil })

		err := rs.Check("grep", []string{"-r", "TODO"}, false)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("nil ruleset methods", func(t *testing.T) {
		rs := NewRuleSet()
		err := rs.Check("grep", []string{"-r", "TODO"}, false)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("retry skips config rules", func(t *testing.T) {
		rs := NewRuleSet(func(cap string, args []string) error { return nil })
		rs.AddConfig(func(cap string, args []string) error {
			return errConfig
		})

		err := rs.Check("make", []string{"-j4"}, true)
		if err != nil {
			t.Errorf("expected nil with retry=true, got %v", err)
		}
	})

	t.Run("retry does not skip hardcoded", func(t *testing.T) {
		rs := NewRuleSet(func(cap string, args []string) error {
			if cap == "rm" {
				return errHardcoded
			}
			return nil
		})
		rs.AddConfig(func(cap string, args []string) error {
			return errConfig
		})

		err := rs.Check("rm", []string{"-rf", "/"}, true)
		if err != errHardcoded {
			t.Errorf("expected hardcoded error even with retry, got %v", err)
		}
	})
}
