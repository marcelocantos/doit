package rules

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Hardcoded returns the built-in safety rules that are always enforced
// regardless of configuration or --retry. These represent doit's core safety
// promise and block permanently catastrophic operations.
func Hardcoded() []CheckFunc {
	return []CheckFunc{
		checkRmCatastrophic,
	}
}

// CheckGitCheckoutAll blocks "git checkout ." and "git checkout -- ."
// which silently discard all uncommitted changes. This is a default config
// rule (not hardcoded) so it can be bypassed with --retry.
func CheckGitCheckoutAll(capName string, args []string) error {
	if capName != "git" || len(args) == 0 || args[0] != "checkout" {
		return nil
	}
	for i, arg := range args[1:] {
		cleaned := filepath.Clean(arg)
		if cleaned == "." {
			return fmt.Errorf("checkout: refusing to discard all changes (config rule). Ask the user for explicit permission, then retry with: doit --retry git checkout .")
		}
		if arg == "--" && i+1 < len(args[1:]) {
			next := filepath.Clean(args[i+2])
			if next == "." {
				return fmt.Errorf("checkout: refusing to discard all changes (config rule). Ask the user for explicit permission, then retry with: doit --retry git checkout .")
			}
		}
	}
	return nil
}

// checkRmCatastrophic blocks recursive removal of root, home, or current directory.
func checkRmCatastrophic(capName string, args []string) error {
	if capName != "rm" {
		return nil
	}
	if !hasAnyFlag(args, "-r", "-R") {
		return nil
	}
	for _, arg := range args {
		if arg == "" || arg[0] == '-' {
			continue
		}
		cleaned := filepath.Clean(arg)
		if cleaned == "/" || cleaned == "." || cleaned == ".." {
			return fmt.Errorf("refusing to recursively remove %q. This operation is permanently blocked", arg)
		}
		if arg == "~" || strings.HasPrefix(arg, "~/") {
			return fmt.Errorf("refusing to recursively remove %q. This operation is permanently blocked", arg)
		}
	}
	return nil
}
