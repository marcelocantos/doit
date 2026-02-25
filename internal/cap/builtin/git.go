package builtin

import (
	"context"
	"fmt"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Git struct{}

var _ cap.Capability = (*Git)(nil)

func (g *Git) Name() string        { return "git" }
func (g *Git) Description() string { return "git version control (tier varies by subcommand)" }
func (g *Git) Tier() cap.Tier      { return cap.TierRead } // base tier; effective tier checked at runtime

func (g *Git) Validate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("git requires a subcommand")
	}
	return nil
}

func (g *Git) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	// Check effective tier based on subcommand.
	// The registry is accessed via the context to check tier permissions.
	effectiveTier := gitSubcommandTier(args[0])
	if reg, ok := cap.RegistryFromContext(ctx); ok {
		if err := reg.CheckTier(effectiveTier); err != nil {
			return fmt.Errorf("git %s: %w", args[0], err)
		}
	}
	return runExternal(ctx, "git", args, stdin, stdout, stderr)
}

func gitSubcommandTier(subcmd string) cap.Tier {
	switch subcmd {
	case "status", "log", "diff", "show", "branch", "tag", "remote",
		"rev-parse", "blame", "ls-files", "ls-tree", "shortlog",
		"describe", "config", "reflog", "stash": // stash list is read, but stash push/pop is write
		return cap.TierRead
	case "add", "commit", "checkout", "switch", "merge", "rebase",
		"cherry-pick", "fetch", "pull", "mv", "rm":
		return cap.TierWrite
	case "push", "reset", "clean", "gc", "filter-branch":
		return cap.TierDangerous
	default:
		return cap.TierDangerous // unknown subcommands default to dangerous
	}
}
