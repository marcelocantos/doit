package builtin

import (
	"context"
	"fmt"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type GoCmd struct{}

var _ cap.Capability = (*GoCmd)(nil)

func (g *GoCmd) Name() string        { return "go" }
func (g *GoCmd) Description() string { return "go build, test, vet, and other go commands (tier varies by subcommand)" }
func (g *GoCmd) Tier() cap.Tier      { return cap.TierBuild } // base tier; effective tier checked at runtime

func (g *GoCmd) Validate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("go requires a subcommand")
	}
	return nil
}

func (g *GoCmd) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	effectiveTier := goSubcommandTier(args[0])
	if reg, ok := cap.RegistryFromContext(ctx); ok {
		if err := reg.CheckTier(effectiveTier); err != nil {
			return fmt.Errorf("go %s: %w", args[0], err)
		}
	}
	return runExternal(ctx, "go", args, stdin, stdout, stderr)
}

func goSubcommandTier(subcmd string) cap.Tier {
	switch subcmd {
	case "build", "test", "vet", "mod", "list", "fmt", "doc",
		"env", "version", "clean", "work":
		return cap.TierBuild
	case "run", "generate", "install", "tool", "get":
		return cap.TierDangerous
	default:
		return cap.TierDangerous
	}
}
