package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type GoCmd struct{}

var _ cap.Capability = (*GoCmd)(nil)

func (g *GoCmd) Name() string        { return "go" }
func (g *GoCmd) Description() string { return "go build, test, vet, and other go commands" }
func (g *GoCmd) Tier() cap.Tier      { return cap.TierBuild }
func (g *GoCmd) Validate(args []string) error { return nil }

func (g *GoCmd) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "go", args, stdin, stdout, stderr)
}
