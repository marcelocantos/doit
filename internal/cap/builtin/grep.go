package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Grep struct{}

var _ cap.Capability = (*Grep)(nil)

func (g *Grep) Name() string        { return "grep" }
func (g *Grep) Description() string { return "search file contents for patterns" }
func (g *Grep) Tier() cap.Tier      { return cap.TierRead }

func (g *Grep) Validate(args []string) error {
	// grep is flexible with args; let the real grep validate.
	return nil
}

func (g *Grep) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "grep", args, stdin, stdout, stderr)
}
