package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Cp struct{}

var _ cap.Capability = (*Cp)(nil)

func (c *Cp) Name() string        { return "cp" }
func (c *Cp) Description() string { return "copy files and directories" }
func (c *Cp) Tier() cap.Tier      { return cap.TierWrite }
func (c *Cp) Validate(args []string) error { return nil }

func (c *Cp) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "cp", args, stdin, stdout, stderr)
}
