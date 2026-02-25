package builtin

import (
	"context"
	"fmt"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Chmod struct{}

var _ cap.Capability = (*Chmod)(nil)

func (c *Chmod) Name() string        { return "chmod" }
func (c *Chmod) Description() string { return "change file permissions (dangerous)" }
func (c *Chmod) Tier() cap.Tier      { return cap.TierDangerous }

func (c *Chmod) Validate(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("chmod requires a mode and at least one file")
	}
	return nil
}

func (c *Chmod) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "chmod", args, stdin, stdout, stderr)
}
