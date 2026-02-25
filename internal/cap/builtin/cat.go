package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Cat struct{}

var _ cap.Capability = (*Cat)(nil)

func (c *Cat) Name() string        { return "cat" }
func (c *Cat) Description() string { return "concatenate and display files" }
func (c *Cat) Tier() cap.Tier      { return cap.TierRead }
func (c *Cat) Validate(args []string) error { return nil }

func (c *Cat) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "cat", args, stdin, stdout, stderr)
}
