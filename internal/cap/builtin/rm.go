package builtin

import (
	"context"
	"fmt"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Rm struct{}

var _ cap.Capability = (*Rm)(nil)

func (r *Rm) Name() string        { return "rm" }
func (r *Rm) Description() string { return "remove files or directories (dangerous)" }
func (r *Rm) Tier() cap.Tier      { return cap.TierDangerous }

func (r *Rm) Validate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("rm requires at least one argument")
	}
	return nil
}

func (r *Rm) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "rm", args, stdin, stdout, stderr)
}
