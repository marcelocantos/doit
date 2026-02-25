package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Tee struct{}

var _ cap.Capability = (*Tee)(nil)

func (t *Tee) Name() string        { return "tee" }
func (t *Tee) Description() string { return "duplicate stdin to stdout and files" }
func (t *Tee) Tier() cap.Tier      { return cap.TierWrite }
func (t *Tee) Validate(args []string) error { return nil }

func (t *Tee) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "tee", args, stdin, stdout, stderr)
}
