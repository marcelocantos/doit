package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Tail struct{}

var _ cap.Capability = (*Tail)(nil)

func (t *Tail) Name() string        { return "tail" }
func (t *Tail) Description() string { return "output the last part of files or stdin" }
func (t *Tail) Tier() cap.Tier      { return cap.TierRead }
func (t *Tail) Validate(args []string) error { return nil }

func (t *Tail) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "tail", args, stdin, stdout, stderr)
}
