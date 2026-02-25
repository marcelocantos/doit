package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Ls struct{}

var _ cap.Capability = (*Ls)(nil)

func (l *Ls) Name() string        { return "ls" }
func (l *Ls) Description() string { return "list directory contents" }
func (l *Ls) Tier() cap.Tier      { return cap.TierRead }
func (l *Ls) Validate(args []string) error { return nil }

func (l *Ls) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "ls", args, stdin, stdout, stderr)
}
