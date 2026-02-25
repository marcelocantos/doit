package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Uniq struct{}

var _ cap.Capability = (*Uniq)(nil)

func (u *Uniq) Name() string        { return "uniq" }
func (u *Uniq) Description() string { return "report or omit repeated lines" }
func (u *Uniq) Tier() cap.Tier      { return cap.TierRead }
func (u *Uniq) Validate(args []string) error { return nil }

func (u *Uniq) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "uniq", args, stdin, stdout, stderr)
}
