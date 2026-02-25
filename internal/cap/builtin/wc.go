package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Wc struct{}

var _ cap.Capability = (*Wc)(nil)

func (w *Wc) Name() string        { return "wc" }
func (w *Wc) Description() string { return "word, line, character, and byte count" }
func (w *Wc) Tier() cap.Tier      { return cap.TierRead }
func (w *Wc) Validate(args []string) error { return nil }

func (w *Wc) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "wc", args, stdin, stdout, stderr)
}
