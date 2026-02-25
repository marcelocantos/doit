package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Find struct{}

var _ cap.Capability = (*Find)(nil)

func (f *Find) Name() string        { return "find" }
func (f *Find) Description() string { return "search for files in a directory hierarchy" }
func (f *Find) Tier() cap.Tier      { return cap.TierRead }
func (f *Find) Validate(args []string) error { return nil }

func (f *Find) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "find", args, stdin, stdout, stderr)
}
