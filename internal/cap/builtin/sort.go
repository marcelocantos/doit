package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Sort struct{}

var _ cap.Capability = (*Sort)(nil)

func (s *Sort) Name() string        { return "sort" }
func (s *Sort) Description() string { return "sort lines of text" }
func (s *Sort) Tier() cap.Tier      { return cap.TierRead }
func (s *Sort) Validate(args []string) error { return nil }

func (s *Sort) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "sort", args, stdin, stdout, stderr)
}
