package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Head struct{}

var _ cap.Capability = (*Head)(nil)

func (h *Head) Name() string        { return "head" }
func (h *Head) Description() string { return "output the first part of files or stdin" }
func (h *Head) Tier() cap.Tier      { return cap.TierRead }
func (h *Head) Validate(args []string) error { return nil }

func (h *Head) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "head", args, stdin, stdout, stderr)
}
