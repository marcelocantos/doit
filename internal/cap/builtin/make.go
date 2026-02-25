package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Make struct{}

var _ cap.Capability = (*Make)(nil)

func (m *Make) Name() string        { return "make" }
func (m *Make) Description() string { return "build targets using make" }
func (m *Make) Tier() cap.Tier      { return cap.TierBuild }
func (m *Make) Validate(args []string) error { return nil }

func (m *Make) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "make", args, stdin, stdout, stderr)
}
