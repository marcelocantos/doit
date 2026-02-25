package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Mv struct{}

var _ cap.Capability = (*Mv)(nil)

func (m *Mv) Name() string        { return "mv" }
func (m *Mv) Description() string { return "move or rename files and directories" }
func (m *Mv) Tier() cap.Tier      { return cap.TierWrite }
func (m *Mv) Validate(args []string) error { return nil }

func (m *Mv) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "mv", args, stdin, stdout, stderr)
}
