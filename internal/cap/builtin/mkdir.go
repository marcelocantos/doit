package builtin

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Mkdir struct{}

var _ cap.Capability = (*Mkdir)(nil)

func (m *Mkdir) Name() string        { return "mkdir" }
func (m *Mkdir) Description() string { return "create directories" }
func (m *Mkdir) Tier() cap.Tier      { return cap.TierWrite }
func (m *Mkdir) Validate(args []string) error { return nil }

func (m *Mkdir) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "mkdir", args, stdin, stdout, stderr)
}
