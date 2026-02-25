package builtin

import (
	"context"
	"fmt"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

type Tr struct{}

var _ cap.Capability = (*Tr)(nil)

func (t *Tr) Name() string        { return "tr" }
func (t *Tr) Description() string { return "translate or delete characters" }
func (t *Tr) Tier() cap.Tier      { return cap.TierRead }

func (t *Tr) Validate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("tr requires at least one argument")
	}
	return nil
}

func (t *Tr) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "tr", args, stdin, stdout, stderr)
}
