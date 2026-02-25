package builtin

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/marcelocantos/doit/internal/cap"
)

type Make struct{}

var _ cap.Capability = (*Make)(nil)

func (m *Make) Name() string        { return "make" }
func (m *Make) Description() string { return "build targets using make" }
func (m *Make) Tier() cap.Tier      { return cap.TierBuild }

func (m *Make) Validate(args []string) error {
	for _, arg := range args {
		switch {
		case arg == "-f" || arg == "--file" || arg == "--makefile":
			return fmt.Errorf("make %s is not allowed (must use the project's Makefile)", arg)
		case arg == "-C" || arg == "--directory":
			return fmt.Errorf("make %s is not allowed (must run in the current directory)", arg)
		case strings.HasPrefix(arg, "-f=") || strings.HasPrefix(arg, "--file=") || strings.HasPrefix(arg, "--makefile="):
			return fmt.Errorf("make custom Makefile path is not allowed (must use the project's Makefile)")
		case strings.HasPrefix(arg, "-C=") || strings.HasPrefix(arg, "--directory="):
			return fmt.Errorf("make custom directory is not allowed (must run in the current directory)")
		}
	}
	return nil
}

func (m *Make) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runExternal(ctx, "make", args, stdin, stdout, stderr)
}
