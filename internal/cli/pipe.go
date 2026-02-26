package cli

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/pipeline"
)

func parseCommand(args []string, reg *cap.Registry) (*pipeline.Command, error) {
	return pipeline.ParseCommand(args, reg)
}

func validateCommand(cmd *pipeline.Command, reg *cap.Registry, retry bool) error {
	return pipeline.ValidateCommand(cmd, reg, retry)
}

func executeCommand(ctx context.Context, cmd *pipeline.Command, reg *cap.Registry, stdin io.Reader, stdout, stderr io.Writer) error {
	return pipeline.ExecuteCommand(ctx, cmd, reg, stdin, stdout, stderr)
}
