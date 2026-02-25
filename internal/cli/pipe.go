package cli

import (
	"context"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/pipeline"
)

func parsePipeline(args []string, reg *cap.Registry) (*pipeline.Pipeline, error) {
	return pipeline.Parse(args, reg)
}

func validatePipeline(p *pipeline.Pipeline, reg *cap.Registry) error {
	return pipeline.Validate(p, reg)
}

func executePipeline(ctx context.Context, p *pipeline.Pipeline, reg *cap.Registry, stdin io.Reader, stdout, stderr io.Writer) error {
	return pipeline.Execute(ctx, p, reg, stdin, stdout, stderr)
}
