package pipeline

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/marcelocantos/doit/internal/cap"
)

// ExecuteCommand runs a compound command, evaluating each pipeline step
// sequentially and applying the compound operator logic.
// Returns the error from the last-executed pipeline (or nil).
func ExecuteCommand(ctx context.Context, cmd *Command, reg *cap.Registry, stdin io.Reader, stdout, stderr io.Writer) error {
	var lastErr error

	for i, step := range cmd.Steps {
		if i > 0 {
			prevOp := cmd.Steps[i-1].Op
			switch Operator(prevOp) {
			case Operator(OpAndThen):
				if lastErr != nil {
					continue
				}
			case Operator(OpOrElse):
				if lastErr == nil {
					continue
				}
			case Operator(OpSequential):
				// Always run.
			}
		}

		lastErr = Execute(ctx, step.Pipeline, reg, stdin, stdout, stderr)
	}

	return lastErr
}

// Execute runs a validated pipeline, streaming data between segments.
// Each segment runs in its own goroutine, connected by io.Pipe().
func Execute(ctx context.Context, p *Pipeline, reg *cap.Registry, stdin io.Reader, stdout, stderr io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle stdin redirect.
	if p.RedirectIn != "" {
		f, err := os.Open(p.RedirectIn)
		if err != nil {
			return err
		}
		defer f.Close()
		stdin = f
	}

	// Handle stdout redirect.
	if p.RedirectOut != "" {
		f, err := os.Create(p.RedirectOut)
		if err != nil {
			return err
		}
		defer f.Close()
		stdout = f
	}

	n := len(p.Segments)
	if n == 1 {
		// Single segment: no pipes needed.
		c, err := reg.Lookup(p.Segments[0].CapName)
		if err != nil {
			return fmt.Errorf("segment 0: %w", err)
		}
		return c.Run(ctx, p.Segments[0].Args, stdin, stdout, stderr)
	}

	// Create N-1 pipes between N segments.
	type pipeEnd struct {
		r *io.PipeReader
		w *io.PipeWriter
	}
	pipes := make([]pipeEnd, n-1)
	for i := range pipes {
		pipes[i].r, pipes[i].w = io.Pipe()
	}

	// Run all segments concurrently.
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)

	setErr := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
		mu.Unlock()
	}

	for i, seg := range p.Segments {
		wg.Add(1)
		go func(i int, seg Segment) {
			defer wg.Done()

			c, err := reg.Lookup(seg.CapName)
			if err != nil {
				setErr(fmt.Errorf("segment %d: %w", i, err))
				return
			}

			var segIn io.Reader
			var segOut io.Writer

			if i == 0 {
				segIn = stdin
			} else {
				segIn = pipes[i-1].r
			}

			if i == n-1 {
				segOut = stdout
			} else {
				segOut = pipes[i].w
			}

			err = c.Run(ctx, seg.Args, segIn, segOut, stderr)
			setErr(err)

			// Close pipe writer so downstream sees EOF.
			if i < n-1 {
				if err != nil {
					pipes[i].w.CloseWithError(err)
				} else {
					pipes[i].w.Close()
				}
			}

			// Close pipe reader when done reading.
			if i > 0 {
				pipes[i-1].r.Close()
			}
		}(i, seg)
	}

	wg.Wait()
	return firstErr
}
