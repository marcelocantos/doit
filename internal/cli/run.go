package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/marcelocantos/doit/internal/audit"
	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/cap/builtin"
)

// RunDirect executes a single capability directly: doit <cap> [args...]
func RunDirect(ctx context.Context, reg *cap.Registry, logger *audit.Logger, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "doit: missing capability name")
		return 1
	}

	name := args[0]
	capArgs := args[1:]

	c, err := reg.Lookup(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "doit: %v\n", err)
		return 1
	}

	if err := reg.CheckTier(c.Tier()); err != nil {
		fmt.Fprintf(os.Stderr, "doit: %s: %v\n", name, err)
		return 1
	}

	if err := c.Validate(capArgs); err != nil {
		fmt.Fprintf(os.Stderr, "doit: %s: %v\n", name, err)
		return 1
	}

	ctx = cap.NewContext(ctx, reg)
	start := time.Now()
	err = c.Run(ctx, capArgs, os.Stdin, os.Stdout, os.Stderr)
	duration := time.Since(start)

	exitCode, errMsg := resolveError(err)

	logAudit(logger, "direct:"+name+" "+strings.Join(capArgs, " "), []string{name}, []string{c.Tier().String()}, exitCode, errMsg, duration)

	return exitCode
}

// RunPipe executes a pipeline: doit pipe <args...>
func RunPipe(ctx context.Context, reg *cap.Registry, logger *audit.Logger, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "doit pipe: empty pipeline")
		return 1
	}

	p, err := parsePipeline(args, reg)
	if err != nil {
		fmt.Fprintf(stderr, "doit pipe: %v\n", err)
		return 1
	}

	if err := validatePipeline(p, reg); err != nil {
		fmt.Fprintf(stderr, "doit pipe: %v\n", err)
		return 1
	}

	ctx = cap.NewContext(ctx, reg)
	start := time.Now()
	err = executePipeline(ctx, p, reg, stdin, stdout, stderr)
	duration := time.Since(start)

	exitCode, errMsg := resolveError(err)

	// Build audit info.
	pipelineStr := strings.Join(args, " ")
	var segments, tiers []string
	for _, seg := range p.Segments {
		segments = append(segments, seg.CapName)
		if c, err := reg.Lookup(seg.CapName); err == nil {
			tiers = append(tiers, c.Tier().String())
		}
	}

	logAudit(logger, pipelineStr, segments, tiers, exitCode, errMsg, duration)

	return exitCode
}

// resolveError extracts an exit code from an error. For ExitError (command
// exited with non-zero status), the code is propagated silently — the
// command's own stderr output is sufficient. For other errors, doit reports
// them on stderr.
func resolveError(err error) (exitCode int, errMsg string) {
	if err == nil {
		return 0, ""
	}
	var exitErr *builtin.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code, ""
	}
	fmt.Fprintf(os.Stderr, "doit: %v\n", err)
	return 2, err.Error()
}

func logAudit(logger *audit.Logger, pipeline string, segments, tiers []string, exitCode int, errMsg string, duration time.Duration) {
	if logger == nil {
		return
	}
	cwd, _ := os.Getwd()
	// Best-effort audit logging — don't fail the command if audit fails.
	_ = logger.Log(pipeline, segments, tiers, exitCode, errMsg, duration, cwd)
}
