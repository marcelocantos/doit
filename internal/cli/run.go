package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/marcelocantos/doit/internal/audit"
	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/cap/builtin"
	"github.com/marcelocantos/doit/internal/pipeline"
	"github.com/marcelocantos/doit/internal/policy"
)

// RunCommand executes a command (single capability, pipeline, or compound).
// All invocations go through ParseCommand, which handles the degenerate
// single-segment case. When retry is true, config rules are bypassed.
func RunCommand(ctx context.Context, reg *cap.Registry, logger *audit.Logger, args []string, stdin io.Reader, stdout, stderr io.Writer, retry bool, cwd string, env map[string]string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "doit: missing command")
		return 1
	}

	cmd, err := pipeline.ParseCommand(args, reg)
	if err != nil {
		fmt.Fprintf(stderr, "doit: %v\n", err)
		return 1
	}

	if err := pipeline.ValidateCommand(cmd, reg, retry); err != nil {
		fmt.Fprintf(stderr, "doit: %v\n", err)
		return 1
	}

	ctx = cap.NewContext(ctx, reg)
	if cwd != "" {
		ctx = cap.NewCwdContext(ctx, cwd)
	}
	if env != nil {
		ctx = cap.NewEnvContext(ctx, env)
	}

	start := time.Now()
	err = pipeline.ExecuteCommand(ctx, cmd, reg, stdin, stdout, stderr)
	duration := time.Since(start)

	exitCode, errMsg := resolveError(err, stderr)

	// Build audit info from all segments.
	pipelineStr := strings.Join(args, " ")
	var segments, tiers []string
	for _, step := range cmd.Steps {
		for _, seg := range step.Pipeline.Segments {
			segments = append(segments, seg.CapName)
			if c, err := reg.Lookup(seg.CapName); err == nil {
				tiers = append(tiers, c.Tier().String())
			}
		}
	}

	logAudit(ctx, logger, pipelineStr, segments, tiers, exitCode, errMsg, duration, retry, cwd)

	return exitCode
}

// resolveError extracts an exit code from an error. For ExitError (command
// exited with non-zero status), the code is propagated silently — the
// command's own stderr output is sufficient. For other errors, doit reports
// them on stderr.
func resolveError(err error, stderr io.Writer) (exitCode int, errMsg string) {
	if err == nil {
		return 0, ""
	}
	var exitErr *builtin.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code, ""
	}
	fmt.Fprintf(stderr, "doit: %v\n", err)
	return 2, err.Error()
}

func logAudit(ctx context.Context, logger *audit.Logger, pipelineStr string, segments, tiers []string, exitCode int, errMsg string, duration time.Duration, retry bool, cwd string) {
	if logger == nil {
		return
	}
	var opts *audit.LogOptions
	if info := policy.EvalFromContext(ctx); info != nil {
		opts = &audit.LogOptions{
			PolicyLevel:   info.Level,
			PolicyResult:  info.Decision,
			PolicyRuleID:  info.RuleID,
			Justification: info.Justification,
			SafetyArg:     info.SafetyArg,
		}
	}
	// Best-effort audit logging — don't fail the command if audit fails.
	_ = logger.Log(pipelineStr, segments, tiers, exitCode, errMsg, duration, cwd, retry, opts)
}
