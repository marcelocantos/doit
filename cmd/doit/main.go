package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/marcelocantos/doit/internal/audit"
	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/cap/builtin"
	"github.com/marcelocantos/doit/internal/cli"
	"github.com/marcelocantos/doit/internal/config"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		cli.RunHelp(nil, os.Stderr, nil)
		return 1
	}

	// Load config.
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "doit: config: %v\n", err)
		return 1
	}

	// Set up registry.
	reg := cap.NewRegistry()
	builtin.RegisterAll(reg)
	cfg.ApplyTiers(reg)
	cfg.ApplyRules(reg)

	// Set up audit logger.
	logger, err := audit.NewLogger(cfg.Audit.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "doit: audit: %v\n", err)
		// Continue without audit logging.
		logger = nil
	}

	// Set up context with cancellation on interrupt.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	switch os.Args[1] {
	case "--pipe":
		pipeArgs := os.Args[2:]
		retry := false
		if len(pipeArgs) > 0 && pipeArgs[0] == "--retry" {
			retry = true
			pipeArgs = pipeArgs[1:]
		}
		return cli.RunPipe(ctx, reg, logger, pipeArgs, os.Stdin, os.Stdout, os.Stderr, retry)
	case "--retry":
		return cli.RunDirect(ctx, reg, logger, os.Args[2:], true)
	case "--list":
		tierFilter := ""
		args := os.Args[2:]
		for i := 0; i < len(args); i++ {
			if args[i] == "--tier" && i+1 < len(args) {
				tierFilter = args[i+1]
				i++
			}
		}
		return cli.RunList(reg, os.Stdout, tierFilter)
	case "--help":
		return cli.RunHelp(reg, os.Stdout, os.Args[2:])
	case "--help-agent":
		return cli.RunHelpAgent(reg, os.Stdout)
	case "--audit":
		return cli.RunAudit(os.Stdout, cfg.Audit.Path, os.Args[2:])
	case "--version":
		fmt.Printf("doit %s\n", version)
		return 0
	default:
		// Everything else is a direct capability invocation.
		return cli.RunDirect(ctx, reg, logger, os.Args[1:], false)
	}
}
