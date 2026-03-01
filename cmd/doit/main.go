package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"strings"

	"github.com/marcelocantos/doit/internal/audit"
	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/cap/builtin"
	"github.com/marcelocantos/doit/internal/cli"
	"github.com/marcelocantos/doit/internal/client"
	"github.com/marcelocantos/doit/internal/config"
	"github.com/marcelocantos/doit/internal/daemon"
	"github.com/marcelocantos/doit/internal/ipc"
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
	case "--daemon":
		return runDaemon(ctx, cfg, reg, logger)
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
		return runCommand(ctx, cfg, reg, logger, os.Args[1:])
	}
}

// runDaemon starts the daemon server. It blocks until the context is
// cancelled or the idle timeout fires.
func runDaemon(ctx context.Context, cfg *config.Config, reg *cap.Registry, logger *audit.Logger) int {
	srv := daemon.New(cfg, reg, logger, cfg.Daemon.IdleTimeoutDuration())
	if err := srv.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "doit daemon: %v\n", err)
		return 1
	}
	return 0
}

// runCommand routes execution through the daemon client when available,
// falling back to in-process execution.
func runCommand(ctx context.Context, cfg *config.Config, reg *cap.Registry, logger *audit.Logger, args []string) int {
	retry := false
	approved := ""
	for len(args) > 0 {
		if args[0] == "--retry" {
			retry = true
			args = args[1:]
		} else if args[0] == "--approved" {
			if len(args) < 2 {
				fmt.Fprintf(os.Stderr, "doit: --approved requires a token argument\n")
				return 1
			}
			approved = args[1]
			args = args[2:]
		} else {
			break
		}
	}

	cwd, _ := os.Getwd()

	if shouldUseDaemon(cfg) {
		selfPath, _ := os.Executable()
		conn, err := client.ConnectOrSpawn(ctx, selfPath)
		if err != nil {
			if cfg.Daemon.Enabled != nil && *cfg.Daemon.Enabled {
				fmt.Fprintf(os.Stderr, "doit: daemon: %v\n", err)
				return 2
			}
			// Auto mode: fall through to in-process.
		} else {
			defer conn.Close()
			stopSig := client.ForwardSignals(conn)
			defer stopSig()

			req := &ipc.Request{
				Args:     args,
				Cwd:      cwd,
				Retry:    retry,
				Approved: approved,
				Env:      ipc.CaptureEnv(),
			}
			result, err := client.Relay(ctx, conn, req, os.Stdin, os.Stdout, os.Stderr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "doit: %v\n", err)
				return 2
			}
			if result.PolicyEscalate != "" {
				fmt.Fprintf(os.Stderr, "\ndoit: policy escalation. To approve, retry with:\n  doit --approved %s %s\n",
					result.PolicyEscalate, strings.Join(args, " "))
			}
			return result.Code
		}
	}

	// In-process fallback.
	return cli.RunCommand(ctx, reg, logger, args, os.Stdin, os.Stdout, os.Stderr, retry, cwd, nil)
}

func shouldUseDaemon(cfg *config.Config) bool {
	if cfg.Daemon.Enabled != nil {
		return *cfg.Daemon.Enabled
	}
	return true // auto: try daemon, fall back to in-process
}
