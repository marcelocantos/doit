package cli

import (
	_ "embed"
	"fmt"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/pipeline"
)

//go:embed help_agent.md
var helpAgent string

// RunHelp shows help for a capability or general usage.
func RunHelp(reg *cap.Registry, w io.Writer, args []string) int {
	if len(args) == 0 {
		printGeneralHelp(w)
		return 0
	}

	name := args[0]
	c, err := reg.Lookup(name)
	if err != nil {
		fmt.Fprintf(w, "doit help: %v\n", err)
		return 1
	}

	fmt.Fprintf(w, "%s — %s\n", c.Name(), c.Description())
	fmt.Fprintf(w, "tier: %s\n", c.Tier())
	return 0
}

// RunHelpAgent outputs the general help followed by the agent-specific guide.
func RunHelpAgent(reg *cap.Registry, w io.Writer) int {
	printGeneralHelp(w)
	fmt.Fprintln(w)
	fmt.Fprint(w, helpAgent)
	return 0
}

func printGeneralHelp(w io.Writer) {
	fmt.Fprintln(w, "doit — capability broker for Claude Code")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  doit <capability> [args...]       run a command")
	fmt.Fprintf(w, "  doit <cmd> %s <cmd> %s ...         run a pipeline\n", pipeline.OpPipe, pipeline.OpPipe)
	fmt.Fprintln(w, "  doit --retry <cmd> [args...]      bypass config rules (single invocation)")
	fmt.Fprintln(w, "  doit --list [--tier <tier>]       list available capabilities")
	fmt.Fprintln(w, "  doit --help [<capability>]        show help")
	fmt.Fprintln(w, "  doit --audit <verify|show|tail>   audit log operations")
	fmt.Fprintln(w, "  doit --help-agent                 full agent usage guide")
	fmt.Fprintln(w, "  doit --version                    show version")
	fmt.Fprintln(w, "  doit --daemon                     run as daemon (internal)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "pipeline operators:")
	fmt.Fprintf(w, "  %s  pipe (stdout → stdin)\n", pipeline.OpPipe)
	fmt.Fprintf(w, "  %s  redirect stdout to file\n", pipeline.OpRedirectOut)
	fmt.Fprintf(w, "  %s  redirect stdin from file\n", pipeline.OpRedirectIn)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "compound operators:")
	fmt.Fprintf(w, "  %s  and-then (run next if previous succeeded)\n", pipeline.OpAndThen)
	fmt.Fprintf(w, "  %s   or-else (run next if previous failed)\n", pipeline.OpOrElse)
	fmt.Fprintf(w, "  %s   sequential (run next regardless)\n", pipeline.OpSequential)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "safety tiers: read, build, write, dangerous")
}
