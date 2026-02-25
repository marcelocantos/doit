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
	fmt.Fprintln(w, "  doit <capability> [args...]       run a capability directly")
	fmt.Fprintf(w, "  doit --pipe <cmd> %s <cmd> ...   run a pipeline\n", pipeline.OpPipe)
	fmt.Fprintln(w, "  doit --list [--tier <tier>]       list available capabilities")
	fmt.Fprintln(w, "  doit --help [<capability>]        show help")
	fmt.Fprintln(w, "  doit --audit <verify|show|tail>   audit log operations")
	fmt.Fprintln(w, "  doit --version                    show version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "pipeline operators:")
	fmt.Fprintf(w, "  %s  pipe (stdout → stdin)\n", pipeline.OpPipe)
	fmt.Fprintf(w, "  %s  redirect stdout to file\n", pipeline.OpRedirectOut)
	fmt.Fprintf(w, "  %s  redirect stdin from file\n", pipeline.OpRedirectIn)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "safety tiers: read, build, write, dangerous")
}
