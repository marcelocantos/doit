package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/marcelocantos/doit/internal/audit"
)

// RunAudit handles the doit audit subcommand.
func RunAudit(w io.Writer, logPath string, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(w, "usage: doit audit <verify|show|tail>")
		return 1
	}

	switch args[0] {
	case "verify":
		if err := audit.Verify(logPath); err != nil {
			fmt.Fprintf(w, "audit verification FAILED: %v\n", err)
			return 1
		}
		fmt.Fprintln(w, "audit log integrity verified")
		return 0

	case "show", "tail":
		n := 20
		entries, err := audit.Tail(logPath, n)
		if err != nil {
			fmt.Fprintf(w, "doit audit: %v\n", err)
			return 1
		}
		if len(entries) == 0 {
			fmt.Fprintln(w, "no audit entries")
			return 0
		}
		for _, e := range entries {
			data, _ := json.MarshalIndent(e, "", "  ")
			fmt.Fprintf(w, "%s\n", data)
		}
		return 0

	default:
		fmt.Fprintf(w, "doit audit: unknown subcommand %q\n", args[0])
		return 1
	}
}
