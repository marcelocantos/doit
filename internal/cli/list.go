package cli

import (
	"fmt"
	"io"

	"github.com/marcelocantos/doit/internal/cap"
)

// RunList lists available capabilities.
func RunList(reg *cap.Registry, w io.Writer, tierFilter string) int {
	caps := reg.All()

	var filter *cap.Tier
	if tierFilter != "" {
		t, err := cap.ParseTier(tierFilter)
		if err != nil {
			fmt.Fprintf(w, "doit list: %v\n", err)
			return 1
		}
		filter = &t
	}

	for _, c := range caps {
		if filter != nil && c.Tier() != *filter {
			continue
		}
		fmt.Fprintf(w, "%-12s %-10s %s\n", c.Name(), c.Tier(), c.Description())
	}
	return 0
}
