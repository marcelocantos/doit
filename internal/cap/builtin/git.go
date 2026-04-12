// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (
	"fmt"

	"github.com/marcelocantos/doit/internal/cap"
)

type Git struct{}

var _ cap.Capability = (*Git)(nil)

func (g *Git) Name() string        { return "git" }
func (g *Git) Description() string { return "git version control (tier varies by subcommand)" }
func (g *Git) Tier() cap.Tier      { return cap.TierRead } // base tier; advisory metadata for capability listing

func (g *Git) Validate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("git requires a subcommand")
	}
	return nil
}
