// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (
	"fmt"

	"github.com/marcelocantos/doit/internal/cap"
)

type GoCmd struct{}

var _ cap.Capability = (*GoCmd)(nil)

func (g *GoCmd) Name() string        { return "go" }
func (g *GoCmd) Description() string { return "go build, test, vet, and other go commands (tier varies by subcommand)" }
func (g *GoCmd) Tier() cap.Tier      { return cap.TierBuild } // base tier; advisory metadata for capability listing

func (g *GoCmd) Validate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("go requires a subcommand")
	}
	return nil
}
