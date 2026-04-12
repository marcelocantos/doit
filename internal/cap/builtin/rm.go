// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (
	"fmt"

	"github.com/marcelocantos/doit/internal/cap"
)

type Rm struct{}

var _ cap.Capability = (*Rm)(nil)

func (r *Rm) Name() string        { return "rm" }
func (r *Rm) Description() string { return "remove files or directories (dangerous)" }
func (r *Rm) Tier() cap.Tier      { return cap.TierDangerous }

func (r *Rm) Validate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("rm requires at least one argument")
	}
	return nil
}

