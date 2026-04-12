// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (

	"github.com/marcelocantos/doit/internal/cap"
)

type Cp struct{}

var _ cap.Capability = (*Cp)(nil)

func (c *Cp) Name() string        { return "cp" }
func (c *Cp) Description() string { return "copy files and directories" }
func (c *Cp) Tier() cap.Tier      { return cap.TierWrite }
func (c *Cp) Validate(args []string) error { return nil }

