// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (

	"github.com/marcelocantos/doit/internal/cap"
)

type Mv struct{}

var _ cap.Capability = (*Mv)(nil)

func (m *Mv) Name() string        { return "mv" }
func (m *Mv) Description() string { return "move or rename files and directories" }
func (m *Mv) Tier() cap.Tier      { return cap.TierWrite }
func (m *Mv) Validate(args []string) error { return nil }

