// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (

	"github.com/marcelocantos/doit/internal/cap"
)

type Mkdir struct{}

var _ cap.Capability = (*Mkdir)(nil)

func (m *Mkdir) Name() string        { return "mkdir" }
func (m *Mkdir) Description() string { return "create directories" }
func (m *Mkdir) Tier() cap.Tier      { return cap.TierWrite }
func (m *Mkdir) Validate(args []string) error { return nil }

