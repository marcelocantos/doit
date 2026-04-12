// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (

	"github.com/marcelocantos/doit/internal/cap"
)

type Uniq struct{}

var _ cap.Capability = (*Uniq)(nil)

func (u *Uniq) Name() string        { return "uniq" }
func (u *Uniq) Description() string { return "report or omit repeated lines" }
func (u *Uniq) Tier() cap.Tier      { return cap.TierRead }
func (u *Uniq) Validate(args []string) error { return nil }

