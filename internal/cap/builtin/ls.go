// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (

	"github.com/marcelocantos/doit/internal/cap"
)

type Ls struct{}

var _ cap.Capability = (*Ls)(nil)

func (l *Ls) Name() string        { return "ls" }
func (l *Ls) Description() string { return "list directory contents" }
func (l *Ls) Tier() cap.Tier      { return cap.TierRead }
func (l *Ls) Validate(args []string) error { return nil }

