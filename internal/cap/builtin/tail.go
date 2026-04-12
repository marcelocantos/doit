// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (

	"github.com/marcelocantos/doit/internal/cap"
)

type Tail struct{}

var _ cap.Capability = (*Tail)(nil)

func (t *Tail) Name() string        { return "tail" }
func (t *Tail) Description() string { return "output the last part of files or stdin" }
func (t *Tail) Tier() cap.Tier      { return cap.TierRead }
func (t *Tail) Validate(args []string) error { return nil }

