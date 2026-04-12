// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (

	"github.com/marcelocantos/doit/internal/cap"
)

type Tee struct{}

var _ cap.Capability = (*Tee)(nil)

func (t *Tee) Name() string        { return "tee" }
func (t *Tee) Description() string { return "duplicate stdin to stdout and files" }
func (t *Tee) Tier() cap.Tier      { return cap.TierWrite }
func (t *Tee) Validate(args []string) error { return nil }

