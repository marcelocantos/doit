// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (

	"github.com/marcelocantos/doit/internal/cap"
)

type Head struct{}

var _ cap.Capability = (*Head)(nil)

func (h *Head) Name() string        { return "head" }
func (h *Head) Description() string { return "output the first part of files or stdin" }
func (h *Head) Tier() cap.Tier      { return cap.TierRead }
func (h *Head) Validate(args []string) error { return nil }

