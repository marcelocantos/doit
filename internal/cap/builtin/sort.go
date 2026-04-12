// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (

	"github.com/marcelocantos/doit/internal/cap"
)

type Sort struct{}

var _ cap.Capability = (*Sort)(nil)

func (s *Sort) Name() string        { return "sort" }
func (s *Sort) Description() string { return "sort lines of text" }
func (s *Sort) Tier() cap.Tier      { return cap.TierRead }
func (s *Sort) Validate(args []string) error { return nil }

