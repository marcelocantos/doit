// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (

	"github.com/marcelocantos/doit/internal/cap"
)

type Cat struct{}

var _ cap.Capability = (*Cat)(nil)

func (c *Cat) Name() string        { return "cat" }
func (c *Cat) Description() string { return "concatenate and display files" }
func (c *Cat) Tier() cap.Tier      { return cap.TierRead }
func (c *Cat) Validate(args []string) error { return nil }

