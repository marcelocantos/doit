// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package builtin

import (
	"fmt"

	"github.com/marcelocantos/doit/internal/cap"
)

type Find struct{}

var _ cap.Capability = (*Find)(nil)

func (f *Find) Name() string        { return "find" }
func (f *Find) Description() string { return "search for files in a directory hierarchy" }
func (f *Find) Tier() cap.Tier      { return cap.TierRead }

func (f *Find) Validate(args []string) error {
	for _, arg := range args {
		switch arg {
		case "-exec", "-execdir", "-ok", "-okdir", "-delete":
			return fmt.Errorf("find %s is not allowed (use dangerous-tier capabilities for mutations)", arg)
		}
	}
	return nil
}

