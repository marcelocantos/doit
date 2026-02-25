package pipeline

import (
	"fmt"

	"github.com/marcelocantos/doit/internal/cap"
)

// Parse takes pre-tokenized args (as delivered by the shell) and builds a Pipeline.
// It splits on ¦ to get pipe segments, and handles ‹/› for redirects.
func Parse(args []string, reg *cap.Registry) (*Pipeline, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("empty pipeline")
	}

	p := &Pipeline{}

	// First pass: extract redirects from the flat arg list.
	// ‹ <file> can appear anywhere (applies to first segment's stdin).
	// › <file> can appear anywhere (applies to last segment's stdout).
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case OpRedirectIn:
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a file path", OpRedirectIn)
			}
			if p.RedirectIn != "" {
				return nil, fmt.Errorf("multiple %s redirects", OpRedirectIn)
			}
			i++
			p.RedirectIn = args[i]
		case OpRedirectOut:
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a file path", OpRedirectOut)
			}
			if p.RedirectOut != "" {
				return nil, fmt.Errorf("multiple %s redirects", OpRedirectOut)
			}
			i++
			p.RedirectOut = args[i]
		default:
			filtered = append(filtered, args[i])
		}
	}

	// Second pass: split on ¦ to get pipe segments.
	var current []string
	for _, arg := range filtered {
		if arg == OpPipe {
			if len(current) == 0 {
				return nil, fmt.Errorf("empty segment before %s", OpPipe)
			}
			seg, err := parseSegment(current, reg)
			if err != nil {
				return nil, err
			}
			p.Segments = append(p.Segments, seg)
			current = nil
		} else {
			current = append(current, arg)
		}
	}
	if len(current) == 0 {
		return nil, fmt.Errorf("empty segment after %s", OpPipe)
	}
	seg, err := parseSegment(current, reg)
	if err != nil {
		return nil, err
	}
	p.Segments = append(p.Segments, seg)

	return p, nil
}

func parseSegment(args []string, reg *cap.Registry) (Segment, error) {
	name := args[0]
	// Verify capability exists.
	if _, err := reg.Lookup(name); err != nil {
		return Segment{}, err
	}
	return Segment{
		CapName: name,
		Args:    args[1:],
	}, nil
}

// ParseCommand splits args on compound operators (＆＆, ‖, ；) to get
// pipeline sections, then parses each section as a Pipeline.
// If no compound operators are present, the result is a single-step Command.
func ParseCommand(args []string, reg *cap.Registry) (*Command, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	cmd := &Command{}
	var current []string

	for _, arg := range args {
		if op := toOperator(arg); op != "" {
			if len(current) == 0 {
				return nil, fmt.Errorf("empty pipeline before %s", arg)
			}
			p, err := Parse(current, reg)
			if err != nil {
				return nil, err
			}
			cmd.Steps = append(cmd.Steps, CommandStep{Pipeline: p, Op: op})
			current = nil
		} else {
			current = append(current, arg)
		}
	}

	// Final section (no trailing operator).
	if len(current) == 0 {
		return nil, fmt.Errorf("empty pipeline after compound operator")
	}
	p, err := Parse(current, reg)
	if err != nil {
		return nil, err
	}
	cmd.Steps = append(cmd.Steps, CommandStep{Pipeline: p})

	return cmd, nil
}

// toOperator checks if a token is a compound operator.
func toOperator(token string) Operator {
	switch token {
	case OpAndThen:
		return Operator(OpAndThen)
	case OpOrElse:
		return Operator(OpOrElse)
	case OpSequential:
		return Operator(OpSequential)
	default:
		return ""
	}
}

// ValidateCommand validates all pipelines within a compound command.
// When allow is true, config rules are bypassed.
func ValidateCommand(cmd *Command, reg *cap.Registry, allow bool) error {
	for i, step := range cmd.Steps {
		if err := Validate(step.Pipeline, reg, allow); err != nil {
			return fmt.Errorf("pipeline %d: %w", i, err)
		}
	}
	return nil
}

// Validate checks all segments' args and tier permissions.
// Call this before Execute to fail fast. When allow is true, config rules
// are bypassed.
func Validate(p *Pipeline, reg *cap.Registry, allow bool) error {
	// Output redirects are write operations — require TierWrite.
	if p.RedirectOut != "" {
		if err := reg.CheckTier(cap.TierWrite); err != nil {
			return fmt.Errorf("redirect %s: %w", OpRedirectOut, err)
		}
	}
	for i, seg := range p.Segments {
		c, err := reg.Lookup(seg.CapName)
		if err != nil {
			return fmt.Errorf("segment %d: %w", i, err)
		}
		if err := reg.CheckTier(c.Tier()); err != nil {
			return fmt.Errorf("segment %d (%s): %w", i, seg.CapName, err)
		}
		if err := reg.CheckRules(seg.CapName, seg.Args, allow); err != nil {
			return fmt.Errorf("segment %d (%s): %w", i, seg.CapName, err)
		}
		if err := c.Validate(seg.Args); err != nil {
			return fmt.Errorf("segment %d (%s): %w", i, seg.CapName, err)
		}
	}
	return nil
}
