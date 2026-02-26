package pipeline

import (
	"context"
	"io"
	"testing"

	"github.com/marcelocantos/doit/internal/cap"
)

// stubCap is a minimal capability for testing.
type stubCap struct {
	name string
	tier cap.Tier
}

func (s *stubCap) Name() string                                                             { return s.name }
func (s *stubCap) Description() string                                                      { return "stub" }
func (s *stubCap) Tier() cap.Tier                                                           { return s.tier }
func (s *stubCap) Validate(args []string) error                                             { return nil }
func (s *stubCap) Run(_ context.Context, _ []string, _ io.Reader, _, _ io.Writer) error { return nil }

func newTestRegistry() *cap.Registry {
	r := cap.NewRegistry()
	r.Register(&stubCap{name: "grep", tier: cap.TierRead})
	r.Register(&stubCap{name: "head", tier: cap.TierRead})
	r.Register(&stubCap{name: "sort", tier: cap.TierRead})
	r.Register(&stubCap{name: "uniq", tier: cap.TierRead})
	r.Register(&stubCap{name: "wc", tier: cap.TierRead})
	r.Register(&stubCap{name: "cat", tier: cap.TierRead})
	r.Register(&stubCap{name: "tr", tier: cap.TierRead})
	r.Register(&stubCap{name: "rm", tier: cap.TierDangerous})
	return r
}

func TestParseSingleSegment(t *testing.T) {
	reg := newTestRegistry()
	p, err := Parse([]string{"grep", "-r", "TODO", "src/"}, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(p.Segments))
	}
	if p.Segments[0].CapName != "grep" {
		t.Errorf("expected cap grep, got %s", p.Segments[0].CapName)
	}
	if len(p.Segments[0].Args) != 3 {
		t.Errorf("expected 3 args, got %d", len(p.Segments[0].Args))
	}
}

func TestParsePipeline(t *testing.T) {
	reg := newTestRegistry()
	// grep -r TODO src/ ¦ sort ¦ uniq -c ¦ head -20
	args := []string{"grep", "-r", "TODO", "src/", "¦", "sort", "¦", "uniq", "-c", "¦", "head", "-20"}
	p, err := Parse(args, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Segments) != 4 {
		t.Fatalf("expected 4 segments, got %d", len(p.Segments))
	}
	expected := []struct {
		name string
		argc int
	}{
		{"grep", 3},
		{"sort", 0},
		{"uniq", 1},
		{"head", 1},
	}
	for i, e := range expected {
		if p.Segments[i].CapName != e.name {
			t.Errorf("segment %d: expected %s, got %s", i, e.name, p.Segments[i].CapName)
		}
		if len(p.Segments[i].Args) != e.argc {
			t.Errorf("segment %d: expected %d args, got %d", i, e.argc, len(p.Segments[i].Args))
		}
	}
}

func TestParseRedirectOut(t *testing.T) {
	reg := newTestRegistry()
	args := []string{"grep", "TODO", "¦", "head", "-5", "›", "/tmp/out.txt"}
	p, err := Parse(args, reg)
	if err != nil {
		t.Fatal(err)
	}
	if p.RedirectOut != "/tmp/out.txt" {
		t.Errorf("expected redirect out to /tmp/out.txt, got %q", p.RedirectOut)
	}
	if len(p.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(p.Segments))
	}
}

func TestParseRedirectIn(t *testing.T) {
	reg := newTestRegistry()
	args := []string{"sort", "‹", "/tmp/in.txt", "¦", "head"}
	p, err := Parse(args, reg)
	if err != nil {
		t.Fatal(err)
	}
	if p.RedirectIn != "/tmp/in.txt" {
		t.Errorf("expected redirect in from /tmp/in.txt, got %q", p.RedirectIn)
	}
	if len(p.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(p.Segments))
	}
}

func TestParseEmptyPipeline(t *testing.T) {
	reg := newTestRegistry()
	_, err := Parse([]string{}, reg)
	if err == nil {
		t.Fatal("expected error for empty pipeline")
	}
}

func TestParseUnknownCapability(t *testing.T) {
	reg := newTestRegistry()
	_, err := Parse([]string{"nonexistent"}, reg)
	if err == nil {
		t.Fatal("expected error for unknown capability")
	}
}

func TestParseEmptySegment(t *testing.T) {
	reg := newTestRegistry()
	// ¦ at the beginning = empty first segment
	_, err := Parse([]string{"¦", "grep", "foo"}, reg)
	if err == nil {
		t.Fatal("expected error for empty segment before pipe")
	}
}

func TestParseTrailingPipe(t *testing.T) {
	reg := newTestRegistry()
	_, err := Parse([]string{"grep", "foo", "¦"}, reg)
	if err == nil {
		t.Fatal("expected error for trailing pipe")
	}
}

func TestValidateTierDenied(t *testing.T) {
	reg := newTestRegistry()
	reg.SetTier(cap.TierDangerous, false)
	p, err := Parse([]string{"rm", "-rf", "/"}, reg)
	if err != nil {
		t.Fatal(err)
	}
	err = Validate(p, reg, false)
	if err == nil {
		t.Fatal("expected error for disabled tier")
	}
}

func TestValidateTierAllowed(t *testing.T) {
	reg := newTestRegistry()
	p, err := Parse([]string{"grep", "foo"}, reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(p, reg, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDoubleRedirectOut(t *testing.T) {
	reg := newTestRegistry()
	args := []string{"cat", "›", "a.txt", "›", "b.txt"}
	_, err := Parse(args, reg)
	if err == nil {
		t.Fatal("expected error for multiple output redirects")
	}
}

func TestParseRedirectOutMissingFile(t *testing.T) {
	reg := newTestRegistry()
	args := []string{"cat", "›"}
	_, err := Parse(args, reg)
	if err == nil {
		t.Fatal("expected error for redirect without file")
	}
}

// --- ParseCommand tests ---

func TestParseCommandSinglePipeline(t *testing.T) {
	reg := newTestRegistry()
	cmd, err := ParseCommand([]string{"grep", "foo", "¦", "wc"}, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(cmd.Steps))
	}
	if len(cmd.Steps[0].Pipeline.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(cmd.Steps[0].Pipeline.Segments))
	}
}

func TestParseCommandAndThen(t *testing.T) {
	reg := newTestRegistry()
	cmd, err := ParseCommand([]string{"grep", "foo", "＆＆", "cat"}, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(cmd.Steps))
	}
	if cmd.Steps[0].Op != Operator(OpAndThen) {
		t.Errorf("expected and-then operator, got %q", cmd.Steps[0].Op)
	}
}

func TestParseCommandOrElse(t *testing.T) {
	reg := newTestRegistry()
	cmd, err := ParseCommand([]string{"grep", "foo", "‖", "cat"}, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(cmd.Steps))
	}
	if cmd.Steps[0].Op != Operator(OpOrElse) {
		t.Errorf("expected or-else operator, got %q", cmd.Steps[0].Op)
	}
}

func TestParseCommandSequential(t *testing.T) {
	reg := newTestRegistry()
	cmd, err := ParseCommand([]string{"cat", "；", "grep", "foo"}, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(cmd.Steps))
	}
	if cmd.Steps[0].Op != Operator(OpSequential) {
		t.Errorf("expected sequential operator, got %q", cmd.Steps[0].Op)
	}
}

func TestParseCommandMixed(t *testing.T) {
	reg := newTestRegistry()
	// grep foo ¦ wc ＆＆ cat ‖ sort
	args := []string{"grep", "foo", "¦", "wc", "＆＆", "cat", "‖", "sort"}
	cmd, err := ParseCommand(args, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(cmd.Steps))
	}
	// First step has 2 pipeline segments (grep | wc)
	if len(cmd.Steps[0].Pipeline.Segments) != 2 {
		t.Errorf("step 0: expected 2 segments, got %d", len(cmd.Steps[0].Pipeline.Segments))
	}
	if cmd.Steps[0].Op != Operator(OpAndThen) {
		t.Errorf("step 0: expected and-then, got %q", cmd.Steps[0].Op)
	}
	if cmd.Steps[1].Op != Operator(OpOrElse) {
		t.Errorf("step 1: expected or-else, got %q", cmd.Steps[1].Op)
	}
}

func TestParseCommandWithRedirects(t *testing.T) {
	reg := newTestRegistry()
	// sort ‹ in.txt ＆＆ cat › out.txt
	args := []string{"sort", "‹", "in.txt", "＆＆", "cat", "›", "out.txt"}
	cmd, err := ParseCommand(args, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(cmd.Steps))
	}
	if cmd.Steps[0].Pipeline.RedirectIn != "in.txt" {
		t.Errorf("step 0: expected redirect in 'in.txt', got %q", cmd.Steps[0].Pipeline.RedirectIn)
	}
	if cmd.Steps[1].Pipeline.RedirectOut != "out.txt" {
		t.Errorf("step 1: expected redirect out 'out.txt', got %q", cmd.Steps[1].Pipeline.RedirectOut)
	}
}

func TestParseCommandEmptyBefore(t *testing.T) {
	reg := newTestRegistry()
	_, err := ParseCommand([]string{"＆＆", "cat"}, reg)
	if err == nil {
		t.Fatal("expected error for empty pipeline before operator")
	}
}

func TestParseCommandEmptyAfter(t *testing.T) {
	reg := newTestRegistry()
	_, err := ParseCommand([]string{"cat", "＆＆"}, reg)
	if err == nil {
		t.Fatal("expected error for empty pipeline after operator")
	}
}

func TestParseCommandEmptyBetween(t *testing.T) {
	reg := newTestRegistry()
	_, err := ParseCommand([]string{"cat", "＆＆", "‖", "sort"}, reg)
	if err == nil {
		t.Fatal("expected error for empty pipeline between operators")
	}
}

func TestParseCommandEmpty(t *testing.T) {
	reg := newTestRegistry()
	_, err := ParseCommand([]string{}, reg)
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}
