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
	err = Validate(p, reg)
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
	if err := Validate(p, reg); err != nil {
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
