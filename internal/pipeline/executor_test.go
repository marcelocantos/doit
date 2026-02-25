package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/marcelocantos/doit/internal/cap"
)

// echoCap writes its args joined by spaces to stdout, then copies stdin.
type echoCap struct {
	name string
}

func (e *echoCap) Name() string        { return e.name }
func (e *echoCap) Description() string { return "echo" }
func (e *echoCap) Tier() cap.Tier      { return cap.TierRead }
func (e *echoCap) Validate(args []string) error { return nil }
func (e *echoCap) Run(_ context.Context, args []string, stdin io.Reader, stdout, _ io.Writer) error {
	if len(args) > 0 {
		fmt.Fprintln(stdout, strings.Join(args, " "))
	}
	io.Copy(stdout, stdin)
	return nil
}

// upperCap reads stdin and writes it uppercased to stdout.
type upperCap struct{}

func (u *upperCap) Name() string        { return "upper" }
func (u *upperCap) Description() string { return "uppercase" }
func (u *upperCap) Tier() cap.Tier      { return cap.TierRead }
func (u *upperCap) Validate(args []string) error { return nil }
func (u *upperCap) Run(_ context.Context, _ []string, stdin io.Reader, stdout, _ io.Writer) error {
	data, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	_, err = stdout.Write([]byte(strings.ToUpper(string(data))))
	return err
}

func TestExecuteSingleSegment(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&echoCap{name: "echo"})

	p := &Pipeline{
		Segments: []Segment{{CapName: "echo", Args: []string{"hello", "world"}}},
	}

	var buf bytes.Buffer
	err := Execute(context.Background(), p, reg, strings.NewReader(""), &buf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(buf.String()); got != "hello world" {
		t.Errorf("expected 'hello world', got %q", got)
	}
}

func TestExecutePipeline(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&echoCap{name: "echo"})
	reg.Register(&upperCap{})

	p := &Pipeline{
		Segments: []Segment{
			{CapName: "echo", Args: []string{"hello", "world"}},
			{CapName: "upper"},
		},
	}

	var buf bytes.Buffer
	err := Execute(context.Background(), p, reg, strings.NewReader(""), &buf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(buf.String()); got != "HELLO WORLD" {
		t.Errorf("expected 'HELLO WORLD', got %q", got)
	}
}

func TestExecuteThreeStages(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&echoCap{name: "echo"})
	reg.Register(&upperCap{})
	reg.Register(&echoCap{name: "prefix"})

	// echo "hello" | upper | prefix "result:"
	// prefix writes its args then copies stdin, so we get "result:\nHELLO\n"
	p := &Pipeline{
		Segments: []Segment{
			{CapName: "echo", Args: []string{"hello"}},
			{CapName: "upper"},
			{CapName: "prefix", Args: []string{"result:"}},
		},
	}

	var buf bytes.Buffer
	err := Execute(context.Background(), p, reg, strings.NewReader(""), &buf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "result:") || !strings.Contains(output, "HELLO") {
		t.Errorf("unexpected output: %q", output)
	}
}

func TestExecuteWithStdin(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&upperCap{})

	p := &Pipeline{
		Segments: []Segment{{CapName: "upper"}},
	}

	var buf bytes.Buffer
	err := Execute(context.Background(), p, reg, strings.NewReader("hello\n"), &buf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(buf.String()); got != "HELLO" {
		t.Errorf("expected 'HELLO', got %q", got)
	}
}

func TestExecuteCancellation(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&echoCap{name: "echo"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	p := &Pipeline{
		Segments: []Segment{{CapName: "echo", Args: []string{"hello"}}},
	}

	var buf bytes.Buffer
	// With a cancelled context, the command may or may not error.
	// The important thing is it doesn't hang.
	_ = Execute(ctx, p, reg, strings.NewReader(""), &buf, io.Discard)
}
