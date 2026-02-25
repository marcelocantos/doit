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

// failCap always returns an error.
type failCap struct {
	name string
}

func (f *failCap) Name() string        { return f.name }
func (f *failCap) Description() string { return "always fails" }
func (f *failCap) Tier() cap.Tier      { return cap.TierRead }
func (f *failCap) Validate(args []string) error { return nil }
func (f *failCap) Run(_ context.Context, _ []string, _ io.Reader, _, _ io.Writer) error {
	return fmt.Errorf("fail")
}

func TestExecuteCommandSingle(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&echoCap{name: "echo"})

	cmd := &Command{
		Steps: []CommandStep{
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "echo", Args: []string{"hello"}}}}},
		},
	}

	var buf bytes.Buffer
	err := ExecuteCommand(context.Background(), cmd, reg, strings.NewReader(""), &buf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(buf.String()); got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}
}

func TestExecuteCommandAndThenSuccess(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&echoCap{name: "echo"})
	reg.Register(&echoCap{name: "echo2"})

	cmd := &Command{
		Steps: []CommandStep{
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "echo", Args: []string{"hello"}}}}, Op: Operator(OpAndThen)},
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "echo2", Args: []string{"world"}}}}},
		},
	}

	var buf bytes.Buffer
	err := ExecuteCommand(context.Background(), cmd, reg, strings.NewReader(""), &buf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "hello") || !strings.Contains(output, "world") {
		t.Errorf("expected both 'hello' and 'world', got %q", output)
	}
}

func TestExecuteCommandAndThenFailure(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&failCap{name: "fail"})
	reg.Register(&echoCap{name: "echo"})

	cmd := &Command{
		Steps: []CommandStep{
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "fail"}}}, Op: Operator(OpAndThen)},
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "echo", Args: []string{"skipped"}}}}},
		},
	}

	var buf bytes.Buffer
	err := ExecuteCommand(context.Background(), cmd, reg, strings.NewReader(""), &buf, io.Discard)
	if err == nil {
		t.Fatal("expected error from failed pipeline")
	}
	if strings.Contains(buf.String(), "skipped") {
		t.Error("echo should not have run after failure with and-then")
	}
}

func TestExecuteCommandOrElseSuccess(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&echoCap{name: "echo"})
	reg.Register(&echoCap{name: "fallback"})

	cmd := &Command{
		Steps: []CommandStep{
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "echo", Args: []string{"ok"}}}}, Op: Operator(OpOrElse)},
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "fallback", Args: []string{"nope"}}}}},
		},
	}

	var buf bytes.Buffer
	err := ExecuteCommand(context.Background(), cmd, reg, strings.NewReader(""), &buf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "nope") {
		t.Error("fallback should not have run after success with or-else")
	}
}

func TestExecuteCommandOrElseFailure(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&failCap{name: "fail"})
	reg.Register(&echoCap{name: "fallback"})

	cmd := &Command{
		Steps: []CommandStep{
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "fail"}}}, Op: Operator(OpOrElse)},
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "fallback", Args: []string{"recovered"}}}}},
		},
	}

	var buf bytes.Buffer
	err := ExecuteCommand(context.Background(), cmd, reg, strings.NewReader(""), &buf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "recovered") {
		t.Error("fallback should have run after failure with or-else")
	}
}

func TestExecuteCommandSequential(t *testing.T) {
	reg := cap.NewRegistry()
	reg.Register(&failCap{name: "fail"})
	reg.Register(&echoCap{name: "echo"})

	cmd := &Command{
		Steps: []CommandStep{
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "fail"}}}, Op: Operator(OpSequential)},
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "echo", Args: []string{"always"}}}}},
		},
	}

	var buf bytes.Buffer
	err := ExecuteCommand(context.Background(), cmd, reg, strings.NewReader(""), &buf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "always") {
		t.Error("echo should have run after failure with sequential")
	}
}

func TestExecuteCommandChain(t *testing.T) {
	// fail ＆＆ skip ‖ recover
	// fail runs and fails. skip is skipped (＆＆ + error). recover runs (‖ + error).
	reg := cap.NewRegistry()
	reg.Register(&failCap{name: "fail"})
	reg.Register(&echoCap{name: "skip"})
	reg.Register(&echoCap{name: "recover"})

	cmd := &Command{
		Steps: []CommandStep{
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "fail"}}}, Op: Operator(OpAndThen)},
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "skip", Args: []string{"no"}}}}, Op: Operator(OpOrElse)},
			{Pipeline: &Pipeline{Segments: []Segment{{CapName: "recover", Args: []string{"yes"}}}}},
		},
	}

	var buf bytes.Buffer
	err := ExecuteCommand(context.Background(), cmd, reg, strings.NewReader(""), &buf, io.Discard)
	if err != nil {
		t.Fatalf("expected no error after recovery, got %v", err)
	}
	output := buf.String()
	if strings.Contains(output, "no") {
		t.Error("skip should not have run")
	}
	if !strings.Contains(output, "yes") {
		t.Error("recover should have run")
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
