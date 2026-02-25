package pipeline

// Unicode operators used in pipeline syntax.
// These are not shell metacharacters, so they survive unquoted in bash/zsh/fish.
const (
	OpPipe        = "¦" // U+00A6 BROKEN BAR — pipe (stdout → stdin)
	OpRedirectIn  = "‹" // U+2039 SINGLE LEFT-POINTING ANGLE QUOTATION MARK — redirect stdin from file
	OpRedirectOut = "›" // U+203A SINGLE RIGHT-POINTING ANGLE QUOTATION MARK — redirect stdout to file

	// Future operators (v2):
	OpAndThen    = "＆＆" // U+FF06 ×2 FULLWIDTH AMPERSAND — and-then (short-circuit)
	OpOrElse     = "‖"   // U+2016 DOUBLE VERTICAL LINE — or-else (run if previous fails)
	OpSequential = "；"   // U+FF1B FULLWIDTH SEMICOLON — sequential (run regardless of exit code)
)

// Segment represents a single command in a pipeline.
type Segment struct {
	CapName string   // capability name (first arg in segment)
	Args    []string // remaining arguments
}

// Pipeline represents a parsed pipeline with optional redirects.
type Pipeline struct {
	Segments    []Segment
	RedirectIn  string // file path for stdin redirect (‹), empty if none
	RedirectOut string // file path for stdout redirect (›), empty if none
}

// Operator represents a compound-command connector between pipelines.
type Operator string

// CommandStep is one pipeline within a compound command, together with
// the operator that connects it to the next step. The last step's Op is
// unused.
type CommandStep struct {
	Pipeline *Pipeline
	Op       Operator // operator AFTER this pipeline (connects to next step)
}

// Command represents a compound command: one or more pipelines connected
// by ＆＆, ‖, or ； operators.
type Command struct {
	Steps []CommandStep
}
