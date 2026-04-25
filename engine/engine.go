// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Package engine provides the public API for doit's policy engine.
// External consumers (e.g. jevon) import this package to evaluate and
// execute commands through doit's three-level policy chain.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marcelocantos/doit/internal/audit"
	"github.com/marcelocantos/doit/internal/cap"
	"github.com/marcelocantos/doit/internal/cap/builtin"
	"github.com/marcelocantos/doit/internal/config"
	doitctx "github.com/marcelocantos/doit/internal/context"
	"github.com/marcelocantos/doit/internal/llm"
	"github.com/marcelocantos/doit/internal/policy"
	"github.com/marcelocantos/doit/internal/script"
	doitstar "github.com/marcelocantos/doit/internal/starlark"
)

// Options configures Engine creation.
type Options struct {
	// ConfigPath loads config from a specific file. Empty uses the default.
	ConfigPath string
	// ProjectRoot enables per-project config overlay. If set, the engine
	// looks for .doit/config.yaml in this directory and merges it with
	// the global config using tighten-only semantics.
	ProjectRoot string
}

// Request describes a command to evaluate or execute.
type Request struct {
	Command       string            // shell command string (for sh -c) or space-joined args
	Args          []string          // parsed args (takes precedence over Command if non-empty)
	Justification string            // why the agent needs this command
	SafetyArg     string            // why the agent believes it's safe
	Cwd           string            // working directory
	Env           map[string]string // environment variables
	Approved      string            // approval token for escalated commands
	Retry         bool              // bypass config rules for this invocation
	// TimeoutSeconds bounds command runtime. When > 0, doit kills the
	// process on expiry (SIGKILL via context cancellation). Zero means
	// no timeout (default).
	TimeoutSeconds int
	// ExpectedDurationSeconds is the agent's estimate of how long the
	// command should take. Zero means not specified. Recorded in the
	// audit log alongside the actual duration so L1/L2 can learn and
	// flag mismatches.
	ExpectedDurationSeconds int
}

// Result is returned by Execute.
type Result struct {
	ExitCode       int
	Stdout         string
	Stderr         string
	PolicyLevel    int
	PolicyDecision string // "allow", "deny", "escalate", or "" if no policy
	PolicyReason   string
	PolicyRuleID   string
	EscalateToken  string // non-empty when policy escalated, token for approval
}

// EvalResult is returned by Evaluate (dry-run, no execution).
type EvalResult struct {
	Decision   string // "allow", "deny", "escalate"
	Level      int    // 1, 2, or 3
	Reason     string // human-readable explanation
	RuleID     string // which rule matched
	Bypassable bool   // true if the denial can be overridden by the user
	// ScriptApproval is non-nil when the engine detected a shell-script
	// invocation whose contents have not been approved. The caller
	// (typically the MCP handler) should show the content preview to
	// the user and, on approval, call Engine.ApproveScript before
	// invoking Execute.
	ScriptApproval *ScriptApprovalRequest
}

// ScriptApprovalRequest describes an unapproved script invocation
// surfaced to the caller for a user decision.
type ScriptApprovalRequest struct {
	Interpreter    string // "bash" | "sh" | "zsh" | "direct"
	Path           string // absolute resolved script path
	ContentHash    string // "sha256:<hex>"
	ContentPreview string // truncated preview for display
	SizeBytes      int64  // script size on disk
}

// WorkSession represents an active work session where L3 evaluations
// accumulate context for faster, more informed decisions.
type WorkSession struct {
	ID          string        `json:"id"`
	Scope       string        `json:"scope"`
	Description string        `json:"description,omitempty"`
	StartedAt   time.Time     `json:"started_at"`
	Timeout     time.Duration `json:"timeout"`
}

// Expired returns true if the session has exceeded its timeout.
func (s *WorkSession) Expired() bool {
	return time.Since(s.StartedAt) > s.Timeout
}

// Engine wraps the doit policy chain, capability registry, and audit log.
type Engine struct {
	cfg        *config.Config
	reg        *cap.Registry
	logger     *audit.Logger
	policyL1   *policy.Level1
	policyL2   *policy.Level2
	policyL3   *policy.Level3
	l3Fast     *llm.Client // fast triage client (sonnet)
	l3Deep     *llm.Client // deep reasoning client (opus) — may be nil
	tokenStore *policy.TokenStore
	storePath  string
	promoteCh  chan struct{}
	projectCtx *doitctx.ProjectContext // discovered project context (may be nil)

	projectRoot   string // normalised project root path (empty = no project context)

	scriptStore   *script.Store
	durationStore *policy.DurationStore

	l1Mu      sync.RWMutex
	l2Mu      sync.RWMutex
	sessionMu sync.RWMutex
	session   *WorkSession
}

// EngineOption configures optional Engine parameters.
type EngineOption func(*Engine)

// WithLevel3 injects a pre-built Level3 engine and TokenStore.
// Useful for tests that supply a mock Prompter.
func WithLevel3(l3 *policy.Level3, ts *policy.TokenStore) EngineOption {
	return func(e *Engine) {
		e.policyL3 = l3
		e.tokenStore = ts
	}
}

// New creates an Engine from config. It initialises the capability registry,
// audit logger, and policy chain (L1/L2/L3) based on the config.
func New(opts Options, engineOpts ...EngineOption) (*Engine, error) {
	var (
		cfg *config.Config
		err error
	)
	if opts.ConfigPath != "" {
		cfg, err = config.LoadFrom(opts.ConfigPath)
	} else {
		cfg, err = config.Load()
	}
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// Per-project config overlay (tighten-only).
	if opts.ProjectRoot != "" {
		projCfg, err := config.LoadProject(opts.ProjectRoot)
		if err != nil {
			return nil, fmt.Errorf("load project config: %w", err)
		}
		cfg.MergeProject(projCfg)
	}

	reg := cap.NewRegistry()
	builtin.RegisterAll(reg)
	cfg.ApplyTiers(reg)
	cfg.ApplyRules(reg)

	logger, err := audit.NewLogger(cfg.Audit.Path, int64(cfg.Audit.MaxSizeMB)*1024*1024)
	if err != nil {
		log.Printf("doit: engine: audit logger: %v (continuing without audit)", err)
		logger = nil
	}

	e := &Engine{
		cfg:           cfg,
		reg:           reg,
		logger:        logger,
		storePath:     cfg.Policy.Level2Path,
		promoteCh:     make(chan struct{}, 1),
		scriptStore:   script.NewStore(""),
		durationStore: policy.NewDurationStore(""),
	}

	// Discover project context from project root (best-effort; non-fatal).
	if opts.ProjectRoot != "" {
		e.projectCtx = doitctx.Discover(opts.ProjectRoot)
		// Normalise the path so audit entries and duration keys are stable
		// across relative vs. absolute invocations.
		if abs, err := filepath.Abs(opts.ProjectRoot); err == nil {
			e.projectRoot = abs
		} else {
			e.projectRoot = opts.ProjectRoot
		}
	}


	if e.storePath == "" {
		e.storePath = policy.DefaultStorePath()
	}

	// L1: deterministic rules.
	if cfg.Policy.Level1Enabled {
		cfgRules := cfg.Rules
		if cfgRules == nil {
			cfgRules = config.DefaultRules()
		}
		var starlarkEval *doitstar.Evaluator
		if cfg.Policy.StarlarkRulesDir != "" {
			starRules, starErr := doitstar.LoadDir(cfg.Policy.StarlarkRulesDir)
			if starErr != nil {
				log.Printf("doit: engine: starlark rules: %v (continuing without starlark rules)", starErr)
			} else if len(starRules) > 0 {
				starlarkEval = doitstar.NewEvaluator(starRules)
				log.Printf("doit: engine: loaded %d starlark rules", len(starRules))
			}
		}
		e.policyL1 = policy.NewLevel1WithStarlark(cfgRules, starlarkEval)

		// Inject project-context-aware safe-command rules (🎯T13).
		if e.projectCtx != nil && len(e.projectCtx.SafeCommands) > 0 {
			e.policyL1.AddProjectContextRules(
				string(e.projectCtx.Type),
				e.projectCtx.SafeCommands,
			)
		}
	}

	// L2: learned policy store.
	if cfg.Policy.Level2Enabled {
		entries, err := policy.LoadStore(e.storePath)
		if err != nil {
			log.Printf("doit: engine: failed to load learned policy: %v", err)
		} else {
			for _, ent := range entries {
				if ent.Approved && !ent.Review.NextReview.IsZero() && policy.NeedsReview(ent.Review.NextReview) {
					log.Printf("doit: learned policy %q is overdue for review (due %s)",
						ent.ID, ent.Review.NextReview.Format("2006-01-02"))
				}
			}
			e.policyL2 = policy.NewLevel2(entries)
		}
	}

	// L3: LLM gatekeeper via `claude -p` (two-tier fast + deep).
	//
	// Previously this used a persistent claudia Session per tier, kept
	// alive for the engine's lifetime and reset between evaluations
	// with /clear. That turned out to be structurally broken: /clear
	// rolls over Claude Code's session ID, creating a new JSONL file
	// that claudia's fixed-path tailer never sees, so every evaluation
	// after the first hung. Switching to one-shot `claude -p` per
	// evaluation removes both the /clear problem and the background
	// init race — L3 is available synchronously the moment NewEngine
	// returns, there is no "L3 policy engine not available" window,
	// and each prompt is stateless.
	if cfg.Policy.Level3Enabled {
		e.tokenStore = policy.NewTokenStore(policy.DefaultTokenTTL)

		workDir := opts.ProjectRoot
		if workDir == "" {
			workDir, _ = os.Getwd()
		}
		timeout := cfg.Policy.Level3TimeoutDuration()

		fastModel := cfg.Policy.Level3FastModel
		if fastModel == "" {
			fastModel = "sonnet"
		}
		fastClient := &llm.Client{
			Model:           fastModel,
			Timeout:         timeout,
			WorkDir:         workDir,
			DisallowTools:   "Bash,Read,Write,Edit,Glob,Grep",
			SkipPermissions: true,
		}
		e.l3Fast = fastClient

		deepModel := cfg.Policy.Level3Model
		if deepModel == "" {
			deepModel = "opus"
		}
		if deepModel != fastModel {
			deepClient := &llm.Client{
				Model:           deepModel,
				Timeout:         timeout,
				WorkDir:         workDir,
				DisallowTools:   "Bash,Read,Write,Edit,Glob,Grep",
				SkipPermissions: true,
			}
			e.l3Deep = deepClient
			e.policyL3 = policy.NewLevel3(fastClient, deepClient)
			log.Printf("doit: L3 ready (fast=%s, deep=%s)", fastModel, deepModel)
		} else {
			e.policyL3 = policy.NewLevel3(fastClient)
			log.Printf("doit: L3 ready (%s only)", fastModel)
		}
	}

	for _, opt := range engineOpts {
		opt(e)
	}

	return e, nil
}

// Close shuts down engine resources. L3 clients are stateless
// `claude -p` wrappers with nothing to clean up — Close just ends
// any active work session.
func (e *Engine) Close() {
	e.EndSession("") // end any active session
	e.l3Fast = nil
	e.l3Deep = nil
}

// l3SessionClient returns the client to use for session interactions — the
// deep model if available, otherwise the fast model.
func (e *Engine) l3SessionClient() *llm.Client {
	if e.l3Deep != nil {
		return e.l3Deep
	}
	return e.l3Fast
}

// StartSession begins a work session. During a session, the declared
// scope and description are prepended to every L3 prompt (via
// buildSessionPrefix in internal/policy/level3.go), giving the
// gatekeeper scope-aware context without requiring a persistent
// conversation. Returns the session ID or an error if L3 is not
// available.
//
// Prior versions primed a persistent claudia session here with a
// "WORK SESSION STARTED" message so subsequent evaluations would
// benefit from accumulated context. That was predicated on claudia's
// Session mode retaining state across calls; after the migration to
// one-shot `claude -p` the priming step is pointless (it evaluates
// and exits), so it's been removed. The session prefix still
// reaches every evaluation via level3.go's buildSessionPrefix.
func (e *Engine) StartSession(scope, description string, timeout time.Duration) (string, error) {
	if scope == "" {
		return "", fmt.Errorf("scope is required")
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}

	id := fmt.Sprintf("session-%d", time.Now().UnixMilli())

	ws := &WorkSession{
		ID:          id,
		Scope:       scope,
		Description: description,
		StartedAt:   time.Now(),
		Timeout:     timeout,
	}

	e.sessionMu.Lock()
	e.session = ws
	e.sessionMu.Unlock()

	log.Printf("doit: session started: %s (scope: %s, timeout: %v)", id, scope, timeout)
	return id, nil
}

// EndSession ends the work session with the given ID. If id is empty, ends
// any active session. Returns true if a session was ended.
//
// With the `claude -p` migration there is no persistent session state
// to tear down — ending a work session just clears the in-engine
// session struct so subsequent evaluations stop getting the session
// prefix prepended.
func (e *Engine) EndSession(id string) bool {
	e.sessionMu.Lock()
	ws := e.session
	if ws == nil || (id != "" && ws.ID != id) {
		e.sessionMu.Unlock()
		return false
	}
	e.session = nil
	e.sessionMu.Unlock()

	log.Printf("doit: session ended: %s", ws.ID)
	return true
}

// ActiveSession returns the current work session, or nil if none is active.
// Automatically expires sessions that have exceeded their timeout.
func (e *Engine) ActiveSession() *WorkSession {
	e.sessionMu.RLock()
	ws := e.session
	e.sessionMu.RUnlock()

	if ws == nil {
		return nil
	}

	if ws.Expired() {
		if e.EndSession(ws.ID) {
			log.Printf("doit: session auto-expired: %s", ws.ID)
		}
		return nil
	}

	return ws
}

// scriptGateOutcome describes the result of the pre-policy script-hash
// check. The outer script invocation is handled entirely by this gate
// (bypassing L1/L2/L3) when applicable; commands that are not script
// invocations fall through to normal policy.
type scriptGateOutcome struct {
	Applicable bool                   // the command is a recognised script invocation
	Approved   bool                   // Applicable && content hash is in the approval store
	Invocation *script.Invocation     // non-nil when Applicable
	Hash       string                 // content hash when Applicable
	Approval   *ScriptApprovalRequest // non-nil when Applicable && !Approved
	Err        error                  // set when detection or hashing failed
}

// runScriptGate inspects req and returns the outcome of the
// content-hash gate. Never returns nil; check fields to interpret.
func (e *Engine) runScriptGate(req Request) scriptGateOutcome {
	if req.Command == "" {
		return scriptGateOutcome{}
	}
	inv, err := script.Detect(req.Command, req.Cwd)
	if err != nil {
		return scriptGateOutcome{Applicable: true, Err: err}
	}
	if inv == nil {
		return scriptGateOutcome{}
	}

	hash, err := script.Hash(inv.ResolvedPath)
	if err != nil {
		return scriptGateOutcome{Applicable: true, Invocation: inv, Err: err}
	}

	existing, err := e.scriptStore.Lookup(hash)
	if err != nil {
		return scriptGateOutcome{Applicable: true, Invocation: inv, Hash: hash, Err: err}
	}
	if existing != nil {
		return scriptGateOutcome{
			Applicable: true,
			Approved:   true,
			Invocation: inv,
			Hash:       hash,
		}
	}

	preview, _ := script.Preview(inv.ResolvedPath)
	var size int64
	if info, err := os.Stat(inv.ResolvedPath); err == nil {
		size = info.Size()
	}
	return scriptGateOutcome{
		Applicable: true,
		Invocation: inv,
		Hash:       hash,
		Approval: &ScriptApprovalRequest{
			Interpreter:    inv.Interpreter,
			Path:           inv.ResolvedPath,
			ContentHash:    hash,
			ContentPreview: preview,
			SizeBytes:      size,
		},
	}
}

// scriptGateDenialResult builds an EvalResult or Result-shaped denial
// from a script-gate error (detection or hashing failure).
func scriptGateDenyReason(outcome scriptGateOutcome) string {
	return fmt.Sprintf("script-hash gate: %v", outcome.Err)
}

// Evaluate runs the policy chain without executing the command.
// Returns the policy decision. Segment/tier analysis is a detail of the
// individual policy layers and is not surfaced at this level.
func (e *Engine) Evaluate(ctx context.Context, req Request) *EvalResult {
	args := req.args()

	if sg := e.runScriptGate(req); sg.Applicable {
		if sg.Err != nil {
			return &EvalResult{
				Decision: "deny",
				Level:    0,
				Reason:   scriptGateDenyReason(sg),
				RuleID:   "script-hash-error",
			}
		}
		if sg.Approved {
			return &EvalResult{
				Decision: "allow",
				Level:    0,
				Reason:   "script content previously approved",
				RuleID:   "script-hash-approved",
			}
		}
		return &EvalResult{
			Decision:       "escalate",
			Level:          0,
			Reason:         "unapproved script content — requires user review",
			RuleID:         "script-hash-pending",
			Bypassable:     true,
			ScriptApproval: sg.Approval,
		}
	}

	result, _, _, _ := e.evaluatePolicy(ctx, args, req)
	if result == nil {
		return &EvalResult{
			Decision: "escalate",
			Level:    0,
			Reason:   "no policy engine configured or parse failed",
		}
	}
	return &EvalResult{
		Decision:   result.Decision.String(),
		Level:      result.Level,
		Reason:     result.Reason,
		RuleID:     result.RuleID,
		Bypassable: result.Bypassable,
	}
}

// handleScriptGate short-circuits Execute-style flows when the outer
// command is a shell-script invocation. Returns (result, true) when the
// script gate handled the request (denial, escalation, or approved run);
// returns (nil, false) when policy should proceed normally.
func (e *Engine) handleScriptGate(ctx context.Context, req Request, stdout, stderr io.Writer) (*Result, bool) {
	sg := e.runScriptGate(req)
	if !sg.Applicable {
		return nil, false
	}
	if sg.Err != nil {
		reason := scriptGateDenyReason(sg)
		e.logScriptEvent(req, "deny", "script-hash-error", "", "", reason, 1)
		if stderr != nil {
			fmt.Fprintf(stderr, "doit: %s\n", reason)
		}
		return &Result{
			ExitCode:       1,
			Stderr:         fmt.Sprintf("doit: %s", reason),
			PolicyLevel:    0,
			PolicyDecision: "deny",
			PolicyReason:   reason,
			PolicyRuleID:   "script-hash-error",
		}, true
	}
	if !sg.Approved {
		reason := "unapproved script content — approve via doit_execute elicitation"
		e.logScriptEvent(req, "escalate", "script-hash-pending", sg.Hash, sg.Invocation.ResolvedPath, reason, 1)
		if stderr != nil {
			fmt.Fprintf(stderr, "doit: policy: %s\n", reason)
		}
		return &Result{
			ExitCode:       1,
			Stderr:         fmt.Sprintf("doit: policy: %s", reason),
			PolicyLevel:    0,
			PolicyDecision: "escalate",
			PolicyReason:   reason,
			PolicyRuleID:   "script-hash-pending",
		}, true
	}

	// Approved — record use, run the command, and audit with script fields.
	_ = e.scriptStore.RecordUse(sg.Hash)

	ctx = policy.NewEvalContext(ctx, &policy.EvalInfo{
		Level:         0,
		Decision:      "allow",
		RuleID:        "script-hash-matched",
		Justification: req.Justification,
		SafetyArg:     req.SafetyArg,
	})

	var stdoutBuf, stderrBuf bytes.Buffer
	var outW io.Writer = &stdoutBuf
	var errW io.Writer = &stderrBuf
	if stdout != nil {
		outW = stdout
	}
	if stderr != nil {
		errW = stderr
	}
	exitCode := e.runScriptCommand(ctx, req, sg, outW, errW)

	res := &Result{
		ExitCode:       exitCode,
		PolicyLevel:    0,
		PolicyDecision: "allow",
		PolicyReason:   "script content previously approved",
		PolicyRuleID:   "script-hash-matched",
	}
	if stdout == nil {
		res.Stdout = stdoutBuf.String()
	}
	if stderr == nil {
		res.Stderr = stderrBuf.String()
	}
	return res, true
}

// runScriptCommand runs an approved script invocation via sh -c and
// writes an audit entry that carries the script hash and path.
// Honours req.TimeoutSeconds the same way runShellCommand does.
func (e *Engine) runScriptCommand(ctx context.Context, req Request, sg scriptGateOutcome, stdout, stderr io.Writer) int {
	cmdStr := req.Command

	ctx, cancel := withTimeoutIfSet(ctx, req.TimeoutSeconds)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	configureProcessGroup(cmd)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if req.Cwd != "" {
		cmd.Dir = req.Cwd
	}
	if req.Env != nil {
		cmd.Env = os.Environ()
		for k, v := range req.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	errMsg := ""
	timedOut := false
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			timedOut = true
			exitCode = timeoutExitCode
			errMsg = fmt.Sprintf("timed out after %ds", req.TimeoutSeconds)
			fmt.Fprintf(stderr, "doit: command timed out after %ds\n", req.TimeoutSeconds)
		} else {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 2
				errMsg = err.Error()
				fmt.Fprintf(stderr, "doit: %v\n", err)
			}
		}
	}

	if e.logger != nil {
		opts := &audit.LogOptions{
			PolicyLevel:   0,
			PolicyResult:  "allow",
			PolicyRuleID:  "script-hash-matched",
			Justification: req.Justification,
			SafetyArg:     req.SafetyArg,
			ScriptHash:    sg.Hash,
			ScriptPath:    sg.Invocation.ResolvedPath,
			TimedOut:      timedOut,
			ProjectRoot:   e.projectRoot,
		}
		if req.ExpectedDurationSeconds > 0 {
			opts.ExpectedDuration = float64(req.ExpectedDurationSeconds) * 1000.0
		}
		_ = e.logger.Log(cmdStr, []string{sg.Invocation.Interpreter}, []string{"script"}, exitCode, errMsg, duration, req.Cwd, req.Retry, opts)
	}
	return exitCode
}

// logScriptEvent writes an audit entry for a script-gate denial or
// escalation. No command is executed; duration is 0.
func (e *Engine) logScriptEvent(req Request, decision, ruleID, hash, scriptPath, reason string, exitCode int) {
	if e.logger == nil {
		return
	}
	opts := &audit.LogOptions{
		PolicyLevel:   0,
		PolicyResult:  decision,
		PolicyRuleID:  ruleID,
		Justification: req.Justification,
		SafetyArg:     req.SafetyArg,
		ScriptHash:    hash,
		ScriptPath:    scriptPath,
	}
	_ = e.logger.Log(req.Command, nil, nil, exitCode, reason, 0, req.Cwd, req.Retry, opts)
}

// Execute evaluates policy and, if allowed, runs the command via sh -c.
// Shell composition (pipes, redirects, &&, ||) is handled by the shell;
// doit passes the command string through unchanged.
func (e *Engine) Execute(ctx context.Context, req Request) *Result {
	if res, handled := e.handleScriptGate(ctx, req, nil, nil); handled {
		return res
	}

	args := req.args()

	// Policy evaluation.
	pResult, segments, tiers, l3ev := e.evaluatePolicy(ctx, args, req)

	wasL3 := false
	if pResult != nil {
		if pResult.Decision == policy.Deny {
			e.logPolicyResult(req, args, pResult, segments, tiers, 1, l3ev)
			if pResult.Level == 3 {
				go e.tryPromote()
			}
			return &Result{
				ExitCode:       1,
				Stderr:         fmt.Sprintf("doit: policy: %s", pResult.Reason),
				PolicyLevel:    pResult.Level,
				PolicyDecision: pResult.Decision.String(),
				PolicyReason:   pResult.Reason,
				PolicyRuleID:   pResult.RuleID,
			}
		}

		if pResult.Decision == policy.Escalate && pResult.Level == 3 && e.tokenStore != nil {
			e.logPolicyResult(req, args, pResult, segments, tiers, 1, l3ev)
			token, tokenErr := e.tokenStore.Issue(strings.Join(args, " "), args)
			if tokenErr != nil {
				return &Result{
					ExitCode: 2,
					Stderr:   fmt.Sprintf("doit: token issue: %v", tokenErr),
				}
			}
			stderrMsg := fmt.Sprintf("doit: policy escalation (Level 3): %s\napproval-token: %s\n",
				pResult.Reason, token)
			go e.tryPromote()
			return &Result{
				ExitCode:       1,
				Stderr:         stderrMsg,
				PolicyLevel:    pResult.Level,
				PolicyDecision: pResult.Decision.String(),
				PolicyReason:   pResult.Reason,
				EscalateToken:  token,
			}
		}

		wasL3 = pResult.Level == 3

		ctx = policy.NewEvalContext(ctx, &policy.EvalInfo{
			Level:         pResult.Level,
			Decision:      pResult.Decision.String(),
			RuleID:        pResult.RuleID,
			Justification: req.Justification,
			SafetyArg:     req.SafetyArg,
			L3Evidence:    l3ev,
		})
	}

	// Execute the command.
	var stdoutBuf, stderrBuf bytes.Buffer
	exitCode := e.runCommand(ctx, args, req, &stdoutBuf, &stderrBuf)

	if wasL3 {
		go e.tryPromote()
	}

	res := &Result{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
	}
	if pResult != nil {
		res.PolicyLevel = pResult.Level
		res.PolicyDecision = pResult.Decision.String()
		res.PolicyReason = pResult.Reason
		res.PolicyRuleID = pResult.RuleID
	}
	return res
}

// ExecuteStreaming is like Execute but writes stdout/stderr to the provided
// writers instead of buffering. Returns the result (Stdout/Stderr will be empty).
func (e *Engine) ExecuteStreaming(ctx context.Context, req Request, stdout, stderr io.Writer) *Result {
	if res, handled := e.handleScriptGate(ctx, req, stdout, stderr); handled {
		res.Stdout = ""
		res.Stderr = ""
		return res
	}

	args := req.args()

	pResult, segments, tiers, l3ev := e.evaluatePolicy(ctx, args, req)

	wasL3 := false
	if pResult != nil {
		if pResult.Decision == policy.Deny {
			e.logPolicyResult(req, args, pResult, segments, tiers, 1, l3ev)
			if pResult.Level == 3 {
				go e.tryPromote()
			}
			msg := fmt.Sprintf("doit: policy: %s", pResult.Reason)
			fmt.Fprintln(stderr, msg)
			return &Result{
				ExitCode:       1,
				PolicyLevel:    pResult.Level,
				PolicyDecision: pResult.Decision.String(),
				PolicyReason:   pResult.Reason,
				PolicyRuleID:   pResult.RuleID,
			}
		}

		if pResult.Decision == policy.Escalate && pResult.Level == 3 && e.tokenStore != nil {
			e.logPolicyResult(req, args, pResult, segments, tiers, 1, l3ev)
			token, tokenErr := e.tokenStore.Issue(strings.Join(args, " "), args)
			if tokenErr != nil {
				fmt.Fprintf(stderr, "doit: token issue: %v\n", tokenErr)
				return &Result{ExitCode: 2}
			}
			fmt.Fprintf(stderr, "doit: policy escalation (Level 3): %s\napproval-token: %s\n",
				pResult.Reason, token)
			go e.tryPromote()
			return &Result{
				ExitCode:       1,
				PolicyLevel:    pResult.Level,
				PolicyDecision: pResult.Decision.String(),
				PolicyReason:   pResult.Reason,
				EscalateToken:  token,
			}
		}

		wasL3 = pResult.Level == 3

		ctx = policy.NewEvalContext(ctx, &policy.EvalInfo{
			Level:         pResult.Level,
			Decision:      pResult.Decision.String(),
			RuleID:        pResult.RuleID,
			Justification: req.Justification,
			SafetyArg:     req.SafetyArg,
			L3Evidence:    l3ev,
		})
	}

	exitCode := e.runCommand(ctx, args, req, stdout, stderr)

	if wasL3 {
		go e.tryPromote()
	}

	res := &Result{ExitCode: exitCode}
	if pResult != nil {
		res.PolicyLevel = pResult.Level
		res.PolicyDecision = pResult.Decision.String()
		res.PolicyReason = pResult.Reason
		res.PolicyRuleID = pResult.RuleID
	}
	return res
}

// PolicyStatus returns a summary of the policy engine state.
func (e *Engine) PolicyStatus() map[string]any {
	status := map[string]any{
		"l1_enabled": e.cfg.Policy.Level1Enabled,
		"l2_enabled": e.cfg.Policy.Level2Enabled,
		"l3_enabled": e.cfg.Policy.Level3Enabled,
	}

	e.l1Mu.RLock()
	if e.policyL1 != nil {
		status["l1_rules"] = len(e.policyL1.Rules())
		if sc := e.policyL1.StarlarkRuleCount(); sc > 0 {
			status["l1_starlark_rules"] = sc
		}
	}
	e.l1Mu.RUnlock()

	e.l2Mu.RLock()
	if e.policyL2 != nil {
		status["l2_loaded"] = true
		status["l2_entries"] = e.policyL2.EntryCount()
	}
	e.l2Mu.RUnlock()

	// Count overdue L2 reviews from the store on disk.
	if entries, err := policy.LoadStore(e.storePath); err == nil {
		overdue := 0
		for _, ent := range entries {
			if ent.Approved && !ent.Review.NextReview.IsZero() && policy.NeedsReview(ent.Review.NextReview) {
				overdue++
			}
		}
		if overdue > 0 {
			status["l2_overdue_reviews"] = overdue
		}
	}

	if e.policyL3 != nil {
		status["l3_model"] = e.cfg.Policy.Level3Model
	}

	if ws := e.ActiveSession(); ws != nil {
		status["session"] = map[string]any{
			"id":          ws.ID,
			"scope":       ws.Scope,
			"description": ws.Description,
			"started_at":  ws.StartedAt.Format(time.RFC3339),
			"remaining":   (ws.Timeout - time.Since(ws.StartedAt)).Truncate(time.Second).String(),
		}
	}

	return status
}

// CapabilityInfo describes a registered capability.
type CapabilityInfo struct {
	Name        string
	Tier        string
	Description string
}

// ListCapabilities returns all registered capabilities.
func (e *Engine) ListCapabilities() []CapabilityInfo {
	caps := e.reg.All()
	result := make([]CapabilityInfo, len(caps))
	for i, c := range caps {
		result[i] = CapabilityInfo{
			Name:        c.Name(),
			Tier:        c.Tier().String(),
			Description: c.Description(),
		}
	}
	return result
}

// AuditPath returns the configured audit log path.
func (e *Engine) AuditPath() string {
	return e.cfg.Audit.Path
}

// Config returns the merged configuration the engine is operating under.
// The threat-model-driven check_config consumer needs to inspect tier and
// L3 model settings; exposing the whole config keeps the engine the single
// source of truth without forcing callers to re-load YAML.
func (e *Engine) Config() *config.Config {
	return e.cfg
}

// StorePath returns the L2 policy store path.
func (e *Engine) StorePath() string {
	return e.storePath
}

// StarlarkRulesDir returns the configured Starlark rules directory.
func (e *Engine) StarlarkRulesDir() string {
	return e.cfg.Policy.StarlarkRulesDir
}

// ScriptApprovalStorePath returns the file path backing the
// script-content-hash approval store.
func (e *Engine) ScriptApprovalStorePath() string {
	return e.scriptStore.Path()
}

// DurationStorePath returns the file path backing the learned
// per-pattern duration statistics.
func (e *Engine) DurationStorePath() string {
	return e.durationStore.Path()
}

// LearnDurations refreshes the learned-duration store from the audit
// log synchronously. Returns the number of patterns recorded. Useful
// for tests and admin triggers; background refresh also fires
// automatically alongside auto-promotion.
func (e *Engine) LearnDurations() (int, error) {
	if e.logger == nil {
		return 0, nil
	}
	entries, err := audit.Tail(e.logger.Path(), durationLearnWindow)
	if err != nil {
		return 0, err
	}
	stats := policy.AggregateDurations(entries)
	if len(stats) == 0 {
		return 0, nil
	}
	if err := e.durationStore.Replace(stats); err != nil {
		return 0, err
	}
	return len(stats), nil
}

// ApproveScript records a user approval for a script content hash. The
// pathHint is stored for display/audit context only — identity is by
// hash alone. Writes an audit entry marking the approval.
func (e *Engine) ApproveScript(hash, pathHint, justification string) (*script.Approval, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is required")
	}
	entry, err := e.scriptStore.Approve(hash, pathHint, justification)
	if err != nil {
		return nil, err
	}
	if e.logger != nil {
		opts := &audit.LogOptions{
			PolicyLevel:   0,
			PolicyResult:  "allow",
			PolicyRuleID:  "script-hash-approved",
			Justification: justification,
			ScriptHash:    hash,
			ScriptPath:    pathHint,
		}
		_ = e.logger.Log("<script-approval>", []string{"script"}, []string{"script"}, 0, "", 0, "", false, opts)
	}
	return entry, nil
}

// RevokeScriptApproval removes an approval for the given content hash.
// Returns an error if no such approval exists.
func (e *Engine) RevokeScriptApproval(hash string) error {
	if err := e.scriptStore.Revoke(hash); err != nil {
		return err
	}
	if e.logger != nil {
		opts := &audit.LogOptions{
			PolicyLevel:  0,
			PolicyResult: "deny",
			PolicyRuleID: "script-hash-revoked",
			ScriptHash:   hash,
		}
		_ = e.logger.Log("<script-revocation>", []string{"script"}, []string{"script"}, 0, "", 0, "", false, opts)
	}
	return nil
}

// ListScriptApprovals returns all recorded script approvals.
func (e *Engine) ListScriptApprovals() ([]script.Approval, error) {
	return e.scriptStore.List()
}

// OverdueReviews returns L2 policy entries that are due for review.
func (e *Engine) OverdueReviews() ([]policy.PolicyEntry, error) {
	entries, err := policy.LoadStore(e.storePath)
	if err != nil {
		return nil, err
	}
	var overdue []policy.PolicyEntry
	for _, ent := range entries {
		if ent.Approved && !ent.Review.NextReview.IsZero() && policy.NeedsReview(ent.Review.NextReview) {
			overdue = append(overdue, ent)
		}
	}
	return overdue, nil
}

// SelfAudit runs a self-audit of the policy rules and returns findings.
func (e *Engine) SelfAudit() ([]policy.AuditFinding, error) {
	entries, err := policy.LoadStore(e.storePath)
	if err != nil {
		return nil, fmt.Errorf("load store: %w", err)
	}

	// Collect L1 rule IDs as hint strings.
	var l1Rules []string
	e.l1Mu.RLock()
	if e.policyL1 != nil {
		for _, r := range e.policyL1.Rules() {
			l1Rules = append(l1Rules, r.ID)
		}
	}
	e.l1Mu.RUnlock()

	// Collect Starlark rule IDs from the rules directory.
	var starlarkRules []string
	if dir := e.cfg.Policy.StarlarkRulesDir; dir != "" {
		if starRules, err := doitstar.LoadDir(dir); err == nil {
			for _, r := range starRules {
				starlarkRules = append(starlarkRules, r.ID)
			}
		}
	}

	return policy.AuditRules(l1Rules, entries, starlarkRules), nil
}

// ProjectContext returns the discovered project context, or nil if no project
// root was set or discovery has not been run.
func (e *Engine) ProjectContext() *doitctx.ProjectContext {
	return e.projectCtx
}

// RecordDecision adds a learned policy entry (L2) for a specific command
// pattern and reloads the L2 engine. The cap/subcmd match criteria are
// derived by tokenising the command string.
func (e *Engine) RecordDecision(command, decision string) error {
	if e.storePath == "" {
		return fmt.Errorf("no policy store configured")
	}

	cap := ""
	subcmd := ""
	parts := strings.Fields(command)
	if len(parts) > 0 {
		cap = parts[0]
	}
	if len(parts) > 1 {
		subcmd = parts[1]
	}

	now := time.Now().UTC()
	entry := policy.PolicyEntry{
		ID:          fmt.Sprintf("user-%s-%d", cap, now.UnixMilli()),
		Description: fmt.Sprintf("User %s for %s", decision, command),
		Match: policy.MatchCriteria{
			Cap:    cap,
			Subcmd: subcmd,
		},
		Decision:   decision,
		Reasoning:  "User decision via MCP elicitation",
		Confidence: "high",
		Provenance: "human",
		Approved:   true,
		Review: policy.ReviewSchedule{
			Created:    now,
			NextReview: now.Add(7 * 24 * time.Hour),
		},
	}

	added, err := policy.AppendEntries(e.storePath, []policy.PolicyEntry{entry})
	if err != nil {
		return fmt.Errorf("append policy entry: %w", err)
	}
	if added > 0 {
		e.reloadL2()
	}
	return nil
}

// RuleProposal describes a proposed Starlark rule at a specific generality.
type RuleProposal struct {
	Description string // human-readable description of what this rule covers
	Generality  string // "broad", "moderate", "narrow"
	Source      string // generated Starlark source code
}

// parsedCommand holds the semantic decomposition of a command string.
type parsedCommand struct {
	Cap        string   // capability name (first token)
	Subcmd     string   // subcommand (first non-flag after cap)
	Flags      []string // all flag tokens (normalised)
	Paths      []string // positional args that look like filesystem paths
	Positional []string // all non-flag positional arguments after subcmd
}

// parseCommand decomposes a command string into semantic components.
// It handles combined short flags (-rf → -r, -f), flag=value syntax
// (--output=json → --output), and recognises common subcommand patterns.
func parseCommand(command string) parsedCommand {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return parsedCommand{}
	}

	pc := parsedCommand{Cap: parts[0]}

	// Detect subcommand: first non-flag token after the capability.
	rest := parts[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		pc.Subcmd = rest[0]
		rest = rest[1:]
	}

	for _, arg := range rest {
		if arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "--") {
			// Long flag: split --flag=value into just the flag.
			if eqIdx := strings.Index(arg, "="); eqIdx >= 0 {
				pc.Flags = append(pc.Flags, arg[:eqIdx])
			} else {
				pc.Flags = append(pc.Flags, arg)
			}
		} else if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			// Short flag(s): expand combined flags (-rf → -r, -f).
			// Stop expansion if we hit a digit (e.g. -j4 → -j).
			for i, ch := range arg[1:] {
				if ch >= '0' && ch <= '9' {
					// Numeric value attached to previous flag; keep the flag prefix.
					if i == 0 {
						pc.Flags = append(pc.Flags, "-"+string(arg[1]))
					}
					break
				}
				pc.Flags = append(pc.Flags, "-"+string(ch))
			}
		} else {
			// Positional argument.
			pc.Positional = append(pc.Positional, arg)
			if looksLikePath(arg) {
				pc.Paths = append(pc.Paths, arg)
			}
		}
	}
	return pc
}

// looksLikePath returns true if arg looks like a filesystem path.
func looksLikePath(arg string) bool {
	return strings.HasPrefix(arg, "/") ||
		strings.HasPrefix(arg, "./") ||
		strings.HasPrefix(arg, "../") ||
		strings.Contains(arg, "/")
}

// ProposeRules generates Starlark rule proposals at varying generality levels
// for a given command decision. Returns 2-3 options for the user to choose from.
//
// The parser handles edge cases that simple string splitting misses:
//   - Combined short flags (-rf → -r, -f)
//   - Long flag=value syntax (--output=json → --output flag)
//   - Numeric flag values (-j4 → -j flag)
//   - Path-like positional arguments
func (e *Engine) ProposeRules(command string, decision string) []RuleProposal {
	pc := parseCommand(command)
	if pc.Cap == "" {
		return nil
	}

	var proposals []RuleProposal
	decWord := "deny"
	if decision == "allow" {
		decWord = "allow"
	}
	bypassable := decision != "deny"

	// Narrow: exact command pattern (cap + subcmd + specific flags).
	if pc.Subcmd != "" && len(pc.Flags) > 0 {
		ruleID := fmt.Sprintf("%s-%s-%s-flags", decWord, pc.Cap, pc.Subcmd)
		flagLabel := strings.Join(pc.Flags, ", ")

		// Build comprehensive test cases.
		testCases := []doitstar.GenerateTestCase{
			// Exact command that triggered the rule.
			{Command: pc.Cap, Args: append([]string{pc.Subcmd}, pc.Flags...), Expect: decWord},
			// Same subcommand without the flags → should not match.
			{Command: pc.Cap, Args: []string{pc.Subcmd}, Expect: "escalate"},
			// Different subcommand with same flags → should not match.
			{Command: pc.Cap, Args: append([]string{"other"}, pc.Flags...), Expect: "escalate"},
		}
		// Edge case: combined short flags if any short flags are present.
		var shortChars []byte
		for _, f := range pc.Flags {
			if len(f) == 2 && f[0] == '-' && f[1] != '-' {
				shortChars = append(shortChars, f[1])
			}
		}
		if len(shortChars) >= 2 {
			combined := "-" + string(shortChars)
			testCases = append(testCases, doitstar.GenerateTestCase{
				Command: pc.Cap, Args: []string{pc.Subcmd, combined}, Expect: decWord,
			})
		}

		source := doitstar.Generate(doitstar.GenerateRequest{
			RuleID:      ruleID,
			Description: fmt.Sprintf("%s %s %s with %s", upperFirst(decWord), pc.Cap, pc.Subcmd, flagLabel),
			Bypassable:  bypassable,
			Command:     pc.Cap,
			Subcommand:  pc.Subcmd,
			RejectFlags: pc.Flags,
			Decision:    decWord,
			TestCases:   testCases,
		})
		proposals = append(proposals, RuleProposal{
			Description: fmt.Sprintf("%s `%s %s` with %s (narrow)", upperFirst(decWord), pc.Cap, pc.Subcmd, flagLabel),
			Generality:  "narrow",
			Source:      source,
		})
	}

	// Narrow (path-based): cap + subcmd + specific path arguments.
	if pc.Subcmd != "" && len(pc.Paths) > 0 && len(pc.Flags) == 0 {
		ruleID := fmt.Sprintf("%s-%s-%s-paths", decWord, pc.Cap, pc.Subcmd)
		source := doitstar.Generate(doitstar.GenerateRequest{
			RuleID:      ruleID,
			Description: fmt.Sprintf("%s %s %s targeting %s", upperFirst(decWord), pc.Cap, pc.Subcmd, strings.Join(pc.Paths, ", ")),
			Bypassable:  bypassable,
			Command:     pc.Cap,
			Subcommand:  pc.Subcmd,
			RejectPaths: pc.Paths,
			Decision:    decWord,
			TestCases: []doitstar.GenerateTestCase{
				{Command: pc.Cap, Args: append([]string{pc.Subcmd}, pc.Paths...), Expect: decWord},
				{Command: pc.Cap, Args: []string{pc.Subcmd, "safe-path"}, Expect: "escalate"},
				{Command: pc.Cap, Args: []string{pc.Subcmd}, Expect: "escalate"},
			},
		})
		proposals = append(proposals, RuleProposal{
			Description: fmt.Sprintf("%s `%s %s` targeting %s (narrow)", upperFirst(decWord), pc.Cap, pc.Subcmd, strings.Join(pc.Paths, ", ")),
			Generality:  "narrow",
			Source:      source,
		})
	}

	// Narrow (no subcmd, flags only): cap + specific flags.
	if pc.Subcmd == "" && len(pc.Flags) > 0 {
		ruleID := fmt.Sprintf("%s-%s-flags", decWord, pc.Cap)
		flagLabel := strings.Join(pc.Flags, ", ")

		testCases := []doitstar.GenerateTestCase{
			{Command: pc.Cap, Args: pc.Flags, Expect: decWord},
			{Command: pc.Cap, Args: []string{"safe-arg"}, Expect: "escalate"},
		}

		source := doitstar.Generate(doitstar.GenerateRequest{
			RuleID:      ruleID,
			Description: fmt.Sprintf("%s %s with %s", upperFirst(decWord), pc.Cap, flagLabel),
			Bypassable:  bypassable,
			Command:     pc.Cap,
			RejectFlags: pc.Flags,
			Decision:    decWord,
			TestCases:   testCases,
		})
		proposals = append(proposals, RuleProposal{
			Description: fmt.Sprintf("%s `%s` with %s (narrow)", upperFirst(decWord), pc.Cap, flagLabel),
			Generality:  "narrow",
			Source:      source,
		})
	}

	// Narrow (no subcmd, paths only): cap + path arguments.
	if pc.Subcmd == "" && len(pc.Paths) > 0 && len(pc.Flags) == 0 {
		ruleID := fmt.Sprintf("%s-%s-paths", decWord, pc.Cap)
		source := doitstar.Generate(doitstar.GenerateRequest{
			RuleID:      ruleID,
			Description: fmt.Sprintf("%s %s targeting %s", upperFirst(decWord), pc.Cap, strings.Join(pc.Paths, ", ")),
			Bypassable:  bypassable,
			Command:     pc.Cap,
			RejectPaths: pc.Paths,
			Decision:    decWord,
			TestCases: []doitstar.GenerateTestCase{
				{Command: pc.Cap, Args: pc.Paths, Expect: decWord},
				{Command: pc.Cap, Args: []string{"safe-path"}, Expect: "escalate"},
			},
		})
		proposals = append(proposals, RuleProposal{
			Description: fmt.Sprintf("%s `%s` targeting %s (narrow)", upperFirst(decWord), pc.Cap, strings.Join(pc.Paths, ", ")),
			Generality:  "narrow",
			Source:      source,
		})
	}

	// Moderate: cap + subcmd (any flags).
	if pc.Subcmd != "" {
		ruleID := fmt.Sprintf("%s-%s-%s", decWord, pc.Cap, pc.Subcmd)
		source := doitstar.Generate(doitstar.GenerateRequest{
			RuleID:      ruleID,
			Description: fmt.Sprintf("%s %s %s (any flags)", upperFirst(decWord), pc.Cap, pc.Subcmd),
			Bypassable:  bypassable,
			Command:     pc.Cap,
			Subcommand:  pc.Subcmd,
			Decision:    decWord,
			TestCases: []doitstar.GenerateTestCase{
				{Command: pc.Cap, Args: []string{pc.Subcmd}, Expect: decWord},
				{Command: pc.Cap, Args: []string{pc.Subcmd, "--some-flag"}, Expect: decWord},
				{Command: pc.Cap, Args: []string{"other"}, Expect: "escalate"},
			},
		})
		proposals = append(proposals, RuleProposal{
			Description: fmt.Sprintf("%s `%s %s` (any flags) (moderate)", upperFirst(decWord), pc.Cap, pc.Subcmd),
			Generality:  "moderate",
			Source:      source,
		})
	}

	// Broad: cap only (any subcommand, any flags).
	{
		ruleID := fmt.Sprintf("%s-%s", decWord, pc.Cap)
		testCases := []doitstar.GenerateTestCase{
			{Command: pc.Cap, Args: nil, Expect: decWord},
		}
		// Include a different command that should not match.
		otherCap := "other"
		if pc.Cap == "other" {
			otherCap = "different"
		}
		testCases = append(testCases, doitstar.GenerateTestCase{
			Command: otherCap, Args: nil, Expect: "escalate",
		})

		source := doitstar.Generate(doitstar.GenerateRequest{
			RuleID:      ruleID,
			Description: fmt.Sprintf("%s all %s commands", upperFirst(decWord), pc.Cap),
			Bypassable:  bypassable,
			Command:     pc.Cap,
			Decision:    decWord,
			TestCases:   testCases,
		})
		proposals = append(proposals, RuleProposal{
			Description: fmt.Sprintf("%s all `%s` commands (broad)", upperFirst(decWord), pc.Cap),
			Generality:  "broad",
			Source:      source,
		})
	}

	return proposals
}

// WriteStarlarkRule writes a Starlark rule to the rules directory.
func (e *Engine) WriteStarlarkRule(ruleID, source string) error {
	dir := e.cfg.Policy.StarlarkRulesDir
	if dir == "" {
		return fmt.Errorf("no starlark_rules_dir configured")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}
	path := filepath.Join(dir, ruleID+".star")
	return os.WriteFile(path, []byte(source), 0o644)
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ValidateApproval checks an approval token. Returns nil on success.
func (e *Engine) ValidateApproval(token string, args []string) error {
	if e.tokenStore == nil {
		return fmt.Errorf("approval tokens not enabled (L3 disabled)")
	}
	_, err := e.tokenStore.Validate(token, args)
	return err
}

// --- internal ---

func (req *Request) args() []string {
	if len(req.Args) > 0 {
		return req.Args
	}
	if req.Command != "" {
		return strings.Fields(req.Command)
	}
	return nil
}

func (e *Engine) evaluatePolicy(ctx context.Context, args []string, req Request) (result *policy.Result, segments, tiers []string, l3ev *policy.CascadeEvidence) {
	if len(args) == 0 {
		return nil, nil, nil, nil
	}

	// Token validation first.
	if req.Approved != "" && e.tokenStore != nil {
		_, err := e.tokenStore.Validate(req.Approved, args)
		if err != nil {
			return &policy.Result{
				Decision: policy.Deny,
				Level:    3,
				Reason:   fmt.Sprintf("invalid approval token: %v", err),
				RuleID:   "approval-token",
			}, nil, nil, nil
		}
		return &policy.Result{
			Decision: policy.Allow,
			Level:    3,
			Reason:   "approved via approval token",
			RuleID:   "approval-token",
		}, nil, nil, nil
	}

	// Extract the first word as the capability name for tier lookup.
	// This is used only for audit log coarse-filtering (segments/tiers fields).
	// The shell handles all composition (&&, |, ;, etc.) — the full command
	// string is passed to policy layers as an opaque string.
	capName := args[0]
	tier := cap.TierRead
	if c, lookupErr := e.reg.Lookup(capName); lookupErr == nil {
		tier = cap.EffectiveTier(c, args[1:], req.Cwd)
	}
	segments = append(segments, capName)
	tiers = append(tiers, tier.String())

	cmdStr := req.Command
	if cmdStr == "" {
		cmdStr = strings.Join(args, " ")
	}

	policyReq := &policy.Request{
		Command:                 cmdStr,
		Cwd:                     req.Cwd,
		Retry:                   req.Retry,
		Justification:           req.Justification,
		SafetyArg:               req.SafetyArg,
		TimeoutSeconds:          req.TimeoutSeconds,
		ExpectedDurationSeconds: req.ExpectedDurationSeconds,
	}
	if e.projectCtx != nil {
		policyReq.ProjectType = string(e.projectCtx.Type)
	}

	// L1: deterministic rules.
	e.l1Mu.RLock()
	l1 := e.policyL1
	e.l1Mu.RUnlock()
	if l1 != nil {
		result = l1.Evaluate(policyReq)
	} else {
		result = &policy.Result{Decision: policy.Escalate, Level: 1, Reason: "L1 disabled"}
	}

	// L2: learned patterns.
	if result.Decision == policy.Escalate && e.policyL2 != nil {
		e.l2Mu.RLock()
		result = e.policyL2.Evaluate(policyReq)
		e.l2Mu.RUnlock()
	}

	// Duration anomaly sanity check (L2-scope) — fires when the request
	// carries a time expectation that deviates sharply from learned
	// history for this cap+subcmd+project. Skipped under --retry (mirrors
	// L2's own --retry bypass). Runs only when the command would otherwise
	// be allowed or escalated (never overrides a hard deny).
	if !policyReq.Retry && result.Decision != policy.Deny && e.durationStore != nil && (policyReq.ExpectedDurationSeconds > 0 || policyReq.TimeoutSeconds > 0) {
		if stats, err := e.durationStore.LookupForCommand(policyReq.Command, e.projectRoot); err == nil && stats != nil {
			if anomaly := policy.CheckDurationAnomaly(policyReq, stats); anomaly != nil {
				result = anomaly
			}
		}
	}

	// L3: LLM evaluation via `claude -p`. Synchronous — L3 is always
	// available the moment the engine finishes construction, so
	// there is no readiness check here.
	if result.Decision == policy.Escalate && e.policyL3 != nil {
		log.Printf("doit: L3 LLM call starting for %q", policyReq.Command)
		t0 := time.Now()

		maxChars := e.cfg.Audit.L3MaxChars

		ws := e.ActiveSession()
		if ws != nil {
			sessionCtx := &policy.SessionContext{
				Scope:       ws.Scope,
				Description: ws.Description,
			}
			result, l3ev = e.policyL3.EvaluateWithEvidence(ctx, policyReq, sessionCtx, maxChars)
		} else {
			result, l3ev = e.policyL3.EvaluateWithEvidence(ctx, policyReq, nil, maxChars)
		}

		elapsed := time.Since(t0)
		log.Printf("doit: L3 LLM call completed in %v: %s (%s)", elapsed, result.Decision, result.Reason)
	}
	return result, segments, tiers, l3ev
}

func (e *Engine) runCommand(ctx context.Context, args []string, req Request, stdout, stderr io.Writer) int {
	return e.runShellCommand(ctx, args, req, stdout, stderr)
}

// runShellCommand executes a command via sh -c, propagating exit codes.
// When args is non-empty, they are joined to form the command string.
// Honours req.TimeoutSeconds: when > 0, the process is killed on expiry
// via context cancellation.
func (e *Engine) runShellCommand(ctx context.Context, args []string, req Request, stdout, stderr io.Writer) int {
	cmdStr := req.Command
	if len(args) > 0 {
		cmdStr = strings.Join(args, " ")
	}

	ctx, cancel := withTimeoutIfSet(ctx, req.TimeoutSeconds)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	configureProcessGroup(cmd)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if req.Cwd != "" {
		cmd.Dir = req.Cwd
	}
	if req.Env != nil {
		cmd.Env = os.Environ()
		for k, v := range req.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	errMsg := ""
	timedOut := false
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			timedOut = true
			exitCode = timeoutExitCode
			errMsg = fmt.Sprintf("timed out after %ds", req.TimeoutSeconds)
			fmt.Fprintf(stderr, "doit: command timed out after %ds\n", req.TimeoutSeconds)
		} else {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 2
				errMsg = err.Error()
				fmt.Fprintf(stderr, "doit: %v\n", err)
			}
		}
	}

	e.logExecution(ctx, cmdStr, nil, nil, exitCode, errMsg, duration, req, timedOut)
	return exitCode
}

// timeoutExitCode is returned when doit kills a process after its
// timeout expires — 128 + SIGKILL(9) by POSIX convention.
const timeoutExitCode = 137

// withTimeoutIfSet returns a derived context with the given timeout
// applied when seconds > 0; otherwise returns the context unchanged
// with a no-op cancel.
func withTimeoutIfSet(ctx context.Context, seconds int) (context.Context, context.CancelFunc) {
	if seconds <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
}

func (e *Engine) logExecution(ctx context.Context, cmdStr string, segments, tiers []string, exitCode int, errMsg string, duration time.Duration, req Request, timedOut bool) {
	if e.logger == nil {
		return
	}
	opts := &audit.LogOptions{}
	if info := policy.EvalFromContext(ctx); info != nil {
		opts.PolicyLevel = info.Level
		opts.PolicyResult = info.Decision
		opts.PolicyRuleID = info.RuleID
		opts.Justification = info.Justification
		opts.SafetyArg = info.SafetyArg
		if info.L3Evidence != nil {
			opts.L3Fast = info.L3Evidence.Fast
			opts.L3Deep = info.L3Evidence.Deep
		}
	}
	if req.ExpectedDurationSeconds > 0 {
		opts.ExpectedDuration = float64(req.ExpectedDurationSeconds) * 1000.0
	}
	opts.TimedOut = timedOut
	opts.ProjectRoot = e.projectRoot
	_ = e.logger.Log(cmdStr, segments, tiers, exitCode, errMsg, duration, req.Cwd, req.Retry, opts)
}

func (e *Engine) logPolicyResult(req Request, args []string, result *policy.Result, segments, tiers []string, exitCode int, l3ev *policy.CascadeEvidence) {
	if e.logger == nil {
		return
	}
	opts := &audit.LogOptions{
		PolicyLevel:   result.Level,
		PolicyResult:  result.Decision.String(),
		PolicyRuleID:  result.RuleID,
		Justification: req.Justification,
		SafetyArg:     req.SafetyArg,
	}
	if l3ev != nil {
		opts.L3Fast = l3ev.Fast
		opts.L3Deep = l3ev.Deep
	}
	_ = e.logger.Log(
		strings.Join(args, " "),
		segments, tiers,
		exitCode, result.Reason,
		0, req.Cwd, req.Retry, opts,
	)
}

func (e *Engine) tryPromote() {
	if e.logger == nil || e.storePath == "" {
		return
	}
	select {
	case e.promoteCh <- struct{}{}:
		defer func() { <-e.promoteCh }()
	default:
		return
	}

	entries, err := audit.Query(e.logger.Path(), &audit.Filter{PolicyLevel: 3})
	if err != nil {
		log.Printf("doit: auto-promote: query audit log: %v", err)
		return
	}

	candidates := policy.AnalyseL3Decisions(entries, policy.PromoteOptions{})
	if len(candidates) == 0 {
		return
	}

	var newEntries []policy.PolicyEntry
	now := time.Now().UTC()
	for i := range candidates {
		newEntries = append(newEntries, policy.CandidateToEntry(&candidates[i], now))
	}

	added, err := policy.AppendEntries(e.storePath, newEntries)
	if err != nil {
		log.Printf("doit: auto-promote: append entries: %v", err)
		return
	}
	if added > 0 {
		log.Printf("doit: auto-promote: added %d new learned policy entries", added)
		e.reloadL2()
	}

	// Piggy-back duration learning on the same background firing.
	// Cheap enough (single audit tail + aggregate) to co-locate.
	e.tryLearnDurations()
}

// tryLearnDurations aggregates per-pattern duration statistics from the
// audit log and persists them to the duration store. Invoked on the
// same schedule as tryPromote (best-effort, fire-and-forget); failures
// are logged but do not surface to the caller.
func (e *Engine) tryLearnDurations() {
	if e.logger == nil || e.durationStore == nil {
		return
	}
	entries, err := audit.Tail(e.logger.Path(), durationLearnWindow)
	if err != nil {
		log.Printf("doit: learn-durations: tail audit log: %v", err)
		return
	}
	stats := policy.AggregateDurations(entries)
	if len(stats) == 0 {
		return
	}
	if err := e.durationStore.Replace(stats); err != nil {
		log.Printf("doit: learn-durations: save: %v", err)
	}
}

// durationLearnWindow bounds how many recent audit entries we rescan
// to rebuild the learned duration distributions. Large enough for
// meaningful percentile estimates, small enough to stay cheap.
const durationLearnWindow = 5000

func (e *Engine) reloadL2() {
	entries, err := policy.LoadStore(e.storePath)
	if err != nil {
		log.Printf("doit: auto-promote: reload L2: %v", err)
		return
	}
	e.l2Mu.Lock()
	e.policyL2 = policy.NewLevel2(entries)
	e.l2Mu.Unlock()
}
