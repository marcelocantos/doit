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
	"github.com/marcelocantos/doit/internal/llm"
	"github.com/marcelocantos/doit/internal/pipeline"
	"github.com/marcelocantos/doit/internal/policy"
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
	Decision   string   // "allow", "deny", "escalate"
	Level      int      // 1, 2, or 3
	Reason     string   // human-readable explanation
	RuleID     string   // which rule matched
	Bypassable bool     // true if the denial can be overridden by the user
	Segments   []string // capability names
	Tiers      []string // tier of each segment
}

// Engine wraps the doit policy chain, capability registry, and audit log.
type Engine struct {
	cfg        *config.Config
	reg        *cap.Registry
	logger     *audit.Logger
	policyL1   *policy.Level1
	policyL2   *policy.Level2
	policyL3   *policy.Level3
	tokenStore *policy.TokenStore
	storePath  string
	promoteCh  chan struct{}

	l1Mu sync.RWMutex
	l2Mu sync.RWMutex
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
		cfg:       cfg,
		reg:       reg,
		logger:    logger,
		storePath: cfg.Policy.Level2Path,
		promoteCh: make(chan struct{}, 1),
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

	// L3: LLM gatekeeper.
	if cfg.Policy.Level3Enabled {
		client := &llm.Client{
			Model:   cfg.Policy.Level3Model,
			Timeout: cfg.Policy.Level3TimeoutDuration(),
		}
		e.policyL3 = policy.NewLevel3(client)
		e.tokenStore = policy.NewTokenStore(policy.DefaultTokenTTL)
	}

	for _, opt := range engineOpts {
		opt(e)
	}

	return e, nil
}

// Evaluate runs the policy chain without executing the command.
// Returns the policy decision, matched segments, and tiers.
func (e *Engine) Evaluate(ctx context.Context, req Request) *EvalResult {
	args := req.args()

	result, segments, tiers := e.evaluatePolicy(ctx, args, req)
	if result == nil {
		return &EvalResult{
			Decision: "escalate",
			Level:    0,
			Reason:   "no policy engine configured or parse failed",
			Segments: segments,
			Tiers:    tiers,
		}
	}
	return &EvalResult{
		Decision:   result.Decision.String(),
		Level:      result.Level,
		Reason:     result.Reason,
		RuleID:     result.RuleID,
		Bypassable: result.Bypassable,
		Segments:   segments,
		Tiers:      tiers,
	}
}

// Execute evaluates policy and, if allowed, runs the command. The command is
// executed via sh -c when Args is empty and Command is set, otherwise through
// the existing pipeline parser.
func (e *Engine) Execute(ctx context.Context, req Request) *Result {
	args := req.args()

	// Policy evaluation.
	pResult, segments, tiers := e.evaluatePolicy(ctx, args, req)

	wasL3 := false
	if pResult != nil {
		if pResult.Decision == policy.Deny {
			e.logPolicyResult(req, args, pResult, segments, tiers, 1)
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
			e.logPolicyResult(req, args, pResult, segments, tiers, 1)
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
	args := req.args()

	pResult, segments, tiers := e.evaluatePolicy(ctx, args, req)

	wasL3 := false
	if pResult != nil {
		if pResult.Decision == policy.Deny {
			e.logPolicyResult(req, args, pResult, segments, tiers, 1)
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
			e.logPolicyResult(req, args, pResult, segments, tiers, 1)
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

	if e.policyL3 != nil {
		status["l3_model"] = e.cfg.Policy.Level3Model
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

// StorePath returns the L2 policy store path.
func (e *Engine) StorePath() string {
	return e.storePath
}

// StarlarkRulesDir returns the configured Starlark rules directory.
func (e *Engine) StarlarkRulesDir() string {
	return e.cfg.Policy.StarlarkRulesDir
}

// RecordDecision adds a learned policy entry (L2) for a specific command
// pattern and reloads the L2 engine.
func (e *Engine) RecordDecision(command string, segments []string, decision string) error {
	if e.storePath == "" {
		return fmt.Errorf("no policy store configured")
	}

	// Build a match criteria from the first segment (capability + subcommand).
	cap := ""
	subcmd := ""
	if len(segments) > 0 {
		parts := strings.SplitN(segments[0], " ", 2)
		cap = parts[0]
		if len(parts) > 1 {
			subcmd = strings.Fields(parts[1])[0]
		}
	}
	if cap == "" {
		// Fall back to parsing command string.
		parts := strings.Fields(command)
		if len(parts) > 0 {
			cap = parts[0]
		}
		if len(parts) > 1 {
			subcmd = parts[1]
		}
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

// ProposeRules generates Starlark rule proposals at varying generality levels
// for a given command decision. Returns 2-3 options for the user to choose from.
func (e *Engine) ProposeRules(command string, decision string) []RuleProposal {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil
	}

	capName := parts[0]
	subcmd := ""
	if len(parts) > 1 && !strings.HasPrefix(parts[1], "-") {
		subcmd = parts[1]
	}

	// Extract flags from the command.
	var flags []string
	for _, arg := range parts[1:] {
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
		}
	}

	var proposals []RuleProposal
	decWord := "deny"
	if decision == "allow" {
		decWord = "allow"
	}
	bypassable := decision != "deny" // allow rules are bypassable

	// Narrow: exact command pattern (cap + subcmd + specific flags).
	if subcmd != "" && len(flags) > 0 {
		ruleID := fmt.Sprintf("%s-%s-%s-%s", decWord, capName, subcmd, strings.Join(flags, "-"))
		source := doitstar.Generate(doitstar.GenerateRequest{
			RuleID:      ruleID,
			Description: fmt.Sprintf("%s %s %s with %s", upperFirst(decWord), capName, subcmd, strings.Join(flags, ", ")),
			Bypassable:  bypassable,
			Command:     capName,
			Subcommand:  subcmd,
			RejectFlags: flags,
			Decision:    decWord,
			TestCases: []doitstar.GenerateTestCase{
				{Command: capName, Args: append([]string{subcmd}, flags...), Expect: decWord},
				{Command: capName, Args: []string{subcmd}, Expect: "escalate"},
			},
		})
		proposals = append(proposals, RuleProposal{
			Description: fmt.Sprintf("%s `%s %s` with %s (narrow)", upperFirst(decWord), capName, subcmd, strings.Join(flags, ", ")),
			Generality:  "narrow",
			Source:      source,
		})
	}

	// Moderate: cap + subcmd (any flags).
	if subcmd != "" {
		ruleID := fmt.Sprintf("%s-%s-%s", decWord, capName, subcmd)
		source := doitstar.Generate(doitstar.GenerateRequest{
			RuleID:      ruleID,
			Description: fmt.Sprintf("%s %s %s (any flags)", upperFirst(decWord), capName, subcmd),
			Bypassable:  bypassable,
			Command:     capName,
			Subcommand:  subcmd,
			Decision:    decWord,
			TestCases: []doitstar.GenerateTestCase{
				{Command: capName, Args: []string{subcmd}, Expect: decWord},
				{Command: capName, Args: []string{"other"}, Expect: "escalate"},
			},
		})
		proposals = append(proposals, RuleProposal{
			Description: fmt.Sprintf("%s `%s %s` (any flags) (moderate)", upperFirst(decWord), capName, subcmd),
			Generality:  "moderate",
			Source:      source,
		})
	}

	// Broad: cap only (any subcommand, any flags).
	{
		ruleID := fmt.Sprintf("%s-%s", decWord, capName)
		source := doitstar.Generate(doitstar.GenerateRequest{
			RuleID:      ruleID,
			Description: fmt.Sprintf("%s all %s commands", upperFirst(decWord), capName),
			Bypassable:  bypassable,
			Command:     capName,
			Decision:    decWord,
			TestCases: []doitstar.GenerateTestCase{
				{Command: capName, Args: nil, Expect: decWord},
			},
		})
		proposals = append(proposals, RuleProposal{
			Description: fmt.Sprintf("%s all `%s` commands (broad)", upperFirst(decWord), capName),
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

func (e *Engine) evaluatePolicy(ctx context.Context, args []string, req Request) (result *policy.Result, segments, tiers []string) {
	if len(args) == 0 {
		return nil, nil, nil
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
			}, nil, nil
		}
		return &policy.Result{
			Decision: policy.Allow,
			Level:    3,
			Reason:   "approved via approval token",
			RuleID:   "approval-token",
		}, nil, nil
	}

	cmd, err := pipeline.ParseCommand(args, e.reg)
	if err != nil {
		return nil, nil, nil
	}

	var policySegs []policy.Segment
	hasRedirectOut := false
	for _, step := range cmd.Steps {
		if step.Pipeline.RedirectOut != "" {
			hasRedirectOut = true
		}
		for _, seg := range step.Pipeline.Segments {
			tier := cap.TierRead
			if c, lookupErr := e.reg.Lookup(seg.CapName); lookupErr == nil {
				tier = c.Tier()
				tiers = append(tiers, tier.String())
			}
			segments = append(segments, seg.CapName)
			policySegs = append(policySegs, policy.Segment{
				CapName: seg.CapName,
				Args:    seg.Args,
				Tier:    tier,
			})
		}
	}

	policyReq := &policy.Request{
		Command:        strings.Join(args, " "),
		Segments:       policySegs,
		Cwd:            req.Cwd,
		Retry:          req.Retry,
		HasRedirectOut: hasRedirectOut,
		Justification:  req.Justification,
		SafetyArg:      req.SafetyArg,
	}

	e.l1Mu.RLock()
	l1 := e.policyL1
	e.l1Mu.RUnlock()
	if l1 != nil {
		result = l1.Evaluate(policyReq)
	} else {
		result = &policy.Result{Decision: policy.Escalate, Level: 1, Reason: "L1 disabled"}
	}
	if result.Decision == policy.Escalate && e.policyL2 != nil {
		e.l2Mu.RLock()
		result = e.policyL2.Evaluate(policyReq)
		e.l2Mu.RUnlock()
	}
	if result.Decision == policy.Escalate && e.policyL3 != nil {
		log.Printf("doit: L3 LLM call starting for %q", policyReq.Command)
		t0 := time.Now()
		result = e.policyL3.Evaluate(ctx, policyReq)
		elapsed := time.Since(t0)
		log.Printf("doit: L3 LLM call completed in %v: %s (%s)", elapsed, result.Decision, result.Reason)
	}
	return result, segments, tiers
}

func (e *Engine) runCommand(ctx context.Context, args []string, req Request, stdout, stderr io.Writer) int {
	return e.runShellCommand(ctx, args, req, stdout, stderr)
}

// runShellCommand executes a command via sh -c, propagating exit codes.
// When args is non-empty, they are joined to form the command string.
func (e *Engine) runShellCommand(ctx context.Context, args []string, req Request, stdout, stderr io.Writer) int {
	cmdStr := req.Command
	if len(args) > 0 {
		cmdStr = strings.Join(args, " ")
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
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
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 2
			errMsg = err.Error()
			fmt.Fprintf(stderr, "doit: %v\n", err)
		}
	}

	e.logExecution(ctx, cmdStr, nil, nil, exitCode, errMsg, duration, req)
	return exitCode
}

func (e *Engine) logExecution(ctx context.Context, cmdStr string, segments, tiers []string, exitCode int, errMsg string, duration time.Duration, req Request) {
	if e.logger == nil {
		return
	}
	var opts *audit.LogOptions
	if info := policy.EvalFromContext(ctx); info != nil {
		opts = &audit.LogOptions{
			PolicyLevel:   info.Level,
			PolicyResult:  info.Decision,
			PolicyRuleID:  info.RuleID,
			Justification: info.Justification,
			SafetyArg:     info.SafetyArg,
		}
	}
	_ = e.logger.Log(cmdStr, segments, tiers, exitCode, errMsg, duration, req.Cwd, req.Retry, opts)
}

func (e *Engine) logPolicyResult(req Request, args []string, result *policy.Result, segments, tiers []string, exitCode int) {
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
}

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
