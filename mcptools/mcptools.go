// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Package mcptools registers doit's MCP tools on an mcp-go server.
// External consumers call Register to add the full suite of doit tools
// (execute, dry_run, policy management, sessions, audit, repo_read,
// check_config) to their MCP server.
package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/marcelocantos/doit/engine"
	"github.com/marcelocantos/doit/internal/audit"
	"github.com/marcelocantos/doit/internal/config"
	doitctx "github.com/marcelocantos/doit/internal/context"
	"github.com/marcelocantos/doit/internal/policy"
)

// Register adds doit's MCP tools to the given server. The server must
// have been created with server.WithElicitation() for policy escalation
// to work interactively.
func Register(srv *server.MCPServer, eng *engine.Engine) {
	srv.AddTool(
		mcp.NewTool("doit_execute",
			mcp.WithDescription("Execute a command through doit's policy engine. "+
				"Evaluates the command against the three-level policy chain (L1 deterministic → L2 learned → L3 LLM), "+
				"then executes if allowed. Returns stdout, stderr, exit code, and policy metadata."),
			mcp.WithString("command", mcp.Required(), mcp.Description("The command to execute (e.g. 'git status', 'make test')")),
			mcp.WithString("justification", mcp.Description("Why the agent needs this command")),
			mcp.WithString("safety_arg", mcp.Description("Why the agent believes the command is safe")),
			mcp.WithString("cwd", mcp.Description("Working directory for the command")),
			mcp.WithString("approved", mcp.Description("Approval token for previously escalated commands")),
			mcp.WithNumber("timeout_seconds", mcp.Description("Kill the process if it runs longer than this many seconds (0 or omitted = no timeout)")),
			mcp.WithNumber("expected_duration_seconds", mcp.Description("Agent's estimate of how long the command should take; recorded in the audit log for later analysis")),
		),
		handleExecute(srv, eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_dry_run",
			mcp.WithDescription("Evaluate a command against doit's policy engine without executing it. "+
				"Returns the policy decision, level, rule ID, and reason."),
			mcp.WithString("command", mcp.Required(), mcp.Description("The command to evaluate")),
			mcp.WithString("justification", mcp.Description("Why the agent needs this command")),
			mcp.WithString("safety_arg", mcp.Description("Why the agent believes the command is safe")),
			mcp.WithString("cwd", mcp.Description("Working directory context")),
			mcp.WithNumber("timeout_seconds", mcp.Description("Intended kill-after-N-seconds bound (informational for dry-run)")),
			mcp.WithNumber("expected_duration_seconds", mcp.Description("Agent's estimate of how long the command should take (informational for dry-run)")),
		),
		handleDryRun(eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_policy_status",
			mcp.WithDescription("Get the current state of doit's policy engine: which levels are enabled, "+
				"how many L1 rules are loaded, L2 learned policy status, and L3 model."),
		),
		handlePolicyStatus(eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_approve",
			mcp.WithDescription("Validate an approval token for a previously escalated command. "+
				"Tokens are single-use and time-limited."),
			mcp.WithString("token", mcp.Required(), mcp.Description("The approval token")),
			mcp.WithString("command", mcp.Required(), mcp.Description("The original command (must match exactly)")),
		),
		handleApprove(eng),
	)

	// Admin tools.
	srv.AddTool(
		mcp.NewTool("doit_list_capabilities",
			mcp.WithDescription("List all registered capabilities with their safety tiers. "+
				"Optionally filter by tier (read, build, write, dangerous)."),
			mcp.WithString("tier", mcp.Description("Filter by tier: read, build, write, or dangerous")),
		),
		handleListCapabilities(eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_audit_verify",
			mcp.WithDescription("Verify the audit log hash chain integrity. "+
				"Returns OK if the chain is valid, or describes the first violation found."),
		),
		handleAuditVerify(eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_audit_tail",
			mcp.WithDescription("Show the most recent audit log entries."),
			mcp.WithNumber("count", mcp.Description("Number of entries to show (default 20)")),
		),
		handleAuditTail(eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_audit_query",
			mcp.WithDescription("Query the audit log with filters. Returns matching entries oldest-first. "+
				"Primary postmortem path: doit_audit_query(policy_result=\"deny\", latest=true) answers \"the last thing doit refused\"."),
			mcp.WithString("policy_result", mcp.Description("Filter by policy result: allow, deny, escalate, allow_once, allow_always, deny_once, deny_always, proposal_accepted, proposal_declined")),
			mcp.WithNumber("policy_level", mcp.Description("Filter by policy level: 1, 2, or 3")),
			mcp.WithString("rule_id", mcp.Description("Filter by policy rule ID (exact match)")),
			mcp.WithString("cwd_substring", mcp.Description("Filter entries whose cwd contains this substring")),
			mcp.WithString("project_root", mcp.Description("Filter by project root (exact match)")),
			mcp.WithString("since", mcp.Description("Lower bound on timestamp: RFC3339 string OR relative duration like \"1h\", \"30m\", \"24h\"")),
			mcp.WithString("until", mcp.Description("Upper bound on timestamp: same format as since")),
			mcp.WithString("exit_code", mcp.Description("Filter by exit code: integer value OR \"nonzero\" for any non-zero exit")),
			mcp.WithString("cap", mcp.Description("Filter by capability name (exact match against any element of segments)")),
			mcp.WithString("command_substring", mcp.Description("Filter entries whose pipeline field contains this substring")),
			mcp.WithNumber("parent_seq", mcp.Description("Filter by parent_seq (returns child entries for elicitation chain reconstruction)")),
			mcp.WithNumber("limit", mcp.Description("Maximum entries to return (default 20, max 200)")),
			mcp.WithBoolean("latest", mcp.Description("Return only the single most recent matching entry (default false)")),
			mcp.WithString("include", mcp.Description("Comma-separated list of expensive fields to include: l3 (L3Fast/L3Deep), excerpts (stdout_excerpt/stderr_excerpt), elicitation (elicitation fields). Default omits these fields.")),
		),
		handleAuditQuery(eng),
	)

	// Policy management tools.
	srv.AddTool(
		mcp.NewTool("doit_policy_list",
			mcp.WithDescription("List L2 learned policy entries. Shows match criteria, "+
				"decision, provenance, approval status, and review schedule."),
		),
		handlePolicyList(eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_policy_delete",
			mcp.WithDescription("Delete an L2 learned policy entry by ID."),
			mcp.WithString("id", mcp.Required(), mcp.Description("The policy entry ID to delete")),
		),
		handlePolicyDelete(eng),
	)

	// Learned duration statistics.
	srv.AddTool(
		mcp.NewTool("doit_durations_list",
			mcp.WithDescription("List learned per-pattern duration statistics "+
				"(cap, subcmd, sample count, p50/p95 in milliseconds, last updated). "+
				"The store is populated as a by-product of successful executions; "+
				"doit uses it to flag requests whose timeout_seconds or "+
				"expected_duration_seconds deviates sharply from history."),
		),
		handleDurationsList(eng),
	)

	// Script-content-hash approval management.
	srv.AddTool(
		mcp.NewTool("doit_approvals_list",
			mcp.WithDescription("List approved shell-script content hashes. "+
				"Approvals are keyed by SHA-256 of the script contents; the path hint is "+
				"informational. Modifying an approved script changes its hash and forces "+
				"re-approval on next invocation."),
		),
		handleApprovalsList(eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_approvals_revoke",
			mcp.WithDescription("Revoke approval for a script content hash. "+
				"The next invocation of a script with that content will require "+
				"re-approval via elicitation."),
			mcp.WithString("hash", mcp.Required(), mcp.Description("The script content hash to revoke (sha256:...)")),
		),
		handleApprovalsRevoke(eng),
	)

	// Policy review and self-audit tools.
	srv.AddTool(
		mcp.NewTool("doit_policy_review",
			mcp.WithDescription("List L2 learned policy entries that are overdue for review. "+
				"Returns entries with their match criteria, decision, reasoning, and review schedule."),
		),
		handlePolicyReview(eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_self_audit",
			mcp.WithDescription("Run a self-audit of the policy rule set. "+
				"Detects contradictions between L1 and L2 rules, stale entries overdue by 90+ days, "+
				"Starlark rule IDs referenced but not loaded, and duplicate L2 coverage. "+
				"Returns findings with severity markers (error/warning/info)."),
		),
		handleSelfAudit(eng),
	)

	// Session management tools.
	srv.AddTool(
		mcp.NewTool("doit_session_start",
			mcp.WithDescription("Start a work session. During a session, L3 policy evaluations "+
				"accumulate context for faster, more informed decisions. Commands within the declared "+
				"scope are evaluated with session awareness. Sessions auto-expire after timeout."),
			mcp.WithString("scope", mcp.Required(), mcp.Description("The scope of work (e.g. 'go development in pkg/util', 'frontend React refactoring')")),
			mcp.WithString("description", mcp.Description("Detailed description of the work being done")),
			mcp.WithNumber("timeout_minutes", mcp.Description("Session timeout in minutes (default 30)")),
		),
		handleSessionStart(eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_session_end",
			mcp.WithDescription("End an active work session. Resumes per-command context clearing for L3 evaluations."),
			mcp.WithString("session_id", mcp.Description("Session ID to end (ends any active session if omitted)")),
		),
		handleSessionEnd(eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_session_status",
			mcp.WithDescription("Get the current work session status, or 'no active session' if none is active."),
		),
		handleSessionStatus(eng),
	)

	// Repo read tool (🎯T15) — read-only access to a hardcoded allowlist of
	// project files for claim verification.
	srv.AddTool(
		mcp.NewTool("doit_repo_read",
			mcp.WithDescription("Read a file from the project repository for claim verification. "+
				"Only files in the hardcoded allowlist are accessible: "+
				".gitignore, Makefile, go.mod, package.json, Cargo.toml, pyproject.toml, CLAUDE.md, .doit/config.yaml. "+
				"Returns the file contents or an error if the file is not allowed or does not exist."),
			mcp.WithString("filename", mcp.Required(), mcp.Description("File to read (must be in the allowlist)")),
			mcp.WithString("project_root", mcp.Description("Project root directory (defaults to engine project root or cwd)")),
		),
		handleRepoRead(eng),
	)

	// Deployment verification tool.
	srv.AddTool(
		mcp.NewTool("doit_check_config",
			mcp.WithDescription("Verify that the deployed doit configuration matches the safety contract "+
				"described in docs/threat-model.md. Reports each load-bearing setting with its current "+
				"value and the safety-model interpretation, distinguishing settings that have been "+
				"weakened from defaults from those merely informing the user of their responsibilities."),
			mcp.WithString("settings_path", mcp.Description("Path to Claude Code settings.json (default: ~/.claude/settings.json)")),
		),
		handleCheckConfig(eng),
	)
}

func handleExecute(srv *server.MCPServer, eng *engine.Engine) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		command, _ := args["command"].(string)
		if command == "" {
			return mcp.NewToolResultError("missing required parameter: command"), nil
		}

		r := engine.Request{
			Command:                 command,
			Justification:           argString(args, "justification"),
			SafetyArg:               argString(args, "safety_arg"),
			Cwd:                     argString(args, "cwd"),
			Approved:                argString(args, "approved"),
			TimeoutSeconds:          argInt(args, "timeout_seconds"),
			ExpectedDurationSeconds: argInt(args, "expected_duration_seconds"),
		}

		// Phase 1: Evaluate policy before executing.
		evalResult := eng.Evaluate(ctx, r)

		// Script-hash gate: unapproved shell-script invocations use a
		// dedicated elicitation that shows the resolved path and content
		// preview. On approval we persist the hash and re-invoke Execute,
		// which finds the stored hash and runs the script.
		if evalResult.ScriptApproval != nil {
			approved, err := elicitScriptApproval(ctx, srv, evalResult.ScriptApproval)
			if err != nil || !approved {
				return mcp.NewToolResultError(fmt.Sprintf("Script approval denied: %s", evalResult.ScriptApproval.Path)), nil
			}
			if _, err := eng.ApproveScript(
				evalResult.ScriptApproval.ContentHash,
				evalResult.ScriptApproval.Path,
				r.Justification,
			); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to record approval: %v", err)), nil
			}
			return executeAndRespond(ctx, eng, r)
		}

		if evalResult.Decision == "escalate" || evalResult.Decision == "deny" {
			if evalResult.Bypassable || evalResult.Decision == "escalate" {
				prompt := buildElicitationPrompt(command, evalResult)
				t0 := time.Now()
				decision, err := elicitPolicyDecision(ctx, srv, command, evalResult)
				latencyMs := float64(time.Since(t0).Microseconds()) / 1000.0
				if err != nil {
					// Elicitation not supported or failed — fall through to
					// normal execution which will return the denial.
					return executeAndRespond(ctx, eng, r)
				}

				switch decision {
				case "allow_once":
					r.Retry = true
					result := eng.Execute(ctx, r)
					eng.LogElicitationEntry(&audit.LogOptions{ //nolint:errcheck
						PolicyResult:         "allow_once",
						ParentSeq:            result.AuditSeq,
						ElicitationPrompt:    prompt,
						ElicitationChoice:    "allow_once",
						ElicitationLatencyMs: latencyMs,
					})
					return buildResult(result), nil
				case "allow_always":
					r.Retry = true
					result := eng.Execute(ctx, r)
					_ = eng.RecordDecision(command, "allow")
					eng.LogElicitationEntry(&audit.LogOptions{ //nolint:errcheck
						PolicyResult:         "allow_always",
						ParentSeq:            result.AuditSeq,
						ElicitationPrompt:    prompt,
						ElicitationChoice:    "allow_always",
						ElicitationLatencyMs: latencyMs,
					})
					elicitRulePromotion(ctx, srv, eng, command, "allow", result.AuditSeq)
					return buildResult(result), nil
				case "deny":
					eng.LogElicitationEntry(&audit.LogOptions{ //nolint:errcheck
						PolicyResult:         "deny_once",
						ElicitationPrompt:    prompt,
						ElicitationChoice:    "deny_once",
						ElicitationLatencyMs: latencyMs,
					})
					return mcp.NewToolResultError(fmt.Sprintf("Denied by user: %s", command)), nil
				case "deny_always":
					eng.LogElicitationEntry(&audit.LogOptions{ //nolint:errcheck
						PolicyResult:         "deny_always",
						ElicitationPrompt:    prompt,
						ElicitationChoice:    "deny_always",
						ElicitationLatencyMs: latencyMs,
					})
					_ = eng.RecordDecision(command, "deny")
					elicitRulePromotion(ctx, srv, eng, command, "deny", 0)
					return mcp.NewToolResultError(fmt.Sprintf("Denied by user (permanent): %s", command)), nil
				}
			}

			// Non-bypassable denial (hardcoded rule) — no elicitation.
			if evalResult.Decision == "deny" {
				return mcp.NewToolResultError(fmt.Sprintf("Denied by policy (L%d): %s — %s",
					evalResult.Level, evalResult.RuleID, evalResult.Reason)), nil
			}
		}

		return executeAndRespond(ctx, eng, r)
	}
}

// elicitScriptApproval presents an unapproved shell-script invocation to
// the user via MCP elicitation, showing the resolved path, size, hash,
// and a content preview. Returns true if the user approves.
func elicitScriptApproval(ctx context.Context, srv *server.MCPServer, info *engine.ScriptApprovalRequest) (bool, error) {
	message := fmt.Sprintf(
		"Shell script requires content-hash approval (first encounter).\n\n"+
			"Path: %s\nInterpreter: %s\nSize: %d bytes\nHash: %s\n\n"+
			"--- Content preview ---\n%s-----------------------\n\n"+
			"Approval is recorded by content hash: future invocations of the same "+
			"contents run without prompting; modifications force re-approval.",
		info.Path, info.Interpreter, info.SizeBytes, info.ContentHash, info.ContentPreview,
	)

	result, err := srv.RequestElicitation(ctx, mcp.ElicitationRequest{
		Params: mcp.ElicitationParams{
			Message: message,
			RequestedSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"decision": map[string]any{
						"type":        "string",
						"description": "Approve or deny execution of this script content",
						"enum":        []string{"approve", "deny"},
						"default":     "deny",
					},
				},
				"required": []string{"decision"},
			},
		},
	})
	if err != nil {
		return false, err
	}
	if result.Action != mcp.ElicitationResponseActionAccept {
		return false, nil
	}
	data, ok := result.Content.(map[string]any)
	if !ok {
		return false, nil
	}
	decision, _ := data["decision"].(string)
	return decision == "approve", nil
}

// buildElicitationPrompt constructs the prompt text shown to the user for a
// policy escalation/denial, used both for the MCP elicitation message and for
// the audit log's elicitation_prompt field.
func buildElicitationPrompt(command string, eval *engine.EvalResult) string {
	msg := fmt.Sprintf("Policy %s for command: %s\n\nLevel: L%d\nReason: %s",
		eval.Decision, command, eval.Level, eval.Reason)
	if eval.RuleID != "" {
		msg += fmt.Sprintf("\nRule: %s", eval.RuleID)
	}
	return msg
}

// elicitPolicyDecision presents a policy escalation to the user via MCP
// elicitation and returns their choice.
func elicitPolicyDecision(ctx context.Context, srv *server.MCPServer, command string, eval *engine.EvalResult) (string, error) {
	message := buildElicitationPrompt(command, eval)

	result, err := srv.RequestElicitation(ctx, mcp.ElicitationRequest{
		Params: mcp.ElicitationParams{
			Message: message,
			RequestedSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"decision": map[string]any{
						"type":        "string",
						"description": "How to handle this command",
						"enum":        []string{"allow_once", "allow_always", "deny", "deny_always"},
						"default":     "allow_once",
					},
				},
				"required": []string{"decision"},
			},
		},
	})
	if err != nil {
		return "", err
	}

	if result.Action != mcp.ElicitationResponseActionAccept {
		return "deny", nil
	}

	data, ok := result.Content.(map[string]any)
	if !ok {
		return "deny", nil
	}
	decision, _ := data["decision"].(string)
	if decision == "" {
		return "deny", nil
	}
	return decision, nil
}

// elicitRulePromotion fires phase 2 elicitation: propose Starlark rules at
// varying generality levels for the user to choose from. Non-blocking — errors
// are silently ignored (the command decision has already been recorded in L2).
// parentSeq links this Phase 2 entry back to the originating command's audit entry.
func elicitRulePromotion(ctx context.Context, srv *server.MCPServer, eng *engine.Engine, command, decision string, parentSeq uint64) {
	proposals := eng.ProposeRules(command, decision)
	if len(proposals) == 0 {
		return
	}

	// Build enum options from proposals.
	options := make([]string, 0, len(proposals)+1)
	for _, p := range proposals {
		options = append(options, p.Description)
	}
	options = append(options, "No rule — just remember this command")

	promotionPrompt := fmt.Sprintf("Would you like to create a permanent rule for `%s`?", command)
	result, err := srv.RequestElicitation(ctx, mcp.ElicitationRequest{
		Params: mcp.ElicitationParams{
			Message: promotionPrompt,
			RequestedSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"rule": map[string]any{
						"type":        "string",
						"description": "Select a rule to create, or decline",
						"enum":        options,
					},
				},
				"required": []string{"rule"},
			},
		},
	})
	if err != nil || result.Action != mcp.ElicitationResponseActionAccept {
		eng.LogElicitationEntry(&audit.LogOptions{ //nolint:errcheck
			PolicyResult:      "proposal_declined",
			ParentSeq:         parentSeq,
			ElicitationPrompt: promotionPrompt,
			ElicitationChoice: "proposal_declined",
		})
		return
	}

	data, ok := result.Content.(map[string]any)
	if !ok {
		eng.LogElicitationEntry(&audit.LogOptions{ //nolint:errcheck
			PolicyResult:      "proposal_declined",
			ParentSeq:         parentSeq,
			ElicitationPrompt: promotionPrompt,
			ElicitationChoice: "proposal_declined",
		})
		return
	}
	chosen, _ := data["rule"].(string)

	// Find the matching proposal and write the rule.
	for _, p := range proposals {
		if p.Description == chosen {
			ruleID := fmt.Sprintf("user-%s-%d", decision, time.Now().UnixMilli())
			writeErr := eng.WriteStarlarkRule(ruleID, p.Source)
			if writeErr != nil {
				log.Printf("doit: write starlark rule: %v", writeErr)
				ruleID = ""
			}
			eng.LogElicitationEntry(&audit.LogOptions{ //nolint:errcheck
				PolicyResult:           "proposal_accepted",
				ParentSeq:              parentSeq,
				ElicitationPrompt:      promotionPrompt,
				ElicitationChoice:      "proposal_accepted",
				ProposedRuleSource:     p.Source,
				ProposedRuleGenerality: p.Generality,
				ProposedRuleID:         ruleID,
			})
			return
		}
	}

	// User selected "No rule — just remember this command".
	eng.LogElicitationEntry(&audit.LogOptions{ //nolint:errcheck
		PolicyResult:      "proposal_declined",
		ParentSeq:         parentSeq,
		ElicitationPrompt: promotionPrompt,
		ElicitationChoice: "proposal_declined",
	})
}

func executeAndRespond(ctx context.Context, eng *engine.Engine, r engine.Request) (*mcp.CallToolResult, error) {
	result := eng.Execute(ctx, r)
	return buildResult(result), nil
}

func buildResult(result *engine.Result) *mcp.CallToolResult {
	resp := map[string]any{
		"exit_code": result.ExitCode,
	}
	if result.Stdout != "" {
		resp["stdout"] = result.Stdout
	}
	if result.Stderr != "" {
		resp["stderr"] = result.Stderr
	}
	if result.PolicyDecision != "" {
		resp["policy"] = map[string]any{
			"level":    result.PolicyLevel,
			"decision": result.PolicyDecision,
			"reason":   result.PolicyReason,
			"rule_id":  result.PolicyRuleID,
		}
	}
	if result.EscalateToken != "" {
		resp["escalate_token"] = result.EscalateToken
	}

	data, _ := json.MarshalIndent(resp, "", "  ")
	isError := result.ExitCode != 0
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(string(data))},
		IsError: isError,
	}
}

func handleDryRun(eng *engine.Engine) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		command, _ := args["command"].(string)
		if command == "" {
			return mcp.NewToolResultError("missing required parameter: command"), nil
		}

		r := engine.Request{
			Command:                 command,
			Justification:           argString(args, "justification"),
			SafetyArg:               argString(args, "safety_arg"),
			Cwd:                     argString(args, "cwd"),
			TimeoutSeconds:          argInt(args, "timeout_seconds"),
			ExpectedDurationSeconds: argInt(args, "expected_duration_seconds"),
		}

		result := eng.Evaluate(ctx, r)

		var b strings.Builder
		fmt.Fprintf(&b, "Command: %s\n", command)
		fmt.Fprintf(&b, "Decision: %s (Level %d)\n", result.Decision, result.Level)
		fmt.Fprintf(&b, "Reason: %s\n", result.Reason)
		if result.RuleID != "" {
			fmt.Fprintf(&b, "Rule: %s\n", result.RuleID)
		}

		return mcp.NewToolResultText(b.String()), nil
	}
}

func handlePolicyStatus(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		status := eng.PolicyStatus()
		data, _ := json.MarshalIndent(status, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}
}

func handleApprove(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		token, _ := args["token"].(string)
		command, _ := args["command"].(string)
		if token == "" {
			return mcp.NewToolResultError("missing required parameter: token"), nil
		}
		if command == "" {
			return mcp.NewToolResultError("missing required parameter: command"), nil
		}

		cmdArgs := strings.Fields(command)
		if err := eng.ValidateApproval(token, cmdArgs); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("approval failed: %v", err)), nil
		}

		return mcp.NewToolResultText("Approval token validated. Command is now authorized."), nil
	}
}

func handleListCapabilities(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tierFilter := argString(req.GetArguments(), "tier")
		caps := eng.ListCapabilities()

		var b strings.Builder
		for _, c := range caps {
			if tierFilter != "" && c.Tier != tierFilter {
				continue
			}
			fmt.Fprintf(&b, "%-12s %-10s %s\n", c.Name, c.Tier, c.Description)
		}
		if b.Len() == 0 {
			if tierFilter != "" {
				return mcp.NewToolResultText(fmt.Sprintf("No capabilities with tier %q", tierFilter)), nil
			}
			return mcp.NewToolResultText("No capabilities registered"), nil
		}
		return mcp.NewToolResultText(b.String()), nil
	}
}

func handleAuditVerify(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if err := audit.Verify(eng.AuditPath()); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Audit chain violation: %v", err)), nil
		}
		return mcp.NewToolResultText("Audit log integrity verified — hash chain is valid."), nil
	}
}

func handleAuditTail(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		count := 20
		if n, ok := req.GetArguments()["count"].(float64); ok && n > 0 {
			count = int(n)
		}
		entries, err := audit.Tail(eng.AuditPath(), count)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to read audit log: %v", err)), nil
		}
		if len(entries) == 0 {
			return mcp.NewToolResultText("No audit entries."), nil
		}
		data, _ := json.MarshalIndent(entries, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}
}

func handleAuditQuery(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		f := &audit.Filter{}

		if s := argString(args, "policy_result"); s != "" {
			f.PolicyResult = s
		}
		if n := argInt(args, "policy_level"); n != 0 {
			f.PolicyLevel = n
		}
		if s := argString(args, "rule_id"); s != "" {
			f.RuleID = s
		}
		if s := argString(args, "cwd_substring"); s != "" {
			f.CwdSubstring = s
		}
		if s := argString(args, "project_root"); s != "" {
			f.ProjectRoot = s
		}
		if s := argString(args, "since"); s != "" {
			t, err := parseTimeOrDuration(s)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("invalid since: %v", err)), nil
			}
			f.After = t
		}
		if s := argString(args, "until"); s != "" {
			t, err := parseTimeOrDuration(s)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("invalid until: %v", err)), nil
			}
			f.Before = t
		}
		if s := argString(args, "exit_code"); s != "" {
			if s == "nonzero" {
				f.Nonzero = true
			} else {
				// try parsing as int
				code := 0
				if _, err := fmt.Sscanf(s, "%d", &code); err != nil {
					return mcp.NewToolResultError(fmt.Sprintf("invalid exit_code: %q (must be integer or \"nonzero\")", s)), nil
				}
				f.ExitCode = &code
			}
		} else if n, ok := args["exit_code"].(float64); ok {
			code := int(n)
			f.ExitCode = &code
		}
		if s := argString(args, "cap"); s != "" {
			f.Cap = s
		}
		if s := argString(args, "command_substring"); s != "" {
			f.CommandSubstring = s
		}
		if n := argInt(args, "parent_seq"); n != 0 {
			f.ParentSeq = uint64(n)
		}

		limit := 20
		if n := argInt(args, "limit"); n > 0 {
			if n > 200 {
				n = 200
			}
			limit = n
		}
		f.Limit = limit

		latest, _ := args["latest"].(bool)

		include := argString(args, "include")
		includeL3 := strings.Contains(include, "l3")
		includeExcerpts := strings.Contains(include, "excerpts")
		includeElicitation := strings.Contains(include, "elicitation")

		if latest {
			entry, err := audit.QueryLatest(eng.AuditPath(), f)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to query audit log: %v", err)), nil
			}
			if entry == nil {
				return mcp.NewToolResultText(""), nil
			}
			stripFields(entry, includeL3, includeExcerpts, includeElicitation)
			data, _ := json.Marshal(entry)
			return mcp.NewToolResultText(string(data)), nil
		}

		entries, err := audit.Query(eng.AuditPath(), f)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to query audit log: %v", err)), nil
		}
		if len(entries) == 0 {
			return mcp.NewToolResultText(""), nil
		}

		var b strings.Builder
		for i := range entries {
			stripFields(&entries[i], includeL3, includeExcerpts, includeElicitation)
			data, _ := json.Marshal(entries[i])
			b.Write(data)
			b.WriteByte('\n')
		}
		return mcp.NewToolResultText(b.String()), nil
	}
}

// parseTimeOrDuration parses s as either a Go duration (e.g. "1h", "30m") —
// in which case the result is time.Now().Add(-duration) — or an RFC3339
// timestamp. Returns an error if neither parse succeeds.
func parseTimeOrDuration(s string) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("must be a duration (e.g. \"1h\") or RFC3339 timestamp")
}

// stripFields zeroes out expensive/large fields on an entry according to the
// caller's include flags. By default all four sets of heavy fields are
// stripped; passing the corresponding include flag re-enables them.
func stripFields(e *audit.Entry, includeL3, includeExcerpts, includeElicitation bool) {
	if !includeL3 {
		e.L3Fast = nil
		e.L3Deep = nil
	}
	if !includeExcerpts {
		e.StdoutExcerpt = ""
		e.StderrExcerpt = ""
	}
	if !includeElicitation {
		e.ElicitationPrompt = ""
		e.ProposedRuleSource = ""
	}
}

func handlePolicyList(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		entries, err := policy.LoadStore(eng.StorePath())
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to load policy store: %v", err)), nil
		}
		if len(entries) == 0 {
			return mcp.NewToolResultText("No L2 policy entries."), nil
		}
		data, _ := json.MarshalIndent(entries, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}
}

func handlePolicyDelete(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id := argString(req.GetArguments(), "id")
		if id == "" {
			return mcp.NewToolResultError("missing required parameter: id"), nil
		}
		if err := policy.DeleteEntry(eng.StorePath(), id); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Delete failed: %v", err)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Deleted policy entry %q.", id)), nil
	}
}

func handleDurationsList(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		stats, err := policy.NewDurationStore(eng.DurationStorePath()).Load()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to load duration stats: %v", err)), nil
		}
		if len(stats) == 0 {
			return mcp.NewToolResultText("No learned duration statistics."), nil
		}
		data, _ := json.MarshalIndent(stats, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}
}

func handleApprovalsList(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		approvals, err := eng.ListScriptApprovals()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to load approvals: %v", err)), nil
		}
		if len(approvals) == 0 {
			return mcp.NewToolResultText("No approved script hashes."), nil
		}
		data, _ := json.MarshalIndent(approvals, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}
}

func handleApprovalsRevoke(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		hash := argString(req.GetArguments(), "hash")
		if hash == "" {
			return mcp.NewToolResultError("missing required parameter: hash"), nil
		}
		if err := eng.RevokeScriptApproval(hash); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Revoke failed: %v", err)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Revoked approval for %s.", hash)), nil
	}
}

func handleSessionStart(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		scope := argString(args, "scope")
		if scope == "" {
			return mcp.NewToolResultError("missing required parameter: scope"), nil
		}
		description := argString(args, "description")

		timeoutMinutes := 30.0
		if n, ok := args["timeout_minutes"].(float64); ok && n > 0 {
			timeoutMinutes = n
		}
		timeout := time.Duration(timeoutMinutes) * time.Minute

		id, err := eng.StartSession(scope, description, timeout)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to start session: %v", err)), nil
		}

		resp := map[string]any{
			"session_id":      id,
			"scope":           scope,
			"description":     description,
			"timeout_minutes": timeoutMinutes,
		}
		data, _ := json.MarshalIndent(resp, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}
}

func handleSessionEnd(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id := argString(req.GetArguments(), "session_id")
		if eng.EndSession(id) {
			return mcp.NewToolResultText("Session ended."), nil
		}
		if id != "" {
			return mcp.NewToolResultError(fmt.Sprintf("No active session with ID %q", id)), nil
		}
		return mcp.NewToolResultText("No active session to end."), nil
	}
}

func handleSessionStatus(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ws := eng.ActiveSession()
		if ws == nil {
			return mcp.NewToolResultText("No active session."), nil
		}
		remaining := ws.Timeout - time.Since(ws.StartedAt)
		resp := map[string]any{
			"session_id":        ws.ID,
			"scope":             ws.Scope,
			"description":       ws.Description,
			"started_at":        ws.StartedAt.Format(time.RFC3339),
			"remaining_minutes": int(remaining.Minutes()),
		}
		data, _ := json.MarshalIndent(resp, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}
}

func handlePolicyReview(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		overdue, err := eng.OverdueReviews()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to load policy store: %v", err)), nil
		}
		if len(overdue) == 0 {
			return mcp.NewToolResultText("No policy entries due for review."), nil
		}
		data, _ := json.MarshalIndent(overdue, "", "  ")
		return mcp.NewToolResultText(string(data)), nil
	}
}

func handleSelfAudit(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		findings, err := eng.SelfAudit()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Self-audit failed: %v", err)), nil
		}
		if len(findings) == 0 {
			return mcp.NewToolResultText("Self-audit: no issues found."), nil
		}

		var b strings.Builder
		for _, f := range findings {
			var marker string
			switch f.Severity {
			case "error":
				marker = "[ERROR]"
			case "warning":
				marker = "[WARN] "
			default:
				marker = "[INFO] "
			}
			fmt.Fprintf(&b, "%s [%s] %s\n", marker, f.Category, f.Description)
		}
		return mcp.NewToolResultText(b.String()), nil
	}
}

func handleRepoRead(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		filename := argString(args, "filename")
		if filename == "" {
			return mcp.NewToolResultError("missing required parameter: filename"), nil
		}

		projectRoot := argString(args, "project_root")
		if projectRoot == "" {
			// Fall back to cwd. (The engine's ProjectRoot is not stored separately;
			// callers should pass project_root explicitly when known.)
			var err error
			projectRoot, err = os.Getwd()
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("cannot determine project root: %v", err)), nil
			}
		}

		data, err := doitctx.ReadRepoFile(projectRoot, filename)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	}
}

func handleCheckConfig(eng *engine.Engine) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("cannot determine home directory: %v", err)), nil
		}

		settingsPath := argString(req.GetArguments(), "settings_path")
		if settingsPath == "" {
			settingsPath = filepath.Join(homeDir, ".claude", "settings.json")
		}
		claudeJSONPath := filepath.Join(homeDir, ".claude.json")

		cwd, _ := os.Getwd()
		results := []checkResult{
			checkBashDenyStatus(settingsPath),
			checkDoitRegisteredStatus(claudeJSONPath),
			checkSiblingMCPServers(claudeJSONPath),
			checkDangerousTier(eng.Config()),
			checkPolicyStorePermissions(eng),
			checkL3Models(eng.Config()),
			checkProjectConfig(cwd),
		}

		var b strings.Builder
		fmt.Fprintf(&b, "=== doit Configuration Check ===\n")
		fmt.Fprintf(&b, "Reference: %s\n\n", threatModelURL)

		var weakened, info int
		for _, r := range results {
			r.render(&b)
			b.WriteByte('\n')
			switch r.level {
			case checkWarn, checkFail:
				weakened++
			case checkInfo:
				info++
			}
		}

		switch {
		case weakened > 0:
			fmt.Fprintf(&b, "Configuration weakened from the safety-contract baseline — %d item(s) need attention.\n", weakened)
		case info > 0:
			fmt.Fprintf(&b, "doit is correctly configured against the safety contract. %d informational item(s) above describe user responsibilities — review and acknowledge.\n", info)
		default:
			fmt.Fprintf(&b, "doit is correctly configured against the safety contract.\n")
		}

		return mcp.NewToolResultText(b.String()), nil
	}
}

const threatModelURL = "https://github.com/marcelocantos/doit/blob/master/docs/threat-model.md#configuration-assumptions"

// checkLevel classifies a checkResult. checkOK means the threat-model
// baseline holds; checkWarn/checkFail mean it has been weakened; checkInfo
// is for items the threat model labels "user's responsibility" where doit
// can only report state, not assert correctness.
type checkLevel int

const (
	checkOK checkLevel = iota
	checkInfo
	checkWarn
	checkFail
)

// checkResult is a single line in the configuration check output. The
// section field is the stable §N marker tying the result back to a numbered
// item in docs/threat-model.md#configuration-assumptions; tests assert on
// it so output reorganisation does not silently break the cross-reference.
type checkResult struct {
	section   string
	summary   string
	level     checkLevel
	details   []string
	threatRef string
	fix       string
}

func (r checkResult) render(b *strings.Builder) {
	prefix := "[OK]  "
	switch r.level {
	case checkInfo:
		prefix = "[INFO]"
	case checkWarn:
		prefix = "[WARN]"
	case checkFail:
		prefix = "[FAIL]"
	}
	fmt.Fprintf(b, "%s %s %s\n", prefix, r.section, r.summary)
	for _, d := range r.details {
		fmt.Fprintf(b, "       %s\n", d)
	}
	if r.threatRef != "" {
		fmt.Fprintf(b, "       %s\n", r.threatRef)
	}
	if r.fix != "" {
		fmt.Fprintf(b, "       Fix: %s\n", r.fix)
	}
}

func checkBashDenyStatus(settingsPath string) checkResult {
	r := checkResult{
		section:   "§1",
		summary:   "Bash tool is denied in Claude Code settings",
		threatRef: "Threat model §1: without this, Claude Code's built-in Bash tool bypasses doit entirely.",
	}
	denied, err := checkBashDenied(settingsPath)
	switch {
	case err != nil:
		r.level = checkFail
		r.summary = "Cannot read Claude Code settings"
		r.details = []string{fmt.Sprintf("path: %s", settingsPath), fmt.Sprintf("error: %v", err)}
		r.fix = "Create ~/.claude/settings.json or specify settings_path."
	case denied:
		r.details = []string{fmt.Sprintf("settings: %s", settingsPath)}
	default:
		r.level = checkFail
		r.summary = "Bash tool is NOT denied — every L1/L2/L3 control is bypassable"
		r.details = []string{fmt.Sprintf("settings: %s", settingsPath)}
		r.fix = `add {"permissions":{"deny":["Bash"]}} to settings.json.`
	}
	return r
}

func checkDoitRegisteredStatus(claudeJSONPath string) checkResult {
	r := checkResult{
		section:   "§2",
		summary:   "doit MCP server is registered",
		threatRef: "Threat model §2: without registration, doit_execute is unavailable to the agent.",
	}
	registered, err := checkDoitRegistered(claudeJSONPath)
	switch {
	case err != nil:
		r.level = checkFail
		r.summary = "Cannot read Claude config"
		r.details = []string{fmt.Sprintf("path: %s", claudeJSONPath), fmt.Sprintf("error: %v", err)}
	case registered:
		r.details = []string{fmt.Sprintf("config: %s", claudeJSONPath)}
	default:
		r.level = checkFail
		r.summary = "doit MCP server is NOT registered"
		r.details = []string{fmt.Sprintf("config: %s", claudeJSONPath)}
		r.fix = "claude mcp add --scope user --transport stdio doit -- doit"
	}
	return r
}

func checkSiblingMCPServers(claudeJSONPath string) checkResult {
	r := checkResult{
		section:   "§3",
		summary:   "Sibling MCP servers — user must audit for execution-adjacent primitives",
		level:     checkInfo,
		threatRef: "Threat model §3: doit is bypassed by any sibling MCP server that exposes shell, file-write+exec, language runtimes, or HTTP to localhost.",
	}
	siblings, err := listOtherMCPServers(claudeJSONPath)
	if err != nil {
		r.summary = "Sibling MCP servers — cannot enumerate"
		r.details = []string{fmt.Sprintf("path: %s", claudeJSONPath), fmt.Sprintf("error: %v", err)}
		return r
	}
	if len(siblings) == 0 {
		r.summary = "No sibling MCP servers registered"
		return r
	}
	r.details = []string{
		fmt.Sprintf("%d sibling server(s) registered alongside doit:", len(siblings)),
		"  " + strings.Join(siblings, ", "),
		"Automated risk classification is tracked separately (🎯T34); audit manually for now.",
	}
	return r
}

func checkDangerousTier(cfg *config.Config) checkResult {
	r := checkResult{
		section:   "§4",
		summary:   "Dangerous tier is disabled (default)",
		threatRef: "Threat model §4: enabling the dangerous tier allows rm, chmod, and destructive git subcommands.",
	}
	if cfg != nil && cfg.Tiers.Dangerous {
		r.level = checkWarn
		r.summary = "Dangerous tier is ENABLED in config"
		r.details = []string{"rm, chmod, and destructive git subcommands now run without per-command tier gating."}
		r.fix = "set tiers.dangerous: false in ~/.config/doit/config.yaml (or remove the override)."
	}
	return r
}

func checkPolicyStorePermissions(eng *engine.Engine) checkResult {
	r := checkResult{
		section:   "§5",
		summary:   "Policy-store directories are owner-writable only",
		threatRef: "Threat model §5: untrusted write access to L1 rules or the L2 store defeats every policy decision.",
	}
	paths := []string{
		filepath.Dir(config.ConfigPath()),
		filepath.Dir(eng.StorePath()),
	}
	if dir := eng.StarlarkRulesDir(); dir != "" {
		paths = append(paths, dir)
	}

	var writable []string
	var details []string
	for _, p := range uniqueStrings(paths) {
		info, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				details = append(details, fmt.Sprintf("%s: (not yet created — owner will own on first write)", p))
				continue
			}
			details = append(details, fmt.Sprintf("%s: stat error: %v", p, err))
			continue
		}
		mode := info.Mode().Perm()
		details = append(details, fmt.Sprintf("%s: mode %#o", p, mode))
		if mode&0o022 != 0 { // group-write or world-write
			writable = append(writable, p)
		}
	}
	r.details = details
	if len(writable) > 0 {
		r.level = checkFail
		r.summary = "Policy-store directories are writable by group or world"
		r.fix = fmt.Sprintf("chmod 0700 %s", strings.Join(writable, " "))
	}
	return r
}

func checkL3Models(cfg *config.Config) checkResult {
	r := checkResult{
		section:   "§6",
		summary:   "L3 models are at defaults (sonnet fast / opus deep)",
		threatRef: "Threat model §6: a custom L3 model or claude binary may have different security properties.",
	}
	if cfg == nil {
		return r
	}
	fast := cfg.Policy.Level3FastModel
	deep := cfg.Policy.Level3Model
	if fast == "" && deep == "" {
		return r
	}
	r.level = checkInfo
	r.summary = "L3 models are overridden in config"
	if fast != "" {
		r.details = append(r.details, fmt.Sprintf("level3_fast_model: %s", fast))
	}
	if deep != "" {
		r.details = append(r.details, fmt.Sprintf("level3_model: %s", deep))
	}
	r.details = append(r.details, "Confirm the configured models still meet the safety properties the threat model assumes (Claude family, instruction-following).")
	return r
}

func checkProjectConfig(cwd string) checkResult {
	r := checkResult{
		section:   "§7",
		summary:   "No per-project .doit/config.yaml in current directory",
		threatRef: "Threat model §7: project config is additive on top of global config — treat as code from a trusted source.",
	}
	if cwd == "" {
		return r
	}
	path := config.ProjectConfigPath(cwd)
	if _, err := os.Stat(path); err == nil {
		r.level = checkInfo
		r.summary = "Per-project .doit/config.yaml is present"
		r.details = []string{fmt.Sprintf("path: %s", path), "Verify it comes from a trusted source before relying on doit's safety guarantees in this project."}
	}
	return r
}

// listOtherMCPServers walks the same nested mcpServers structure as
// checkDoitRegistered but returns every server name except doit itself.
func listOtherMCPServers(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	seen := map[string]bool{}
	collectMCPServerNames(root, seen)
	delete(seen, "doit")
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func collectMCPServerNames(obj map[string]json.RawMessage, out map[string]bool) {
	if raw, ok := obj["mcpServers"]; ok {
		var servers map[string]json.RawMessage
		if err := json.Unmarshal(raw, &servers); err == nil {
			for name := range servers {
				out[name] = true
			}
		}
	}
	for _, v := range obj {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(v, &nested); err == nil {
			collectMCPServerNames(nested, out)
		}
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// checkBashDenied reads settings.json and returns true if "Bash" appears in
// the permissions.deny list.
func checkBashDenied(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var settings struct {
		Permissions struct {
			Deny []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return false, fmt.Errorf("invalid JSON: %w", err)
	}
	for _, d := range settings.Permissions.Deny {
		if d == "Bash" {
			return true, nil
		}
	}
	return false, nil
}

// checkDoitRegistered reads ~/.claude.json and returns true if a doit MCP
// server entry is present (any entry whose command or name is "doit").
func checkDoitRegistered(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	// ~/.claude.json has a nested structure: {"mcpServers": {"name": {...}}}
	// at the top level or under a "projects" key. We do a simple key search.
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return false, fmt.Errorf("invalid JSON: %w", err)
	}
	return findDoitInMCPServers(root), nil
}

// findDoitInMCPServers recursively searches a JSON object for an mcpServers
// key that contains a "doit" entry.
func findDoitInMCPServers(obj map[string]json.RawMessage) bool {
	if raw, ok := obj["mcpServers"]; ok {
		var servers map[string]json.RawMessage
		if err := json.Unmarshal(raw, &servers); err == nil {
			if _, found := servers["doit"]; found {
				return true
			}
		}
	}
	// Recurse into nested objects (e.g. projects.<path>.mcpServers).
	for _, v := range obj {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(v, &nested); err == nil {
			if findDoitInMCPServers(nested) {
				return true
			}
		}
	}
	return false
}

func argString(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}

// argInt extracts an integer parameter from MCP tool args. Numbers on
// the wire arrive as float64; callers use 0 to mean "not set".
func argInt(args map[string]any, key string) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}
