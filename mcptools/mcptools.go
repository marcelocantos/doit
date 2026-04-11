// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// Package mcptools registers doit's MCP tools on an mcp-go server.
// External consumers call Register to add doit_execute, doit_dry_run,
// doit_policy_status, and doit_approve tools to their MCP server.
package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/marcelocantos/doit/engine"
	"github.com/marcelocantos/doit/internal/audit"
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
		),
		handleExecute(srv, eng),
	)

	srv.AddTool(
		mcp.NewTool("doit_dry_run",
			mcp.WithDescription("Evaluate a command against doit's policy engine without executing it. "+
				"Returns the policy decision, matched segments, and safety tiers."),
			mcp.WithString("command", mcp.Required(), mcp.Description("The command to evaluate")),
			mcp.WithString("justification", mcp.Description("Why the agent needs this command")),
			mcp.WithString("safety_arg", mcp.Description("Why the agent believes the command is safe")),
			mcp.WithString("cwd", mcp.Description("Working directory context")),
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
			mcp.WithDescription("Verify that doit is correctly configured as the sole execution path. "+
				"Checks that the Bash tool is denied in Claude Code settings and that the doit MCP server "+
				"is registered. Returns a report of what is configured correctly and what is missing."),
			mcp.WithString("settings_path", mcp.Description("Path to Claude Code settings.json (default: ~/.claude/settings.json)")),
		),
		handleCheckConfig(),
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
			Command:       command,
			Justification: argString(args, "justification"),
			SafetyArg:     argString(args, "safety_arg"),
			Cwd:           argString(args, "cwd"),
			Approved:      argString(args, "approved"),
		}

		// Phase 1: Evaluate policy before executing.
		evalResult := eng.Evaluate(ctx, r)

		if evalResult.Decision == "escalate" || evalResult.Decision == "deny" {
			if evalResult.Bypassable || evalResult.Decision == "escalate" {
				decision, err := elicitPolicyDecision(ctx, srv, command, evalResult)
				if err != nil {
					// Elicitation not supported or failed — fall through to
					// normal execution which will return the denial.
					return executeAndRespond(ctx, eng, r)
				}

				switch decision {
				case "allow_once":
					r.Retry = true
					return executeAndRespond(ctx, eng, r)
				case "allow_always":
					r.Retry = true
					result := eng.Execute(ctx, r)
					_ = eng.RecordDecision(command, evalResult.Segments, "allow")
					elicitRulePromotion(ctx, srv, eng, command, "allow")
					return buildResult(result), nil
				case "deny":
					return mcp.NewToolResultError(fmt.Sprintf("Denied by user: %s", command)), nil
				case "deny_always":
					_ = eng.RecordDecision(command, evalResult.Segments, "deny")
					elicitRulePromotion(ctx, srv, eng, command, "deny")
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

// elicitPolicyDecision presents a policy escalation to the user via MCP
// elicitation and returns their choice.
func elicitPolicyDecision(ctx context.Context, srv *server.MCPServer, command string, eval *engine.EvalResult) (string, error) {
	message := fmt.Sprintf("Policy %s for command: %s\n\nLevel: L%d\nReason: %s",
		eval.Decision, command, eval.Level, eval.Reason)
	if eval.RuleID != "" {
		message += fmt.Sprintf("\nRule: %s", eval.RuleID)
	}

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
func elicitRulePromotion(ctx context.Context, srv *server.MCPServer, eng *engine.Engine, command, decision string) {
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

	result, err := srv.RequestElicitation(ctx, mcp.ElicitationRequest{
		Params: mcp.ElicitationParams{
			Message: fmt.Sprintf("Would you like to create a permanent rule for `%s`?", command),
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
		return
	}

	data, ok := result.Content.(map[string]any)
	if !ok {
		return
	}
	chosen, _ := data["rule"].(string)

	// Find the matching proposal and write the rule.
	for _, p := range proposals {
		if p.Description == chosen {
			ruleID := fmt.Sprintf("user-%s-%d", decision, time.Now().UnixMilli())
			if err := eng.WriteStarlarkRule(ruleID, p.Source); err != nil {
				log.Printf("doit: write starlark rule: %v", err)
			}
			return
		}
	}
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
			Command:       command,
			Justification: argString(args, "justification"),
			SafetyArg:     argString(args, "safety_arg"),
			Cwd:           argString(args, "cwd"),
		}

		result := eng.Evaluate(ctx, r)

		var b strings.Builder
		fmt.Fprintf(&b, "Command: %s\n", command)
		fmt.Fprintf(&b, "Decision: %s (Level %d)\n", result.Decision, result.Level)
		fmt.Fprintf(&b, "Reason: %s\n", result.Reason)
		if result.RuleID != "" {
			fmt.Fprintf(&b, "Rule: %s\n", result.RuleID)
		}
		if len(result.Segments) > 0 {
			fmt.Fprintf(&b, "Segments: %v\n", result.Segments)
		}
		if len(result.Tiers) > 0 {
			fmt.Fprintf(&b, "Tiers: %v\n", result.Tiers)
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

func handleCheckConfig() server.ToolHandlerFunc {
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

		var b strings.Builder
		allOK := true

		// Check 1: Bash is denied in settings.json.
		bashDenied, settingsErr := checkBashDenied(settingsPath)
		if settingsErr != nil {
			fmt.Fprintf(&b, "[WARN] Cannot read %s: %v\n", settingsPath, settingsErr)
			allOK = false
		} else if bashDenied {
			fmt.Fprintf(&b, "[OK]   Bash tool is denied in %s\n", settingsPath)
		} else {
			fmt.Fprintf(&b, "[FAIL] Bash tool is NOT denied in %s\n", settingsPath)
			fmt.Fprintf(&b, "       Add {\"permissions\":{\"deny\":[\"Bash\"]}} to enforce doit as sole execution path.\n")
			allOK = false
		}

		// Check 2: doit MCP server is registered in ~/.claude.json.
		doitRegistered, claudeJSONErr := checkDoitRegistered(claudeJSONPath)
		if claudeJSONErr != nil {
			fmt.Fprintf(&b, "[WARN] Cannot read %s: %v\n", claudeJSONPath, claudeJSONErr)
			allOK = false
		} else if doitRegistered {
			fmt.Fprintf(&b, "[OK]   doit MCP server is registered in %s\n", claudeJSONPath)
		} else {
			fmt.Fprintf(&b, "[FAIL] doit MCP server is NOT registered in %s\n", claudeJSONPath)
			fmt.Fprintf(&b, "       Run: claude mcp add --scope user --transport stdio doit -- doit\n")
			allOK = false
		}

		if allOK {
			fmt.Fprintf(&b, "\ndoit is correctly configured as the sole execution path.\n")
		} else {
			fmt.Fprintf(&b, "\nConfiguration incomplete — see FAIL/WARN items above.\n")
		}

		return mcp.NewToolResultText(b.String()), nil
	}
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
