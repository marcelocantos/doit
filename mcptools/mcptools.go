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
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/marcelocantos/doit/engine"
	"github.com/marcelocantos/doit/internal/audit"
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
					// TODO: Record in L2 learned policy.
					// TODO: Fire elicitation phase 2 for rule promotion.
					return buildResult(result), nil
				case "deny":
					return mcp.NewToolResultError(fmt.Sprintf("Denied by user: %s", command)), nil
				case "deny_always":
					// TODO: Record in L2 learned policy.
					// TODO: Fire elicitation phase 2 for rule promotion.
					return mcp.NewToolResultError(fmt.Sprintf("Denied by user: %s", command)), nil
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

func argString(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}
