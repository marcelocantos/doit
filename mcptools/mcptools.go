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
)

// Register adds the four doit MCP tools to the given server.
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
		handleExecute(eng),
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
}

func handleExecute(eng *engine.Engine) server.ToolHandlerFunc {
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

		result := eng.Execute(ctx, r)

		// Build a structured response.
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
		}, nil
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

func argString(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}
