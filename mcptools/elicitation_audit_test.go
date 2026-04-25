// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/marcelocantos/doit/engine"
	"github.com/marcelocantos/doit/internal/audit"
)

// mockServerElicitationHandler implements server.ElicitationHandler for testing.
// It returns predetermined decisions based on the schema properties in the request.
type mockServerElicitationHandler struct {
	phase1Decision string // decision field value for policy-escalation prompts
	phase2Choice   string // rule description chosen for promotion prompts (empty = decline)
}

func (h *mockServerElicitationHandler) Elicit(_ context.Context, req mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
	schema, _ := req.Params.RequestedSchema.(map[string]any)
	props, _ := schema["properties"].(map[string]any)

	if _, hasDecision := props["decision"]; hasDecision {
		return &mcp.ElicitationResult{
			ElicitationResponse: mcp.ElicitationResponse{
				Action:  mcp.ElicitationResponseActionAccept,
				Content: map[string]any{"decision": h.phase1Decision},
			},
		}, nil
	}
	if _, hasRule := props["rule"]; hasRule {
		if h.phase2Choice == "" {
			return &mcp.ElicitationResult{
				ElicitationResponse: mcp.ElicitationResponse{
					Action: mcp.ElicitationResponseActionDecline,
				},
			}, nil
		}
		return &mcp.ElicitationResult{
			ElicitationResponse: mcp.ElicitationResponse{
				Action:  mcp.ElicitationResponseActionAccept,
				Content: map[string]any{"rule": h.phase2Choice},
			},
		}, nil
	}
	return &mcp.ElicitationResult{
		ElicitationResponse: mcp.ElicitationResponse{Action: mcp.ElicitationResponseActionDecline},
	}, nil
}

// newElicitationClient creates an in-process MCP client wired to a doit engine
// that injects the given server.ElicitationHandler so tests can control Phase 1
// and Phase 2 decisions. Returns the client and the audit log path.
func newElicitationClient(t *testing.T, handler server.ElicitationHandler) (*mcpclient.Client, string) {
	t.Helper()

	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte(
		"tiers:\n  read: true\n  build: true\n  write: true\n  dangerous: true\n"+
			"audit:\n  path: "+auditPath+"\n"+
			"policy:\n  level1_enabled: true\n  level2_enabled: false\n  level3_enabled: false\n",
	), 0600)

	eng, err := engine.New(engine.Options{ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	srv := server.NewMCPServer("doit-test", "0.0.1", server.WithElicitation())
	Register(srv, eng)

	tr := transport.NewInProcessTransportWithOptions(srv, transport.WithElicitationHandler(handler))
	client := mcpclient.NewClient(tr)
	t.Cleanup(func() { client.Close() })

	ctx := context.Background()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := client.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: "test", Version: "0.0.1"},
		},
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return client, auditPath
}

// newElicitationClientWithRules is like newElicitationClient but also configures
// a starlark_rules_dir so rule-writing tests can persist a Starlark rule.
func newElicitationClientWithRules(t *testing.T, handler server.ElicitationHandler) (*mcpclient.Client, string, string) {
	t.Helper()

	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	rulesDir := filepath.Join(dir, "rules")
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte(
		"tiers:\n  read: true\n  build: true\n  write: true\n  dangerous: true\n"+
			"audit:\n  path: "+auditPath+"\n"+
			"policy:\n  level1_enabled: true\n  level2_enabled: false\n  level3_enabled: false\n"+
			"  starlark_rules_dir: "+rulesDir+"\n",
	), 0600)

	eng, err := engine.New(engine.Options{ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	srv := server.NewMCPServer("doit-test", "0.0.1", server.WithElicitation())
	Register(srv, eng)

	tr := transport.NewInProcessTransportWithOptions(srv, transport.WithElicitationHandler(handler))
	client := mcpclient.NewClient(tr)
	t.Cleanup(func() { client.Close() })

	ctx := context.Background()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := client.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: "test", Version: "0.0.1"},
		},
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return client, auditPath, rulesDir
}

// readAuditLog reads all entries from the audit log at path.
func readAuditLog(t *testing.T, path string) []audit.Entry {
	t.Helper()
	entries, err := audit.Tail(path, 1000)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	return entries
}

// findEntry scans entries and returns the first one where predicate returns true.
func findEntry(entries []audit.Entry, predicate func(audit.Entry) bool) *audit.Entry {
	for i := range entries {
		if predicate(entries[i]) {
			return &entries[i]
		}
	}
	return nil
}

// TestElicitationAudit_AllowOnce verifies that an "allow_once" choice produces
// one elicitation entry whose parent_seq points at the command's audit entry.
func TestElicitationAudit_AllowOnce(t *testing.T) {
	handler := &mockServerElicitationHandler{phase1Decision: "allow_once"}
	client, auditPath := newElicitationClient(t, handler)
	ctx := context.Background()

	_, err := client.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "doit_execute",
			Arguments: map[string]any{"command": "git push"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	entries := readAuditLog(t, auditPath)

	cmdEntry := findEntry(entries, func(e audit.Entry) bool {
		return e.ElicitationChoice == "" && e.Pipeline != "<elicitation>" && e.Pipeline != "<elicitation-promotion>"
	})
	elicitEntry := findEntry(entries, func(e audit.Entry) bool {
		return e.ElicitationChoice == "allow_once"
	})

	if cmdEntry == nil {
		t.Fatal("no command entry found in audit log")
	}
	if elicitEntry == nil {
		t.Fatal("no allow_once elicitation entry found in audit log")
	}
	if elicitEntry.ParentSeq != cmdEntry.Seq {
		t.Errorf("elicitation parent_seq=%d, want command seq=%d", elicitEntry.ParentSeq, cmdEntry.Seq)
	}
	if elicitEntry.PolicyResult != "allow_once" {
		t.Errorf("policy_result=%q, want allow_once", elicitEntry.PolicyResult)
	}
	if elicitEntry.ElicitationPrompt == "" {
		t.Error("elicitation_prompt should not be empty")
	}
	if elicitEntry.ElicitationLatencyMs <= 0 {
		t.Errorf("elicitation_latency_ms=%f, want > 0", elicitEntry.ElicitationLatencyMs)
	}
	if elicitEntry.Pipeline != "<elicitation>" {
		t.Errorf("pipeline=%q, want <elicitation>", elicitEntry.Pipeline)
	}
}

// TestElicitationAudit_AllowAlways verifies that "allow_always" produces a Phase 1
// entry plus a Phase 2 entry (here: declined), both linking back to the command entry.
func TestElicitationAudit_AllowAlways_ProducesPhase1AndPhase2(t *testing.T) {
	handler := &mockServerElicitationHandler{
		phase1Decision: "allow_always",
		phase2Choice:   "", // decline promotion
	}
	client, auditPath := newElicitationClient(t, handler)
	ctx := context.Background()

	_, err := client.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "doit_execute",
			Arguments: map[string]any{"command": "git push"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	entries := readAuditLog(t, auditPath)

	cmdEntry := findEntry(entries, func(e audit.Entry) bool {
		return e.ElicitationChoice == "" && e.Pipeline != "<elicitation>" && e.Pipeline != "<elicitation-promotion>"
	})
	phase1Entry := findEntry(entries, func(e audit.Entry) bool {
		return e.ElicitationChoice == "allow_always"
	})
	phase2Entry := findEntry(entries, func(e audit.Entry) bool {
		return e.ElicitationChoice == "proposal_declined"
	})

	if cmdEntry == nil {
		t.Fatal("no command entry found")
	}
	if phase1Entry == nil {
		t.Fatal("no Phase 1 (allow_always) entry found")
	}
	if phase2Entry == nil {
		data, _ := json.MarshalIndent(entries, "", "  ")
		t.Fatalf("no Phase 2 (proposal_declined) entry found. Entries:\n%s", data)
	}

	if phase1Entry.ParentSeq != cmdEntry.Seq {
		t.Errorf("phase1 parent_seq=%d, want %d", phase1Entry.ParentSeq, cmdEntry.Seq)
	}
	if phase2Entry.ParentSeq != cmdEntry.Seq {
		t.Errorf("phase2 parent_seq=%d, want %d", phase2Entry.ParentSeq, cmdEntry.Seq)
	}
	if phase1Entry.PolicyResult != "allow_always" {
		t.Errorf("phase1 policy_result=%q, want allow_always", phase1Entry.PolicyResult)
	}
	if phase2Entry.PolicyResult != "proposal_declined" {
		t.Errorf("phase2 policy_result=%q, want proposal_declined", phase2Entry.PolicyResult)
	}
}

// TestElicitationAudit_ProposalAccepted verifies that an accepted promotion produces
// a Phase 2 entry with ProposedRuleSource, ProposedRuleGenerality, and ProposedRuleID set.
func TestElicitationAudit_ProposalAccepted(t *testing.T) {
	// Discover the broad proposal description without a starlark_rules_dir configured.
	// We need it to choose it via elicitation.
	tmpEng, err := engine.New(engine.Options{ConfigPath: func() string {
		dir := t.TempDir()
		p := filepath.Join(dir, "cfg.yaml")
		os.WriteFile(p, []byte("policy:\n  level1_enabled: true\n  level2_enabled: false\n  level3_enabled: false\n"), 0600)
		return p
	}()})
	if err != nil {
		t.Fatalf("engine for proposals: %v", err)
	}
	proposals := tmpEng.ProposeRules("git push", "allow")
	if len(proposals) == 0 {
		t.Skip("no proposals generated")
	}
	var broadDesc string
	for _, p := range proposals {
		if p.Generality == "broad" {
			broadDesc = p.Description
			break
		}
	}
	if broadDesc == "" {
		t.Skip("no broad proposal found")
	}

	handler := &mockServerElicitationHandler{
		phase1Decision: "allow_always",
		phase2Choice:   broadDesc,
	}
	client, auditPath, _ := newElicitationClientWithRules(t, handler)
	ctx := context.Background()

	_, err = client.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "doit_execute",
			Arguments: map[string]any{"command": "git push"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	entries := readAuditLog(t, auditPath)

	promotionEntry := findEntry(entries, func(e audit.Entry) bool {
		return e.ElicitationChoice == "proposal_accepted"
	})
	if promotionEntry == nil {
		data, _ := json.MarshalIndent(entries, "", "  ")
		t.Fatalf("no proposal_accepted entry found. Entries:\n%s", data)
	}

	if promotionEntry.ProposedRuleSource == "" {
		t.Error("proposed_rule_source should not be empty")
	}
	if promotionEntry.ProposedRuleGenerality != "broad" {
		t.Errorf("proposed_rule_generality=%q, want broad", promotionEntry.ProposedRuleGenerality)
	}
	if promotionEntry.ProposedRuleID == "" {
		t.Error("proposed_rule_id should not be empty")
	}
	if promotionEntry.PolicyResult != "proposal_accepted" {
		t.Errorf("policy_result=%q, want proposal_accepted", promotionEntry.PolicyResult)
	}
}

// TestElicitationAudit_ParentSeqLinking verifies the parent_seq field links back
// to the correct command entry sequence number.
func TestElicitationAudit_ParentSeqLinking(t *testing.T) {
	handler := &mockServerElicitationHandler{phase1Decision: "allow_once"}
	client, auditPath := newElicitationClient(t, handler)
	ctx := context.Background()

	// Run two commands that will be denied by L1 rules; only the second gets elicited.
	// First: an L1 hard deny (no elicitation).
	client.CallTool(ctx, mcp.CallToolRequest{ //nolint:errcheck
		Params: mcp.CallToolParams{
			Name:      "doit_execute",
			Arguments: map[string]any{"command": "rm -rf /"},
		},
	})

	// Second: a bypassable escalation.
	client.CallTool(ctx, mcp.CallToolRequest{ //nolint:errcheck
		Params: mcp.CallToolParams{
			Name:      "doit_execute",
			Arguments: map[string]any{"command": "git push"},
		},
	})

	entries := readAuditLog(t, auditPath)

	// The elicitation entry should link to the git push command, not the rm command.
	elicitEntry := findEntry(entries, func(e audit.Entry) bool {
		return e.ElicitationChoice == "allow_once"
	})
	if elicitEntry == nil {
		t.Fatal("no elicitation entry found")
	}

	linkedEntry := findEntry(entries, func(e audit.Entry) bool {
		return e.Seq == elicitEntry.ParentSeq
	})
	if linkedEntry == nil {
		t.Fatalf("no entry found with seq=%d (parent of elicitation)", elicitEntry.ParentSeq)
	}
	if linkedEntry.Pipeline == "rm -rf /" {
		t.Error("elicitation should not link to the rm -rf / entry")
	}
}
