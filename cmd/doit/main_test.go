// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

// TestServerRecoversFromHandlerPanic is the 🎯T42 regression for the
// process: a panicking tool handler must degrade to a tool error, not
// take the whole MCP server (and every other tool) down with it.
func TestServerRecoversFromHandlerPanic(t *testing.T) {
	srv := newMCPServer("test")
	srv.AddTool(mcp.NewTool("panic_tool"), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		panic("handler exploded")
	})

	c, err := mcpclient.NewInProcessClient(srv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	ctx := context.Background()
	if _, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: "test", Version: "0.0.1"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	result, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "panic_tool"}})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("expected the panic to surface as a tool error")
	}
}
