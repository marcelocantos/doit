// Copyright 2026 Marcelo Cantos
// SPDX-License-Identifier: Apache-2.0

// doit is an MCP server that exposes doit's policy engine as MCP tools
// over stdio. Register it in ~/.claude.json (or equivalent) to use doit
// as the execution broker for Claude Code.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/mark3labs/mcp-go/server"

	"github.com/marcelocantos/doit/engine"
	"github.com/marcelocantos/doit/mcptools"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	var configPath string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "doit: --config requires a path argument\n")
				return 1
			}
			configPath = args[i+1]
			i++
		case "--version":
			fmt.Printf("doit %s\n", version)
			return 0
		case "--help":
			fmt.Fprintf(os.Stderr, "Usage: doit [--config <path>] [--version] [--help]\n\n")
			fmt.Fprintf(os.Stderr, "MCP server for doit's policy engine (stdio transport).\n")
			return 0
		default:
			fmt.Fprintf(os.Stderr, "doit: unknown flag %q\n", args[i])
			return 1
		}
	}

	eng, err := engine.New(engine.Options{ConfigPath: configPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "doit: %v\n", err)
		return 1
	}

	srv := server.NewMCPServer("doit", version, server.WithElicitation())
	mcptools.Register(srv, eng)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	stdio := server.NewStdioServer(srv)
	if err := stdio.Listen(ctx, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "doit: %v\n", err)
		return 1
	}

	return 0
}
