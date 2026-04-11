# Targets

## Active

(none)

## Achieved

### 🎯T10 L3→L2 auto-promotion detects stable patterns from decision history
- **Value**: 3
- **Cost**: 3
- **Acceptance**:
  - Semantic similarity grouping clusters similar L3 decisions (e.g., go test ./... variants)
  - Conditional branching detection identifies same command approved/denied based on different flags
  - Stable L3 patterns are proposed as L2 entries for human approval via elicitation
  - Auto-promotion runs after L3 decisions (tryPromote already exists, needs elicitation integration)
- **Context**: The claudia session (🎯T8) can analyse L3 decision history for patterns. Instead of simple audit log analysis, the agent uses semantic understanding to cluster similar decisions and propose L2 entries. Runs as a periodic task within the existing claudia session.
- **Tags**: policy, claudia
- **Origin**: roadmap — docs/todo.md Policy Migration
- **Status**: Achieved
- **Discovered**: 2026-04-10
- **Achieved**: 2026-04-11

### 🎯T11 Spaced repetition review keeps learned policy fresh
- **Value**: 3
- **Cost**: 2
- **Acceptance**:
  - L2 entries have ReviewSchedule with next_review dates
  - Overdue entries are surfaced via doit_policy_status or a dedicated review tool
  - Review elicitation presents the entry and asks: keep, modify, or remove
  - Review intervals use spaced repetition (increasing intervals after each confirmation)
- **Context**: L2 entries have ReviewSchedule fields but review is never triggered. Without periodic review, learned policy accumulates stale entries that don't reflect current project reality. Design doc section: Spaced Repetition Review.
- **Tags**: policy
- **Origin**: roadmap — design doc
- **Status**: Achieved
- **Discovered**: 2026-04-10
- **Achieved**: 2026-04-11

### 🎯T12 Gatekeeper self-audit detects dangerous rule combinations and drift
- **Value**: 2
- **Cost**: 3
- **Acceptance**:
  - Periodic audit detects rules that are dangerous in combination
  - Flags rules that have drifted from current project reality
  - Identifies L3 patterns that should have been promoted but weren't
  - Surfaces inconsistencies between L1 Starlark rules and L2 learned entries
- **Context**: The claudia session (🎯T8) can perform holistic rule set review. The agent reads all L1 Starlark rules and L2 entries, reasons about interactions, and flags dangerous combinations or drift. Runs as a periodic or on-demand task.
- **Tags**: policy, safety, claudia
- **Origin**: roadmap — docs/todo.md Gatekeeper Self-Audit
- **Status**: Achieved
- **Discovered**: 2026-04-10
- **Achieved**: 2026-04-11

### 🎯T13 Project context auto-discovery informs policy decisions
- **Value**: 3
- **Cost**: 2
- **Acceptance**:
  - Engine discovers project type from Makefile, go.mod, package.json, etc.
  - Project context influences L1/L2 evaluation (e.g., Go project allows go test)
  - CLAUDE.md is parsed for doit-relevant configuration hints
  - Context is passed to L3 for informed reasoning about command safety
- **Context**: Currently doit treats all commands the same regardless of project context. A Go project should auto-allow go test, a Node project should allow npm test. Per-project config handles explicit rules but auto-discovery handles the common case. Design doc section: Global vs Repo-Level Policy.
- **Tags**: policy, context
- **Origin**: roadmap — docs/todo.md Global vs Repo-Level Policy
- **Status**: Achieved
- **Discovered**: 2026-04-10
- **Achieved**: 2026-04-11

### 🎯T14 Session-scoped gatekeeper uses claudia for context-aware triage
- **Value**: 5
- **Cost**: 3
- **Acceptance**:
  - Worker can introduce a work session via doit_execute metadata (scope, description)
  - Session context persists across evaluations within a declared work session (no /clear)
  - Session agent makes faster, more informed decisions using accumulated work context
  - Session agent can pre-approve patterns within the declared scope
  - Session ends on worker signal or timeout, resuming per-command /clear behavior
- **Context**: With L3 already running as a persistent claudia session (🎯T8), the session agent becomes an extension: workers can introduce a work session with scope/description, and the existing claudia session accumulates that context across evaluations (skip /clear for within-session commands). This builds on top of the L3 claudia integration rather than being a separate system.
- **Tags**: policy, agent, claudia
- **Origin**: roadmap — docs/todo.md Gatekeeper Capabilities
- **Status**: Achieved
- **Discovered**: 2026-04-10
- **Achieved**: 2026-04-11

### 🎯T15 Gatekeeper has read-only repo access for claim verification
- **Value**: 2
- **Cost**: 2
- **Acceptance**:
  - Gatekeeper can read .gitignore to verify 'generated directory' claims
  - Gatekeeper can read build config to verify build-related command justifications
  - Read-only access is enforced — gatekeeper cannot modify the repo
  - Hardcoded allowlist governs which files the gatekeeper can read
- **Context**: When an agent claims 'this directory is generated, safe to delete', the gatekeeper currently takes it at face value. With repo access, it can verify claims against .gitignore, build configs, etc.
- **Tags**: policy, safety
- **Origin**: roadmap — docs/todo.md Gatekeeper Capabilities
- **Status**: Achieved
- **Discovered**: 2026-04-10
- **Achieved**: 2026-04-11

### 🎯T16 doit is the sole execution path — agents have no direct Bash access
- **Value**: 8
- **Cost**: 2
- **Acceptance**:
  - Documentation and agents-guide instruct agents to use only doit_execute
  - Claude Code permission config denies Bash and routes through doit MCP tools
  - Worker CLAUDE.md audit tool verifies doit routing is configured correctly
  - Agents that attempt direct Bash are detected and flagged
- **Context**: The entire security model depends on doit being the sole execution path. If an agent can bypass doit via direct Bash, all policy enforcement is theatre. This is about ensuring the deployment configuration enforces the architecture.
- **Tags**: safety, deployment
- **Origin**: roadmap — design doc core principle
- **Status**: Achieved
- **Discovered**: 2026-04-10
- **Achieved**: 2026-04-11

### 🎯T8 L3 evaluation runs as a persistent claudia session
- **Value**: 5
- **Cost**: 3
- **Acceptance**:
  - doit imports claudia as a Go library dependency
  - Engine.New starts a persistent claudia session when L3 is enabled
  - L3 evaluation sends a structured prompt to the claudia session and parses the response
  - Session /clear runs between evaluations to prevent context cross-contamination
  - L3 escalation fires MCP elicitation with the agent's reasoning
  - L3 decisions are recorded in audit log with level=3
  - Session is gracefully shut down when the engine stops
- **Context**: Instead of a raw LLM API client, L3 uses a persistent claudia session (github.com/marcelocantos/claudia). The session starts with the engine and persists for its lifetime. Each evaluation sends a prompt, gets a decision, then /clear resets context. This gives L3 full Claude Code capabilities (file reading, project context) while maintaining clean evaluation boundaries. Collapses the old L3-as-API-call and session-agent concepts into one architecture.
- **Tags**: policy, llm, claudia
- **Origin**: roadmap — STABILITY.md 1.0 gap
- **Status**: Achieved
- **Discovered**: 2026-04-10
- **Achieved**: 2026-04-11

### 🎯T9 Rule promotion generates high-quality Starlark from L3 context
- **Value**: 3
- **Cost**: 3
- **Acceptance**:
  - Phase 2 elicitation rule proposals include L3 reasoning context
  - Generated Starlark rules handle edge cases (combined flags, flag=value syntax)
  - Generated rules include comprehensive test cases covering allow and deny paths
  - ProposeRules uses command semantics (not just string splitting) to determine generality levels
- **Context**: With L3 running as a claudia session, rule promotion can leverage the agent's full reasoning capability. Instead of simple string splitting, the claudia session generates Starlark rules with semantic understanding of the command, its flags, and the project context. The agent proposes rules at varying generality levels for the phase 2 elicitation.
- **Tags**: policy, starlark, claudia
- **Origin**: roadmap — STABILITY.md 1.0 gap
- **Status**: Achieved
- **Discovered**: 2026-04-10
- **Achieved**: 2026-04-11

### 🎯T7 L2 policy store has an MCP management tool
- **Value**: 5
- **Cost**: 2
- **Acceptance**:
  - doit_policy_list MCP tool shows L2 entries with match criteria, decision, provenance, and review status
  - doit_policy_delete MCP tool removes an L2 entry by ID
  - doit_policy_status reports L2 entry count
- **Context**: Users cannot currently inspect or manage L2 learned policy entries. The only way to see what's been learned is to read the YAML file directly. This is a 1.0 prerequisite (STABILITY.md gap).
- **Tags**: policy, mcp
- **Origin**: roadmap — STABILITY.md 1.0 gap
- **Status**: Achieved
- **Discovered**: 2026-04-10
- **Achieved**: 2026-04-10

### 🎯T1 MCP-first architecture
- **Value**: 5
- **Cost**: 1
- **Acceptance**: TODO
- **Status**: Achieved
- **Discovered**: 2026-04-09

### 🎯T2 sh -c execution model
- **Value**: 4
- **Cost**: 1
- **Acceptance**: TODO
- **Status**: Achieved
- **Discovered**: 2026-04-09

### 🎯T3 Starlark L1 rules
- **Value**: 3
- **Cost**: 2
- **Acceptance**: TODO
- **Status**: Achieved
- **Discovered**: 2026-04-09

### 🎯T4 Per-project policy
- **Value**: 2
- **Cost**: 1
- **Acceptance**: TODO
- **Status**: Achieved
- **Discovered**: 2026-04-09

### 🎯T5 Test coverage for core packages
- **Value**: 3
- **Cost**: 1
- **Acceptance**: TODO
- **Status**: Achieved
- **Discovered**: 2026-04-09

### 🎯T6 Clean up legacy code paths
- **Value**: 1
- **Cost**: 1
- **Acceptance**: TODO
- **Status**: Achieved
- **Discovered**: 2026-04-09
