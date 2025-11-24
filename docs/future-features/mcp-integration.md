# MCP Integration Plan

This document outlines the strategy for integrating the Model Context Protocol (MCP) into Strix, enabling multi-model workflows and external orchestration while preserving native tool performance.

## Table of Contents

- [Overview](#overview)
- [Related Issues](#related-issues)
- [Architecture Options](#architecture-options)
- [LLM Roles Configuration](#llm-roles-configuration)
- [Option A: Strix-Native with zen-mcp](#option-a-strix-native-with-zen-mcp)
- [Option B: External Orchestration](#option-b-external-orchestration)
- [Strix as MCP Server](#strix-as-mcp-server)
- [Configuration Reference](#configuration-reference)
- [Implementation Phases](#implementation-phases)
- [Security Considerations](#security-considerations)

---

## Overview

### The Problem

Strix currently uses a single LLM via LiteLLM. While performant, this limits:

1. **Model specialization**: Different models excel at different tasks
2. **Cost optimization**: Expensive models aren't always needed
3. **External orchestration**: Using Strix from Claude Code, Codex, or Gemini CLI
4. **Validation workflows**: Cross-checking findings with multiple models

### Design Principles

1. **Don't reinvent the wheel**: zen-mcp-server already handles multi-model orchestration
2. **Keep Strix fast**: Native tools remain the execution layer
3. **Configuration over code**: Model routing via YAML, not custom logic
4. **Two clean deployment modes**: Not a complex hybrid

---

## Related Issues

| Issue | Title | Summary |
|-------|-------|---------|
| [#31](https://github.com/usestrix/strix/issues/31) | Integration with OpenAI's Codex | Enable Codex CLI as orchestration layer |
| [#66](https://github.com/usestrix/strix/issues/66) | Add support for Claude Code | Use Claude Code's auth/session management |
| [#109](https://github.com/usestrix/strix/issues/109) | MCP Support | Expose Strix services via MCP protocol |
| [#117](https://github.com/usestrix/strix/issues/117) | Add support for Google Gemini 3.0 | Integrate Gemini as an LLM provider |

---

## Architecture Options

There are two clean deployment architectures. Choose based on your workflow.

### Option A: Strix-Native (Recommended for Speed)

Strix drives the scan, optionally using zen-mcp for multi-model capabilities.

```
┌─────────────────────────────────────────────────────────────────┐
│                         STRIX                                   │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                    STRIX AGENT                             │ │
│  │              (Primary LLM via LiteLLM)                     │ │
│  └─────────────────────────┬─────────────────────────────────┘ │
│                            │                                    │
│            ┌───────────────┼───────────────┐                   │
│            ▼               ▼               ▼                    │
│     ┌────────────┐  ┌────────────┐  ┌────────────┐             │
│     │  NATIVE    │  │ zen-mcp    │  │  LLM       │             │
│     │  TOOLS     │  │ (optional) │  │  ROLES     │             │
│     │  (fast)    │  │            │  │  CONFIG    │             │
│     └────────────┘  └─────┬──────┘  └─────┬──────┘             │
│                           │               │                     │
└───────────────────────────┼───────────────┼─────────────────────┘
                            │               │
                            ▼               ▼
                  ┌──────────────────────────────────┐
                  │        MODEL PROVIDERS           │
                  │  Claude | Gemini | GPT | Ollama  │
                  └──────────────────────────────────┘
```

**When to use**:
- Performance-critical scans
- Single-model workflows
- When you want Strix in control

### Option B: External Orchestration (Recommended for Flexibility)

External AI tool drives the workflow, Strix provides pentest capabilities via MCP.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ORCHESTRATION LAYER                          │
│         (Claude Code / Codex CLI / Gemini CLI / OpenCode)       │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      zen-mcp-server                             │
│                    (Multi-Model Hub)                            │
│                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │  thinkdeep  │  │  consensus  │  │  codereview │            │
│   │  (reasoning)│  │ (validation)│  │  (analysis) │            │
│   └─────────────┘  └─────────────┘  └─────────────┘            │
│                                                                 │
│   Model Routing: fast | thinking | coding | local              │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    STRIX (MCP Server)                           │
│                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│   │  terminal   │  │   browser   │  │    proxy    │            │
│   │  execute    │  │   action    │  │   tools     │            │
│   └─────────────┘  └─────────────┘  └─────────────┘            │
│                                                                 │
│   Pentest Tools in Docker Sandbox                              │
└─────────────────────────────────────────────────────────────────┘
```

**When to use**:
- Conversational workflows ("help me test this API")
- Multi-model validation requirements
- When you want Claude Code/Codex/Gemini in control
- Complex reasoning with specialized model routing

---

## LLM Roles Configuration

Both options benefit from defining model roles. Different tasks need different models.

### Role Definitions

| Role | Purpose | Characteristics | Example Models |
|------|---------|-----------------|----------------|
| `fast` | Quick operations, simple tasks | Low latency, cheap | `gemini-2.0-flash`, `gpt-4o-mini` |
| `local` | Cost-free, offline, privacy | No API calls | `ollama/llama3.1`, `ollama/qwen2.5` |
| `thinking` | Complex reasoning, planning | Deep analysis | `claude-sonnet-4.5`, `o3`, `gemini-3.0-pro` |
| `coding` | Code analysis, exploit dev | Code-optimized | `claude-sonnet-4.5`, `codex-medium` |
| `validation` | Cross-check findings | Different perspective | Model different from primary |

### Configuration File: `llm.yaml`

```yaml
# LLM Roles Configuration
# Define which models to use for different purposes

roles:
  # Primary model for main agent loop
  primary:
    provider: anthropic
    model: claude-sonnet-4-20250514
    description: Main reasoning model for scan orchestration

  # Fast model for quick operations
  fast:
    provider: google
    model: gemini-2.0-flash
    description: Low-latency for simple tasks, progress updates
    max_tokens: 1000

  # Local model for cost savings / offline
  local:
    provider: ollama
    model: llama3.1
    base_url: http://localhost:11434
    description: Free local inference, use when cost-sensitive
    fallback_to: fast  # If Ollama unavailable

  # Thinking model for complex analysis
  thinking:
    provider: google
    model: gemini-3.0-pro
    description: Deep reasoning for vulnerability analysis
    # Alternative: openai/o3, anthropic/claude-sonnet-4.5

  # Coding model for exploit development
  coding:
    provider: anthropic
    model: claude-sonnet-4-20250514
    description: Code generation and analysis
    # Alternative: openai/codex-medium

  # Validation model (intentionally different from primary)
  validation:
    provider: openai
    model: gpt-5-turbo
    description: Cross-validate findings with different model family

# Task-to-role mapping
task_routing:
  # Which role to use for specific operations
  planning: thinking
  reconnaissance: primary
  exploitation: coding
  reporting: fast
  vuln_analysis: thinking
  code_review: coding
  finding_validation: validation

# Cost optimization settings
cost_optimization:
  # Use local model first, fallback to cloud
  prefer_local: true
  local_timeout_seconds: 30

  # Use fast model for operations under N tokens
  fast_threshold_tokens: 500

  # Rate limiting
  rate_limit_delay_seconds: 1
```

### Environment Variable Override

```bash
# Override specific roles via environment
STRIX_LLM_PRIMARY="anthropic/claude-sonnet-4-20250514"
STRIX_LLM_FAST="google/gemini-2.0-flash"
STRIX_LLM_LOCAL="ollama/llama3.1"
STRIX_LLM_THINKING="google/gemini-3.0-pro"
STRIX_LLM_CODING="anthropic/claude-sonnet-4-20250514"
STRIX_LLM_VALIDATION="openai/gpt-5-turbo"

# Local model configuration
LLM_LOCAL_BASE_URL="http://192.168.1.100:11434"

# Or use a single model for everything (current behavior)
STRIX_LLM="anthropic/claude-sonnet-4-20250514"
```

---

## Option A: Strix-Native with zen-mcp

In this mode, Strix runs the scan and optionally uses zen-mcp for multi-model operations.

### Basic Setup (Single Model)

This is the current behavior - no changes needed:

```bash
export STRIX_LLM="anthropic/claude-sonnet-4-20250514"
export LLM_API_KEY="sk-ant-..."
strix --target https://example.com
```

### Enhanced Setup (With LLM Roles)

```bash
# Create llm.yaml with role definitions
strix --target https://example.com --llm-config llm.yaml
```

### With zen-mcp for Multi-Model

```bash
# 1. Start zen-mcp-server
cd zen-mcp-server && ./run-server.sh &

# 2. Configure Strix to use it
export STRIX_ZEN_MCP_SOCKET="/tmp/zen-mcp.sock"

# 3. Run scan - Strix can now use zen-mcp tools
strix --target https://example.com --enable-zen-mcp
```

### When Strix Uses zen-mcp

With zen-mcp enabled, the agent can:

```
Strix Agent: "I found a potential SQLi. Let me validate with another model."
  └─▶ Native: terminal_execute (run sqlmap)
  └─▶ zen-mcp: thinkdeep (analyze with Gemini Pro)
  └─▶ zen-mcp: consensus (get O3 + Claude opinions)
  └─▶ Native: create_vulnerability_report (document finding)
```

### Implementation Requirements

1. **LLM roles config loader** - Parse `llm.yaml` and route by task
2. **zen-mcp client** - Connect to zen-mcp-server as MCP client
3. **Tool routing** - Native tools stay native, zen-mcp tools via MCP

---

## Option B: External Orchestration

In this mode, an external AI tool (Claude Code, Codex, Gemini CLI) orchestrates, with zen-mcp-server in the middle and Strix as a tool provider.

### Architecture Detail

```
┌──────────────────────────────────────────────────────────────────────┐
│                        USER INTERFACE                                │
│              (Claude Code / Codex / Gemini CLI / OpenCode)           │
│                                                                      │
│  User: "Scan example.com for IDOR vulnerabilities"                   │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        zen-mcp-server                                │
│                      (Central MCP Hub)                               │
│                                                                      │
│  Receives request, routes to appropriate model/tool:                 │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    MODEL ROUTING                                │ │
│  │                                                                 │ │
│  │  fast: gemini-2.0-flash     thinking: gemini-3.0-pro           │ │
│  │  coding: claude-4.5         validation: o3                      │ │
│  │  local: ollama/llama3.1                                         │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    BUILT-IN TOOLS                               │ │
│  │                                                                 │ │
│  │  thinkdeep    consensus    codereview    apilookup             │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    CONNECTED MCP SERVERS                        │ │
│  │                                                                 │ │
│  │  strix (pentest tools)    filesystem    git    ...             │ │
│  └────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     STRIX (MCP Server Mode)                          │
│                                                                      │
│  Exposes pentest tools via MCP:                                      │
│                                                                      │
│  Tools:                        Execution:                            │
│  - terminal_execute            Docker sandbox                        │
│  - browser_action              Playwright                            │
│  - python_action               Python runtime                        │
│  - send_request                HTTP client                           │
│  - list_requests               Caido proxy                           │
│  - str_replace_editor          File operations                       │
│  - create_vulnerability_report Reporting                             │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Setup

**1. Configure zen-mcp-server** (`zen-mcp-server/.env`):

```bash
# Model providers
OPENROUTER_API_KEY=...
GOOGLE_API_KEY=...
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...

# Model routing
DEFAULT_MODEL=anthropic/claude-sonnet-4.5
FAST_MODEL=google/gemini-2.0-flash
THINKING_MODEL=google/gemini-3.0-pro
CODING_MODEL=anthropic/claude-sonnet-4.5

# Enable Strix as connected MCP server
MCP_SERVERS='[{"name": "strix", "command": ["strix", "--mcp-server"]}]'
```

**2. Configure Claude Code** (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "zen": {
      "command": "./zen-mcp-server/run-server.sh",
      "env": {
        "MCP_SERVERS": "[{\"name\": \"strix\", \"command\": [\"strix\", \"--mcp-server\"]}]"
      }
    }
  }
}
```

**3. Use from Claude Code**:

```
User: Scan https://api.example.com for authentication bypasses

Claude Code: I'll use the Strix pentest tools to scan this API.

[Invokes zen-mcp → strix tools]
- terminal_execute: nmap port scan
- browser_action: explore authentication endpoints
- send_request: test auth bypass payloads
- thinkdeep: analyze responses for vulnerabilities
- create_vulnerability_report: document findings
```

### Workflow Example

```
User (in Claude Code):
  "Test the /api/users endpoint for IDOR"
       │
       ▼
Claude Code (orchestrator):
  "I'll analyze this systematically"
       │
       ├──▶ zen-mcp: thinkdeep
       │    "Plan IDOR test methodology"
       │    (Uses: gemini-3.0-pro)
       │
       ├──▶ strix: browser_action
       │    "Authenticate and capture session"
       │
       ├──▶ strix: send_request
       │    "GET /api/users/1 with user A session"
       │    "GET /api/users/2 with user A session"
       │
       ├──▶ zen-mcp: consensus
       │    "Is this response an IDOR vulnerability?"
       │    (Uses: claude-4.5 + o3 + gemini-3.0)
       │
       └──▶ strix: create_vulnerability_report
            "Document confirmed IDOR"
```

---

## Strix as MCP Server

Both options require Strix to expose tools via MCP.

### Exposed Tools

| Tool | Description | Sandbox |
|------|-------------|---------|
| `terminal_execute` | Run shell commands | Yes |
| `browser_action` | Playwright browser automation | Yes |
| `python_action` | Execute Python code | Yes |
| `str_replace_editor` | File read/write/edit | Yes |
| `send_request` | HTTP requests | Yes |
| `repeat_request` | Replay captured requests | Yes |
| `list_requests` | View proxy traffic | Yes |
| `view_request` | Inspect request details | Yes |
| `create_vulnerability_report` | Document findings | No |
| `web_search` | Perplexity search | No |

### NOT Exposed (Internal Only)

| Tool | Reason |
|------|--------|
| `create_agent` | Internal orchestration |
| `agent_finish` | Internal lifecycle |
| `send_message_to_agent` | Internal messaging |
| `think` | Internal reasoning |
| `finish_scan` | Internal completion |

### MCP Server Implementation

```python
# strix/mcp/server.py

from mcp import Server
from strix.tools.registry import get_mcp_exposed_tools, get_tool_by_name
from strix.tools.executor import execute_tool

class StrixMCPServer:
    def __init__(self):
        self.server = Server("strix")
        self._register_tools()

    def _register_tools(self):
        for tool_def in get_mcp_exposed_tools():
            self.server.register_tool(
                name=tool_def.name,
                description=tool_def.description,
                input_schema=tool_def.to_mcp_schema(),
                handler=self._create_handler(tool_def.name)
            )

    def _create_handler(self, tool_name: str):
        async def handler(**kwargs):
            result = await execute_tool(tool_name, agent_state=None, **kwargs)
            return result
        return handler
```

### Running as MCP Server

```bash
# Standalone server (stdio for Claude Code)
strix --mcp-server

# HTTP server (for remote connections)
strix --mcp-server --transport http --port 8080

# Unix socket
strix --mcp-server --transport socket --path /tmp/strix.sock
```

---

## Configuration Reference

### Full Configuration File: `strix.config.yaml`

```yaml
# Strix Configuration with MCP and LLM Roles

#──────────────────────────────────────────────────────────────────────
# LLM ROLES
# Define models for different purposes
#──────────────────────────────────────────────────────────────────────
llm:
  roles:
    primary:
      provider: anthropic
      model: claude-sonnet-4-20250514
      api_key: ${ANTHROPIC_API_KEY}

    fast:
      provider: google
      model: gemini-2.0-flash
      api_key: ${GOOGLE_API_KEY}

    local:
      provider: ollama
      model: llama3.1
      base_url: ${OLLAMA_BASE_URL:-http://localhost:11434}

    thinking:
      provider: google
      model: gemini-3.0-pro
      api_key: ${GOOGLE_API_KEY}

    coding:
      provider: anthropic
      model: claude-sonnet-4-20250514
      api_key: ${ANTHROPIC_API_KEY}

    validation:
      provider: openai
      model: gpt-5-turbo
      api_key: ${OPENAI_API_KEY}

  # Map tasks to roles
  routing:
    default: primary
    quick_tasks: fast
    planning: thinking
    code_analysis: coding
    finding_validation: validation

    # Use local when available for these
    prefer_local:
      - quick_tasks
      - progress_updates

  # Cost controls
  cost:
    prefer_local: true
    fast_threshold_tokens: 500
    rate_limit_delay: 1.0

#──────────────────────────────────────────────────────────────────────
# MCP SERVER
# Expose Strix tools via MCP
#──────────────────────────────────────────────────────────────────────
mcp:
  server:
    enabled: false  # Enable with --mcp-server flag
    transport: stdio  # stdio | http | socket
    port: 8080
    socket_path: /tmp/strix-mcp.sock

    auth:
      enabled: true
      token: ${STRIX_MCP_TOKEN}

    # Tools to expose
    exposed_tools:
      - terminal_execute
      - browser_action
      - python_action
      - str_replace_editor
      - send_request
      - repeat_request
      - list_requests
      - view_request
      - create_vulnerability_report
      - web_search

#──────────────────────────────────────────────────────────────────────
# ZEN-MCP INTEGRATION
# Connect to zen-mcp-server for multi-model capabilities
#──────────────────────────────────────────────────────────────────────
zen_mcp:
  enabled: false  # Enable with --enable-zen-mcp flag

  connection:
    type: socket  # socket | subprocess
    socket_path: /tmp/zen-mcp.sock
    # Or spawn as subprocess:
    # command: ["./zen-mcp-server/run-server.sh"]

  # Which zen-mcp tools to use
  tools:
    - thinkdeep
    - consensus
    - codereview
    - apilookup

  # When to automatically use zen-mcp
  auto_use:
    - finding_validation  # Cross-check vulns with consensus
    - complex_analysis    # Use thinkdeep for complex bugs
```

### Environment Variables Reference

```bash
#──────────────────────────────────────────────────────────────────────
# BASIC CONFIGURATION (Current behavior - unchanged)
#──────────────────────────────────────────────────────────────────────
STRIX_LLM="anthropic/claude-sonnet-4-20250514"
LLM_API_KEY="sk-ant-..."

#──────────────────────────────────────────────────────────────────────
# LLM ROLES (Optional - for multi-model)
#──────────────────────────────────────────────────────────────────────
STRIX_LLM_PRIMARY="anthropic/claude-sonnet-4-20250514"
STRIX_LLM_FAST="google/gemini-2.0-flash"
STRIX_LLM_LOCAL="ollama/llama3.1"
STRIX_LLM_THINKING="google/gemini-3.0-pro"
STRIX_LLM_CODING="anthropic/claude-sonnet-4-20250514"
STRIX_LLM_VALIDATION="openai/gpt-5-turbo"

# API Keys for each provider
ANTHROPIC_API_KEY="sk-ant-..."
GOOGLE_API_KEY="..."
OPENAI_API_KEY="sk-..."
OLLAMA_BASE_URL="http://localhost:11434"

#──────────────────────────────────────────────────────────────────────
# MCP SERVER (For Option B - External Orchestration)
#──────────────────────────────────────────────────────────────────────
STRIX_MCP_SERVER_ENABLED=true
STRIX_MCP_TRANSPORT="stdio"  # stdio | http | socket
STRIX_MCP_PORT=8080
STRIX_MCP_SOCKET="/tmp/strix-mcp.sock"
STRIX_MCP_TOKEN="secure-token-here"

#──────────────────────────────────────────────────────────────────────
# ZEN-MCP CLIENT (For Option A - Enhanced Strix)
#──────────────────────────────────────────────────────────────────────
STRIX_ZEN_MCP_ENABLED=true
STRIX_ZEN_MCP_SOCKET="/tmp/zen-mcp.sock"
```

---

## Implementation Phases

### Phase 1: LLM Roles Configuration

**Goal**: Support multiple models for different purposes

**Tasks**:
1. Create `llm.yaml` config schema
2. Implement role-based model routing in `llm/llm.py`
3. Add `--llm-config` CLI flag
4. Support environment variable overrides

**Deliverables**:
- Users can define fast/local/thinking/coding models
- Automatic routing based on task type

### Phase 2: Strix as MCP Server

**Goal**: Expose Strix tools via MCP for external orchestration

**Tasks**:
1. Create `strix/mcp/server.py`
2. Implement tool schema translation
3. Add `--mcp-server` CLI flag
4. Support stdio/HTTP/socket transports

**Deliverables**:
- `strix --mcp-server` exposes tools
- Claude Code/Codex/Gemini can invoke Strix tools

### Phase 3: zen-mcp Client Integration

**Goal**: Use zen-mcp-server tools from within Strix

**Tasks**:
1. Create `strix/mcp/client.py`
2. Add zen-mcp tools to tool registry
3. Implement connection management
4. Add `--enable-zen-mcp` CLI flag

**Deliverables**:
- Strix can use `thinkdeep`, `consensus`, etc.
- Multi-model validation in native Strix mode

### Phase 4: Documentation & Examples

**Goal**: Make it easy to adopt

**Tasks**:
1. Write setup guides for both options
2. Create example configurations
3. Add workflow templates
4. Document security considerations

---

## Security Considerations

### MCP Server Security

1. **Authentication**: Token-based auth required for non-stdio transports
2. **Tool filtering**: Only expose safe subset of tools
3. **Sandbox enforcement**: All tool execution in Docker sandbox
4. **Rate limiting**: Prevent abuse via request limits

### zen-mcp Security

1. **Local only**: zen-mcp should run locally, not exposed to network
2. **API key isolation**: Each provider has separate credentials
3. **Model access control**: Define which models are available

### Sensitive Data

1. **API keys**: Never log or expose via MCP results
2. **Scan data**: Scope to current engagement
3. **Credentials found**: Mask in all outputs

---

## Summary

### Decision Matrix

| Use Case | Recommended Option |
|----------|-------------------|
| Maximum scan speed | Option A (Strix-native) |
| Single model, simple setup | Option A (basic) |
| Multi-model validation | Option A + zen-mcp |
| Conversational workflow | Option B (Claude Code) |
| Claude Code/Codex users | Option B |
| Cost optimization with local models | Either + LLM roles |

### Key Takeaways

1. **zen-mcp-server handles multi-model orchestration** - don't rebuild it in Strix
2. **Strix stays focused on pentest tools** - fast native execution
3. **LLM roles configuration** enables model specialization in either option
4. **Two clean deployment modes** instead of one complex hybrid

### Files to Create/Modify

| File | Change |
|------|--------|
| `strix/mcp/server.py` | New - MCP server implementation |
| `strix/mcp/client.py` | New - zen-mcp client |
| `strix/llm/roles.py` | New - LLM role routing |
| `strix/llm/config.py` | Modify - Add role config support |
| `strix/tools/registry.py` | Modify - MCP schema generation |
| `strix/interface/main.py` | Modify - Add CLI flags |

---

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [zen-mcp-server](https://github.com/BeehiveInnovations/zen-mcp-server)
- [LiteLLM Documentation](https://docs.litellm.ai/)
- [Claude Code MCP Guide](https://docs.anthropic.com/en/docs/claude-code/mcp)
- [Issue #31: Codex Integration](https://github.com/usestrix/strix/issues/31)
- [Issue #66: Claude Code Support](https://github.com/usestrix/strix/issues/66)
- [Issue #109: MCP Support](https://github.com/usestrix/strix/issues/109)
- [Issue #117: Gemini 3.0 Support](https://github.com/usestrix/strix/issues/117)
