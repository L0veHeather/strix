# 🦉 Strix: Autonomous AI Security Agent

[English](README.md) | [中文](README_ZH.md)

**Strix** is an advanced, open-source autonomous AI agent designed to perform comprehensive security assessments and penetration testing. Acting like a team of skilled ethical hackers, Strix dynamically analyzes your applications, identifies vulnerabilities, and validates them with real proof-of-concept (PoC) exploits.

Unlike traditional scanners that rely on static rules, Strix uses Large Language Models (LLMs) to understand the context of your application, plan complex attack vectors, and adapt its strategy in real-time.

---

## ✨ Key Capabilities

### 🛡️ Advanced Vulnerability Detection
Strix goes beyond simple signature matching, using AI to understand logic and context:
- **OWASP API Top 10**: Comprehensive coverage including BOLA, Mass Assignment, and Broken Authentication using **Akto's** proven library.
- **IDOR & Access Control**: Advanced detection of Insecure Direct Object References with multi-account testing.
- **Parameter Fuzzing**: Integrated **Arjun** for discovering hidden parameters and legacy endpoints.
- **Header Manipulation**: Automated **Whitepass-inspired** header bypass techniques (IP spoofing, auth bypass).
- **Client-Side Attacks**: Detection of XSS (Reflected/Stored), Open Redirects, and CSRF.
- **Server-Side Flaws**: SSRF, RCE, and SQL Injection testing.

### 🔮 Omniscient Testing (Crystal-Box)
Strix transcends traditional scanning by leveraging full deployment context:
- **Infrastructure Awareness**: Analyzes `Dockerfile`, `docker-compose.yml`, and `.env` to map internal networks and services.
- **Deep Logic Assessment**: Correlates infrastructure findings with code analysis and dynamic testing.
- **Full-Chain Exploitation**: Chains vulnerabilities across layers (e.g., using an SSRF in code to access an internal Redis service discovered in docker-compose).
- **IAST-like Container Analysis**: With `--deploy`, Strix auto-starts your target and reads container logs to observe runtime behavior during attacks.

### 🧠 Agentic Intelligence
- **Adaptive Planning**: Calculates a **Target Complexity Index (TCI)** to tailor the scan strategy (e.g., "Quick Scan" vs. "Deep Dive").
- **Multi-Agent Orchestration**: Specialized agents collaborate:
    - **Orchestrator**: Manages the overall mission.
    - **JSRouteAnalyzer**: Deep analysis of JavaScript files using **urlfinder** and AI.
    - **Validation Agent**: Verifies findings with reproducible PoCs to ensure **Zero False Positives**.
- **Deep Thinking**: Leverages "thinking" models to analyze complex logic flaws and edge cases.

### � Powerful Interface
###  Powerful Interface
- **Real-time TUI**: Interactive terminal UI with a **Live Stats Panel** showing agent status, token usage, costs, and vulnerability severity breakdown.
- **Full HTTP Proxy**: Intercepts and manipulates traffic for deep inspection.
- **Browser Automation**: Headless browser for testing modern SPAs and authentication flows.

---

## 🔄 How Strix Works (Deterministic Phase-Driven Workflow)

Strix follows a **code-controlled**, **phase-based** methodology ensuring complete coverage:

1.  **👀 ENUMERATION Phase**
    *   Discovers URLs, endpoints, and parameters from the target
    *   LLM analyzes HTTP responses to extract links and form fields
    *   **Code** manages task queue and prevents duplicates
    *   **Transition**: When no new URLs discovered

2.  **🔍 PARAM_EXPANSION Phase**
    *   LLM suggests hidden parameters (API keys, debug modes, admin flags)
    *   **Code** creates test tasks for each parameter on all known URLs
    *   Uses AI reasoning to predict parameter names
    *   **Transition**: When all parameter tests queued

3.  **⚡ VULNERABILITY_TEST Phase**
    *   Tests for OWASP Top 10, API security issues, logic flaws
    *   LLM detects vulnerability *indicators* (not confirmations)
    *   **NEW**: Automatic HTTP method enumeration (GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD)
    *   Suspected vulnerabilities → queued for verification
    *   **Transition**: When all vuln tests complete

4.  **✅ LLM_VERIFICATION Phase (Zero False Positives)**
    *   **LLM Role**: Generate PoC strategies (payloads, expected indicators)
    *   **Code Role**: Execute PoCs, validate with pattern matching
    *   Type-specific validators: XSS, SQLi, SSRF, XXE, RCE, IDOR
    *   **Only code-confirmed** vulnerabilities are reported
    *   **Transition**: When all PoCs validated

5.  **🔗 DEEP_ANALYSIS Phase**
    *   Identifies vulnerability chains and exploit paths
    *   Plans multi-step attacks (e.g., SSRF → internal Redis access)
    *   **Transition**: Analysis complete

6.  **📊 SUMMARY Phase**
    *   Final report generation
    *   Comprehensive findings with reproduction steps
    *   **Scan Complete**: Code determines completion, not LLM

**Key Guarantee**: Finding vulnerabilities does NOT stop the scan. All phases complete regardless of findings.

---

## 🚀 Installation

### Prerequisites
1.  **Docker**: Strix runs its sandbox environment in Docker.
2.  **Python 3.12+**: Required for the CLI.
3.  **LLM API Key**: Access to a powerful LLM (e.g., OpenAI GPT-4o, Claude 3.5 Sonnet).

### Install via pipx (Recommended)
```bash
pipx install .
```

### Install via pip
```bash
pip install .
```

---

## ⚙️ Configuration

Set your environment variables:

```bash
# Required: LLM Provider
export STRIX_LLM="openai/gpt-4o"
export LLM_API_KEY="sk-..."

# Optional: Telemetry & Research
export PERPLEXITY_API_KEY="pplx-..."  # For web research
export LANGFUSE_PUBLIC_KEY="..."      # For tracing
```

---

## 💻 Usage

### Basic Scanning
```bash
strix --target https://example.com
```

### 🔮 Omniscient Scanning (Crystal-Box)
Provide full context for the deepest possible assessment:
```bash
strix --target https://app.example.com \
      --source ./src \
      --docker ./docker-compose.yml
```
This enables the **Omniscient Workflow**, where Strix analyzes infrastructure, code, and the live application in unison.

### 🔄 Combined DAST + SAST + IAST
For the ultimate security assessment, deploy your target and enable all analysis modes:
```bash
strix --target http://localhost:8080 \
      --source ./src \
      --docker ./docker-compose.yml \
      --deploy
```
| Mode | Description |
|------|-------------|
| DAST | Dynamic testing against running target |
| SAST | Static code analysis in `./src` |
| IAST | Container log analysis (SQL, errors, traces) |

### Scope-Based Scanning (Enterprise)
For complex engagements, use a scope file to define targets, credentials, and exclusions.

**scope.yaml:**
```yaml
targets:
  - name: "Main App"
    url: "https://app.example.com"
    credentials:
      - username: "admin"
        password_env: "ADMIN_PASS"
```

**Run:**
```bash
strix --scope ./scope.yaml
```

### Custom Instructions
Guide the agent to focus on specific threats:
```bash
strix --target https://api.app.com --instruction "Focus on BOLA vulnerabilities in the /users endpoint using Arjun for parameter discovery."
```

### 🎲 Reproducible Scans
For compliance testing or debugging, use a fixed seed for deterministic results:
```bash
# Same seed = same scan behavior
strix --target https://example.com --seed 12345

# Verify a previous finding
strix --target https://example.com --seed 12345  # Identical result
```

### ⚡ Performance Options
Strix automatically optimizes performance with:
- **Concurrent requests**: Up to 10 parallel HTTP requests (configurable)
- **Connection pooling**: Reuses TCP connections for efficiency
- **Method enumeration**: Tests all HTTP methods (GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD)

**Result**: 5-10× faster scans compared to sequential execution

---

## 🛠️ Customization & Development Guide

Strix is designed to be easily extensible. Here is how you can customize it to fit your needs:

### 1. Improving Vulnerability Detection
To modify *how* Strix detects vulnerabilities or to add new attack vectors, edit the prompt modules in `strix/prompts/vulnerabilities/`.
*   **Location**: `strix/prompts/vulnerabilities/*.jinja`
*   **Action**: Edit the `<methodology>` and `<automation_patterns>` sections.
*   **Example**: To add a new JWT bypass technique, edit `jwt.jinja` and add the specific python code pattern to the `<automation_patterns>` block.

### 2. Adding New Tools
Strix supports custom Python tools that agents can use.
*   **Location**: `strix/tools/`
*   **How to Add**:
    1.  Create a new file (e.g., `strix/tools/my_custom_tool.py`).
    2.  Define your function and use the `@register_tool` decorator.
    3.  Import your tool in `strix/tools/registry.py`.
```python
from strix.tools.registry import register_tool

@register_tool(sandbox_execution=True) # Set False if it needs local network access
def my_custom_tool(target_url: str) -> dict:
    """Description that the Agent sees to understand when to use this tool."""
    # Your logic here
    return {"status": "success", "data": ...}
```

### 3. Configuring Agent Behavior
*   **Timeouts**: Set `AGENT_TIMEOUT_MINUTES` environment variable to limit how long a sub-agent can run (default: 30 mins).
*   **Max Iterations**: Modify `max_iterations` in `strix/interface/tui.py` or `strix/agents/StrixAgent/strix_agent.py`.

### 4. Limiting Detection Methods
If you want to restrict the agent to specific test types (e.g., *only* SQL Injection):
*   **CLI**: Use the `--instruction` flag.
    ```bash
    strix --target ... --instruction "Only test for SQL Injection. Do NOT perform fuzzing or XSS tests."
    ```
*   **TCI Override**: You can modify `strix/core/tci.py` to force-filter specific modules, though instruction-based guidance is usually sufficient.

## 🏗️ Architecture

Strix is built on a modern, modular stack:
- **Core**: Python 3.12+ with Pydantic for robust data validation.
- **Sandboxing**: Docker containers for safe tool execution.
- **Observability**: OpenTelemetry and Langfuse for deep tracing of agent thoughts.
- **UI**: Textual-based TUI for a rich terminal experience.

### 🎯 Deterministic Phase-Driven Scanning Architecture

**NEW**: Strix v2.0 introduces a completely refactored scanning engine with deterministic flow control:

#### Core Principles
1. **Code Controls Flow**: `ScanController` manages all phase transitions and scan completion—LLM agents only analyze data
2. **Phase-Based Execution**: Strict sequential phases ensure complete coverage
3. **Task Queue Driven**: All work items processed through a managed queue  
4. **Zero Premature Termination**: Finding vulnerabilities doesn't stop the scan

#### Scanning Phases

```
ENUMERATION → PARAM_EXPANSION → VULNERABILITY_TEST → LLM_VERIFICATION → DEEP_ANALYSIS → SUMMARY
```

| Phase | LLM Role | Code Role | Output |
|-------|----------|-----------|--------|
| **ENUMERATION** | Extract URLs/params from responses | Execute HTTP requests, manage queue | New scan targets |
| **PARAM_EXPANSION** | Suggest hidden parameters | Create test tasks for each param | Parameter test tasks |
| **VULNERABILITY_TEST** | Detect vulnerability indicators | Execute tests, track coverage | Suspected vulnerabilities |
| **LLM_VERIFICATION** | Generate PoC strategies | Execute PoCs, validate results | Verified vulnerabilities |
| **DEEP_ANALYSIS** | Identify exploit chains | Coordinate multi-step tests | Chained exploits |
| **SUMMARY** | Summarize findings | Finalize report | Scan complete |

#### Key Components

**ScanController** (`strix/core/scan_controller.py`)
- **Single source of truth** for scan state
- Manages task queue (FIFO execution)
- Enforces phase transitions (no LLM input)
- Determines scan completion via hard-coded conditions:
  ```python
  is_complete = (queue_empty AND phase==SUMMARY AND summary_executed)
  ```

**ScanTask** (`strix/core/scan_phase.py`)
- Represents a single unit of work (URL + method + params + phase)
- Deduplication via signature to prevent infinite loops
- Tracks tested vulnerabilities to ensure coverage

**PoCValidator** (`strix/core/poc_validator.py`)
- **Code-based validation** of suspected vulnerabilities
- Type-specific validators: XSS, SQLi, SSRF, XXE, RCE, IDOR
- LLM generates PoC strategies → Code validates → Report only confirmed

**Pydantic Schemas** (`strix/core/phase_schemas.py`)
- Strict validation of all LLM outputs
- Prevents silent failures from malformed JSON
- Type safety for discovered URLs, parameters, vulnerabilities

#### LLM Constraints

LLMs are **strictly prohibited** from:
- ❌ Deciding when to transition phases
- ❌ Determining scan completion
- ❌ Declaring vulnerabilities as "confirmed"
- ❌ Calling `finish_scan` tool when controller is active

LLMs are **only allowed** to:
- ✅ Analyze HTTP responses for data extraction
- ✅ Suggest parameters and attack vectors
- ✅ Generate PoC test strategies
- ✅ Identify potential vulnerability indicators

#### Performance Optimizations

**HTTP Method Enumeration**
- Automatically tests GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
- Discovers method-specific vulnerabilities (e.g., unsafe PUT uploads)
- 7× more comprehensive than GET-only testing

**Concurrent Execution** (`strix/core/concurrent_executor.py`)
- Parallel HTTP requests (configurable, default: 10 concurrent)
- Connection pooling for efficiency
- **5-10× faster** than sequential execution
- Rate limiting to respect target servers

**Reproducible Scans**
- `--seed` parameter for deterministic LLM sampling
- Same seed → same URL discovery → same test sequence
- Enables compliance validation and debugging

```bash
# Reproducible scan
strix --target example.com --seed 42

# All runs with seed=42 produce identical task sequences
```

---

## 🚀 Enhanced Features (vs. Original Strix)

This fork extends the [original Strix](https://github.com/usestrix/strix) with significant new capabilities, focusing on **Inter-Agent Coordination** and **Gray-Box testing**:

### 🧠 Advanced Agent Coordination
|Feature|Original Strix|This Version|
|---|---|---|
|**Agent Roles**|Generic agents|**Specialized Roles**: `BlackboxScanner`, `WhiteboxVerifier`, `GrayboxMonitor`|
|**Communication**|Basic message passing|**Bidirectional Handoff**: <br>1. Blackbox -> Whitebox (Trace Trigger Point) <br>2. Whitebox -> Blackbox (Verify Code Flaw)|
|**Verification**|Mostly autonomous black-box|**Silent Detection**: Graybox finds vulnerabilities via **internal logs/DB** even if HTTP response is normal (200 OK)| |

### 🔮 Omniscient Testing (Crystal-Box Mode)
| Feature | Description |
|---------|-------------|
| **Infrastructure Analysis** | Phase 0 analysis of `Dockerfile`, `docker-compose.yml`, and `.env` files |
| **Gray-Box Workflow** | Correlates static code analysis with dynamic testing results |
| **Full-Chain Exploitation** | Chains vulnerabilities across infrastructure, code, and runtime layers |
| **State Monitoring** | **NEW**: Agents can now execute commands inside containers (`psql`, `cat logs`) to confirm invisible side-effects (Blind SQLi, RCE) |

### 🔄 Combined DAST + SAST + IAST
| Mode | New CLI Flag | Capability |
|------|--------------|------------|
| SAST | `--source ./path` | Static analysis of local source code |
| DAST | `--target URL` | Dynamic testing against running targets |
| IAST | `--docker ./docker-compose.yml --deploy` | Auto-deploy target containers, monitor logs, AND **inspect internal state** |

### 🛠️ New CLI Arguments
```
-S, --source PATH    Path to local source code directory
-D, --docker PATH    Path to docker-compose.yml or Dockerfile
-C, --container ID   Name/ID of existing container to attach
    --deploy         Auto-deploy target containers before testing
```

### 📦 New Components
| File | Purpose |
|------|---------|
| `strix/runtime/deployment_manager.py` | Docker-compose orchestration & command execution |
| `strix/tools/container_tools.py` | Tools for log reading and **arbitrary command execution** in containers |
| `strix/prompts/coordination/agent_roles.jinja` | Role definitions and collaboration protocols |

### 🧠 Agent Enhancements
- **Infrastructure Agent**: New agent type for Phase 0 infrastructure mapping
- **Graybox Monitor**: New role using `execute_container_command` to inspect DB/filesystem changes
- **Omniscient Workflow**: Infrastructure → Code → Validation → Reporting → Fixing

### Example: Full Omniscient Scan
```bash
strix --target http://localhost:8080 \
      --source ./src \
      --docker ./docker-compose.yml \
      --deploy \
      --instruction "Focus on SSRF. Use the GrayboxMonitor to check if the request hit the internal Redis."
```
