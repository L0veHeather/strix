# 🦉 Strix: Autonomous AI Security Agent

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

### 🧠 Agentic Intelligence
- **Adaptive Planning**: Calculates a **Target Complexity Index (TCI)** to tailor the scan strategy (e.g., "Quick Scan" vs. "Deep Dive").
- **Multi-Agent Orchestration**: Specialized agents collaborate:
    - **Orchestrator**: Manages the overall mission.
    - **JSRouteAnalyzer**: Deep analysis of JavaScript files using **urlfinder** and AI.
    - **Validation Agent**: Verifies findings with reproducible PoCs to ensure **Zero False Positives**.
- **Deep Thinking**: Leverages "thinking" models to analyze complex logic flaws and edge cases.

### � Powerful Interface
- **Real-time TUI**: Interactive terminal UI with a **Live Stats Panel** showing agent status, token usage, costs, and vulnerability severity breakdown.
- **Full HTTP Proxy**: Intercepts and manipulates traffic for deep inspection.
- **Browser Automation**: Headless browser for testing modern SPAs and authentication flows.

---

## 🔄 How Strix Works (The Workflow)

Strix follows a structured, hacker-like methodology:

1.  **👀 Reconnaissance & Scope**
    *   Strix starts by mapping the attack surface.
    *   It uses **urlfinder** to extract URLs from JS files and **Arjun** to find hidden parameters.
    *   The **Target Complexity Index (TCI)** is calculated to determine the scan depth.

2.  **� Strategic Planning**
    *   Based on recon data, the AI generates a dynamic **Scan Plan**.
    *   It prioritizes high-risk areas (e.g., "Test Admin API for BOLA", "Fuzz Upload Endpoint").

3.  **⚡ Execution & Analysis**
    *   **Agents** execute the plan steps using a suite of tools (Browser, Proxy, Terminal).
    *   **Akto Integration**: Uses thousands of proven test patterns for API security.
    *   **Whitepass Logic**: Automatically attempts to bypass 403/401 errors using header manipulation.

4.  **✅ Validation (The "Zero False Positive" Promise)**
    *   Every potential finding is sent to the **Validation Agent**.
    *   The agent attempts to reproduce the vulnerability using a generated Python PoC.
    *   Only successful exploits are reported.

5.  **📊 Reporting**
    *   Findings are displayed in real-time in the TUI.
    *   A comprehensive report is generated in `strix_runs/` with reproduction steps.

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

---

## 🏗️ Architecture

Strix is built on a modern, modular stack:
- **Core**: Python 3.12+ with Pydantic for robust data validation.
- **Sandboxing**: Docker containers for safe tool execution.
- **Observability**: OpenTelemetry and Langfuse for deep tracing of agent thoughts.
- **UI**: Textual-based TUI for a rich terminal experience.
