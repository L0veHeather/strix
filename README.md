## 🦉 Introduction

**Strix** is an advanced, open-source autonomous AI agent designed to perform comprehensive security assessments and penetration testing. Acting like a team of skilled ethical hackers, Strix dynamically analyzes your applications, identifies vulnerabilities, and validates them with real proof-of-concept (PoC) exploits.

Unlike traditional scanners that rely on static rules, Strix uses Large Language Models (LLMs) to understand the context of your application, plan complex attack vectors, and adapt its strategy in real-time.

---

## ✨ Key Features

### 🧠 Agentic Intelligence
- **Adaptive Planning**: Uses a Target Complexity Index (TCI) to generate tailored scan plans.
- **Multi-Agent Orchestration**: Specialized agents collaborate on tasks like reconnaissance, planning, and exploitation.
- **Deep Thinking**: Leverages "thinking" models to analyze complex logic flaws and edge cases.

### 🛠️ Comprehensive Toolkit
- **Full HTTP Proxy**: Intercepts and manipulates traffic.
- **Browser Automation**: Tests client-side vulnerabilities (XSS, CSRF) and authentication flows.
- **Terminal Access**: Executes commands and scripts for infrastructure testing.
- **Code Analysis**: Performs static and dynamic analysis of source code.

### 🔌 MCP Integration (New!)
- **Model Context Protocol**: Integrates with `zen-mcp-server` for enhanced capabilities.
- **Multi-Model Consensus**: Validates findings by cross-referencing multiple AI models.
- **External Tools**: Connects with external CLIs and data sources.

### 🎯 Broad Vulnerability Coverage
- **OWASP Top 10**: Covers critical web risks like Injection, Broken Access Control, and SSRF.
- **API Security**: Tests for broken object level authorization (BOLA), mass assignment, etc.
- **Business Logic**: Identifies flaws in application workflows.
- **Infrastructure**: Scans for misconfigurations and exposed services.

---

## 🚀 Installation

### Prerequisites
1.  **Docker**: Strix runs its sandbox environment in Docker. Ensure Docker is installed and running.
2.  **Python 3.12+**: Required for the CLI.
3.  **LLM API Key**: Access to a powerful LLM (e.g., OpenAI GPT-4o/5, Anthropic Claude 3.5 Sonnet).

### Install via pipx (Recommended)
```bash
pipx install strix-agent
```

### Install via pip
```bash
pip install strix-agent
```

---

## ⚙️ Configuration

Strix is configured via environment variables. You can set these in your shell or a `.env` file.

### Required
```bash
# The model to use (supported by LiteLLM)
export STRIX_LLM="openai/gpt-4o"

# Your API key for the provider
export LLM_API_KEY="sk-..."
```

### Optional
```bash
# For local models (e.g., Ollama, LMStudio)
export LLM_API_BASE="http://localhost:11434"

# For real-time web research and reconnaissance
export PERPLEXITY_API_KEY="pplx-..."

# MCP Configuration (Advanced)
export ZEN_MCP_ENABLED="true"
export ZEN_MCP_TRANSPORT="stdio"
```

---

## 💻 Usage

### Basic Scanning
Run a scan against a target URL, domain, or local path.

```bash
# Scan a web application
strix --target https://example.com

# Scan a local directory
strix --target ./my-app

# Scan a GitHub repository
strix --target https://github.com/username/repo
```

### Advanced Options

#### Custom Instructions
Guide the agent to focus on specific areas or use specific credentials.

```bash
strix --target https://app.com --instruction "Focus on the login flow and check for IDOR in the user profile."
```

#### Multi-Target Scanning
Scan multiple assets in a single run.

```bash
strix -t https://api.app.com -t https://frontend.app.com
```

#### Headless Mode (CI/CD)
Run without the interactive TUI, suitable for automated pipelines.

```bash
strix -n --target https://app.com
```

### Scope-Based Scanning (New!)
For complex engagements, define a scope file (YAML) to control targets, exclusions, and credentials.

**scope.yaml example:**
```yaml
metadata:
  engagement_name: "Q4 Security Audit"
  engagement_type: "web_application"

targets:
  - name: "Main App"
    url: "https://app.example.com"
    critical: true
    technologies: ["react", "django"]
    credentials:
      - username: "admin"
        password_env: "ADMIN_PASSWORD"

exclusions:
  paths: ["/logout", "/admin/dangerous"]

settings:
  operational_mode: "poc-only"
```

**Run with scope:**
```bash
strix --scope ./scope.yaml
```

---

## 🔄 Workflow

Here is how Strix works under the hood:

1.  **Initialization**: Strix loads the configuration, validates the environment, and pulls the sandbox Docker image.
2.  **Reconnaissance**: The agent gathers information about the target (tech stack, endpoints, attack surface).
3.  **Planning**:
    *   Calculates **Target Complexity Index (TCI)** based on recon data.
    *   Generates a **Scan Plan** with prioritized steps (e.g., "Test Auth", "Fuzz API").
4.  **Execution**:
    *   **Agents** execute the plan steps using tools (Browser, Proxy, Terminal).
    *   **MCP Gateway** (if enabled) provides deep thinking and consensus validation.
5.  **Validation**: Findings are verified with proof-of-concept exploits to ensure zero false positives.
6.  **Reporting**: Real-time results are displayed in the TUI, and a final report is generated in `strix_runs/<run-name>`.

---