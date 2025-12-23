# 🦉 Strix v2: Human-Controlled Security Scanner

[English](README.md) | [中文](README_ZH.md) | [**📖 v2 设计哲学**](docs/strix-v2-philosophy.md)

> ⚠️ **Architecture Change**: Strix v2 has been fundamentally redesigned.
> - ❌ **Removed**: Agent loops, Docker/Sandbox, LLM-controlled flow, CLI/TUI
> - ✅ **Added**: Server + Engine + Plugin architecture with human control

**Strix v2** is an open-source, plugin-based security scanning system. Unlike v1's autonomous agent approach, v2 puts **humans in control** while leveraging security tools for comprehensive vulnerability detection.

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/your-org/strix.git
cd strix

# One-click launch (backend + web UI)
./start.sh

# Or run server directly
uvicorn strix.server.app:app --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd desktop && pnpm dev
```

**Access:**
- 🌐 Web UI: http://localhost:5173
- 📡 API: http://localhost:8000
- 📖 API Docs: http://localhost:8000/docs

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Desktop UI (React + Tauri)                  │
├─────────────────────────────────────────────────────────────────┤
│                     FastAPI Server (REST + WS)                  │
├─────────────────────────────────────────────────────────────────┤
│                         Scan Engine                             │
│    ┌──────────────┬──────────────┬──────────────────────┐      │
│    │  Event Bus   │Phase Manager │ Result Collector     │      │
│    └──────────────┴──────────────┴──────────────────────┘      │
├─────────────────────────────────────────────────────────────────┤
│                      Plugin Registry                            │
│    ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐     │
│    │ Nuclei │ │ HTTPX  │ │  ffuf  │ │ Katana │ │ SQLMap │     │
│    └────────┘ └────────┘ └────────┘ └────────┘ └────────┘     │
├─────────────────────────────────────────────────────────────────┤
│                      SQLite Storage                             │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| **Server** | FastAPI backend with REST API and WebSocket for real-time updates |
| **Engine** | ScanEngine orchestrates phases, EventBus distributes events |
| **Plugins** | Security tools (Nuclei, httpx, ffuf, katana, sqlmap) |
| **Storage** | SQLite database for scans, findings, and configurations |
| **Desktop** | Tauri + React frontend for visual scan management |

---

## 🛡️ Plugin-Based Vulnerability Detection

Strix v2 uses proven security tools as plugins:

| Plugin | Phase | Description |
|--------|-------|-------------|
| **nuclei** | Vulnerability Scan | Template-based vulnerability scanning (10,000+ templates) |
| **httpx** | Reconnaissance | HTTP probing, technology detection |
| **ffuf** | Enumeration | Directory brute-forcing, parameter fuzzing |
| **katana** | Reconnaissance | Web crawling, endpoint discovery |
| **sqlmap** | Exploitation | SQL injection detection and exploitation |

---

## 🔄 How Strix v2 Works

Strix v2 follows a **deterministic, code-controlled** workflow:

```
RECONNAISSANCE → ENUMERATION → VULNERABILITY_SCAN → VALIDATION → REPORTING
```

| Phase | Plugins | Output |
|-------|---------|--------|
| **Reconnaissance** | httpx, katana | Discovered endpoints, technologies |
| **Enumeration** | ffuf | Hidden paths, parameters |
| **Vulnerability Scan** | nuclei, sqlmap | Detected vulnerabilities |
| **Validation** | nuclei | Verified findings |
| **Reporting** | - | JSON, Markdown, SARIF reports |

### Key Principles

1. **Code controls flow** - Phase transitions are deterministic, not LLM-decided
2. **Plugins execute** - Security tools run natively, no Docker/sandbox
3. **Humans review** - All results require human analysis

---

## 🚀 Installation

### Prerequisites

1. **Python 3.12+**: Required for the backend
2. **Node.js 18+**: Required for the desktop UI
3. **Security Tools**: Required for scanning

### Install Security Tools

```bash
# Go tools (requires Go 1.21+)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Python tools
pipx install sqlmap

# Verify installation
nuclei -version
httpx -version
ffuf -version
katana -version
sqlmap --version
```

### Install Strix

```bash
# Clone repository
git clone https://github.com/your-org/strix.git
cd strix

# Backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Frontend
cd desktop
pnpm install
```

---

## ⚙️ Configuration

### Optional: LLM for Analysis (Future Feature)

```bash
export STRIX_LLM="openai/gpt-4o"
export LLM_API_KEY="sk-..."
```

> Note: LLM integration is optional in v2. The core scanning workflow is fully functional without LLM.

---

## 💻 Usage

### Web UI (Recommended)

```bash
./start.sh
```

Features:
- 📊 Real-time scan progress with phase visualization
- 🔌 Plugin management (install/enable/disable)
- 📈 Vulnerability dashboard with severity breakdown
- 📄 Export reports (JSON, Markdown, SARIF)
- 🌙 Dark/Light theme support

### API Usage

```bash
# Create scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Get scan status
curl http://localhost:8000/api/scans/{scan_id}

# List vulnerabilities
curl http://localhost:8000/api/results/{scan_id}/vulnerabilities
```

### WebSocket Events

Connect to `ws://localhost:8000/ws/{client_id}` for real-time updates:

```javascript
// Subscribe to scan updates
ws.send(JSON.stringify({ action: "subscribe", scan_id: "abc123" }))

// Receive events
// - scan.started
// - phase.started / phase.completed
// - plugin.started / plugin.output / plugin.completed
// - vulnerability.found
// - scan.completed / scan.failed
```

---

## 🔌 Creating Custom Plugins

```yaml
# plugins/my-scanner/manifest.yaml
name: my-scanner
version: "1.0.0"
display_name: "My Custom Scanner"
description: "Custom vulnerability scanner"
author: "Your Name"

phases:
  - VULNERABILITY_SCAN

capabilities:
  - WEB_SCANNING

executable:
  binary: my-scanner
  install_method: go
  install_command: "go install github.com/example/my-scanner@latest"
```

```python
# plugins/my-scanner/plugin.py
from strix.plugins.base import BasePlugin, ScanPhase, PluginCapability

class MyScanner(BasePlugin):
    name = "my-scanner"
    version = "1.0.0"
    phases = [ScanPhase.VULNERABILITY_SCAN]
    capabilities = [PluginCapability.WEB_SCANNING]
    
    async def execute(self, target, phase, parameters):
        async for event in self.stream_command(
            ["my-scanner", "-target", target],
            phase,
            line_parser=self._parse_output,
        ):
            yield event
```

---

## ⚠️ What's NOT in Strix v2

The following v1 features have been **permanently removed**:

| Removed Feature | Reason |
|-----------------|--------|
| **Agent loops** | LLM should advise, not control |
| **Docker/Sandbox runtime** | Tools run natively for transparency |
| **CLI/TUI interface** | Replaced by Web UI + API |
| **LLM-controlled tool selection** | Code determines workflow |
| **MCP gateway** | Agent-specific, not needed |
| **Scope configuration files** | Replaced by ScanConfig API |
| **Multi-agent orchestration** | Single deterministic engine |
| **Autonomous scanning** | Human-in-the-loop required |

See [v2 设计哲学](docs/strix-v2-philosophy.md) for the architectural rationale.

---

## 📁 Project Structure

```
strix/
├── desktop/              # Tauri + React frontend
├── plugins/              # Security tool plugins
│   ├── nuclei/
│   ├── httpx/
│   ├── ffuf/
│   ├── katana/
│   └── sqlmap/
├── strix/
│   ├── server/           # FastAPI backend
│   │   ├── app.py        # Main application
│   │   └── routes/       # API endpoints
│   ├── engine/           # Scan engine
│   │   ├── scan_engine.py
│   │   ├── phase_manager.py
│   │   ├── event_bus.py
│   │   └── result_collector.py
│   ├── plugins/          # Plugin infrastructure
│   │   ├── base.py
│   │   ├── registry.py
│   │   └── loader.py
│   ├── storage/          # SQLite persistence
│   │   ├── database.py
│   │   └── models.py
│   └── llm/              # LLM integration (optional)
├── docs/
│   └── strix-v2-philosophy.md
├── start.sh              # One-click launcher
└── pyproject.toml
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Key principle: Any change must align with the [v2 设计哲学](docs/strix-v2-philosophy.md).

---

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE)

---

## 🙏 Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) for Nuclei, httpx, katana
- [ffuf](https://github.com/ffuf/ffuf) for web fuzzing
- [sqlmap](https://sqlmap.org/) for SQL injection testing
