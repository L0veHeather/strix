# 🐯trix (Tiger-Strix)

> **Next-Generation Deterministic & Plugin-Based DAST Engine**

🐯trix is a complete evolution of the original Strix security agent. We have abandoned uncontrollable agent loops and heavy Docker dependencies to build a **stable, fast, and infinitely extensible** modern security scanning platform.

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-yellow)
![Frontend](https://img.shields.io/badge/frontend-React%20%7C%20Tauri-cyan)

---

## 🚀 Core Philosophy: Why 🐯trix?

| Feature | 🐯trix (New Architecture) | Traditional Autonamous Agents |
|---------|---------------------------|-------------------------------|
| **Stability** | ✅ **100% Deterministic** State Machine | ❌ Prone to infinite loops & non-reproducible results |
| **Runtime** | ✅ **Native Processes** (Zero Docker) | ❌ Complex Docker-in-Docker setup |
| **AI Role** | ✅ **Analysis & Advice** (Co-pilot) | ❌ Full Control (Prone to hallucinations) |
| **Extensibility** | ✅ **Open Plugin System** (Web UI + Python) | ❌ Hard to modify core code |
| **Performance** | ✅ **Blazing Fast Local Execution** | ❌ Slow container startup & high resource usage |

---

## 🌟 Key Features

### 1. 🎯 Deterministic Phase Machine
Instead of letting an LLM "decide what to do next", 🐯trix uses a strict code-controlled flow to ensure coverage:
- **Reconnaissance**: Asset discovery
- **Enumeration**: Parameter & path expansion
- **Vulnerability Scan**: Plugin execution
- **Validation**: PoC verification

### 2. 🔌 Dual-Mode Plugin System
Infinitely extensible capabilities with two ways to add tools:
- **Web UI (No Code)**: Simply fill in a command template (e.g., `nmap -sV {target}`) in the frontend. The LLM automatically decides when to use it based on context.
- **Python (Advanced)**: Write Python classes for complex vulnerability parsing and logic control.

### 3. 🧠 LLM-Augmented Analysis
The LLM (e.g., GPT-4, Claude) serves as a **Super Analyst**, not a controller:
- Analyzes hidden parameters in HTTP responses
- Generates targeted payloads
- Explains findings and suggests remediation

### 4. 💻 Modern Interface
- **Web UI**: Beautiful React + Tailwind dashboard
- **Real-time**: WebSocket-based live logs and progress
- **Management**: Full scan history and report management

---

## 🛠️ Quick Start

### Prerequisites
- **Python**: 3.10+
- **Node.js**: 18+ (for frontend)
- **Go**: (Optional, for tools like nuclei)

### Install & Run

```bash
# 1. Clone the repository
git clone https://github.com/your-repo/trix.git
cd trix

# 2. Start (Auto-installs dependencies)
./start.sh
```

Open Web UI: `http://localhost:5173`

---

## 🔌 Adding Custom Plugins

The plugin system is the heart of 🐯trix.

### Method 1: Via Frontend UI (Recommended - No Code)

Perfect for quickly integrating CLI tools:
1. Go to **Plugins** page in Web UI
2. Click **Add Custom Plugin**
3. Fill in command (e.g., `nikto -host {target}`)
4. Select **Capabilities** and **Phases**
5. **Instant activation**, no restart required!

### Method 2: Python Plugin (Advanced)

For deep integration:

```python
# plugins/my-scanner/plugin.py
from strix.plugins.base import BasePlugin, PluginEvent, ScanPhase

class MyScanner(BasePlugin):
    name = "my-scanner"
    phases = [ScanPhase.VULNERABILITY_SCAN]
    
    async def execute(self, target: str, phase: ScanPhase, params: dict):
        yield PluginEvent(event_type="STARTED", message=f"Scanning {target}")
        # ... logic ...
```

---

## 🏗️ Architecture Overview

```
🐯trix
├── 🖥️ Desktop (Frontend)    # React + Tauri, User Interface
├── 🔌 Plugins               # Independent Security Tools (Nuclei, SQLMap, Custom...)
├── 🧠 Engine (Core)         # Deterministic State Machine
│   ├── Phase Manager        # Flow Control
│   ├── Event Bus            # Real-time Messaging
│   └── Scan Controller      # Task Scheduling
└── 💾 Storage               # SQLite Persistence
```

---

## 🤝 Contributing

Pull Requests are welcome! Whether it's a new plugin, UI improvement, or core optimization.

## 📄 License

Apache 2.0 License
