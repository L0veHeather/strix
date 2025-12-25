# 🐯trix (Tiger-Strix)

> **下一代确定性、插件化 DAST 安全扫描引擎**

🐯trix 是对原版 Strix 的彻底重构与进化。我们摒弃了不可控的代理循环和沉重的 Docker 依赖，打造了一个**稳定、快速、极易扩展**的现代化安全扫描平台。

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-yellow)
![Frontend](https://img.shields.io/badge/frontend-React%20%7C%20Tauri-cyan)

---

## 🚀 核心哲学：为何选择 �trix？

| 特性 | 🐯trix (新架构) | 传统 Agent 扫描器 |
|------|-----------------|-------------------|
| **稳定性** | ✅ **100% 确定性**，状态机驱动 | ❌ 易陷入死循环，结果不可复现 |
| **执行环境** | ✅ **原生进程** (零 Docker 依赖) | ❌ 复杂的 Docker-in-Docker，部署困难 |
| **AI 角色** | ✅ **分析与建议** (副驾驶) | ❌ 全权控制 (容易失控) |
| **扩展性** | ✅ **开放插件系统** (Web UI + Python) | ❌ 难以修改核心代码 |
| **性能** | ✅ **本地极速执行** | ❌ 容器启动慢，资源消耗大 |

---

## 🌟 主要特性

### 1. 🎯 确定性扫描阶段机
🐯trix 不依赖 LLM "决定下一步做什么"，而是通过严格的代码控制流程确保扫描的完整性：
- **侦察 (Reconnaissance)**: 资产发现
- **枚举 (Enumeration)**: 参数与路径扩展
- **漏洞扫描 (Vulnerability Scan)**: 执行插件测试
- **验证 (Validation)**: PoC 验证与确认

### 2. � 双模插件系统
无限扩展扫描能力，支持两种添加方式：
- **Web UI (无代码)**: 直接在前端填写命令模板（如 `nmap -sV {target}`），LLM 自动决定何时调用。
- **Python (高级)**: 编写 Python 类，实现复杂的漏洞解析和逻辑控制。

### 3. 🧠 LLM 增强分析
LLM (如 GPT-4, Claude) 不控制流程，而是作为**超级分析师**：
- 分析 HTTP 响应中的隐藏参数
- 生成针对性的 Payload
- 解释扫描结果并生成修复建议

### 4. 💻 现代交互界面
- **Web UI**: 基于 React + Tailwind 的精美管理界面
- **实时反馈**: WebSocket 实时推送扫描进度和日志
- **任务管理**: 完整的扫描历史与报告管理

---

## 🛠️ 快速开始

### 前置要求
- **Python**: 3.10+
- **Node.js**: 18+ (用于前端)
- **Go**: (可选，用于某些扫描工具如 nuclei)

### 安装与运行

```bash
# 1. 克隆项目
git clone https://github.com/your-repo/trix.git
cd trix

# 2. 一键启动 (自动安装依赖)
./start.sh
```

访问 Web UI: `http://localhost:5173`

---

## 🔌 添加自定义插件

🐯trix 最强大的功能是其插件系统。

### 方式一：通过前端界面（推荐 - 无需编写代码）

适合快速集成命令行工具：
1. 进入 Web UI 的 **插件** 页面
2. 点击 **添加自定义插件**
3. 填写命令（例如：`nikto -host {target}`）
4. 选择 **能力 (Capabilities)** 和 **阶段 (Phases)**
5. **即刻生效**，无需重启！

### 方式二：Python 插件（高级）

适合深度集成：

```python
# plugins/my-scanner/plugin.py
from strix.plugins.base import BasePlugin, PluginEvent, ScanPhase

class MyScanner(BasePlugin):
    name = "my-scanner"
    phases = [ScanPhase.VULNERABILITY_SCAN]
    
    async def execute(self, target: str, phase: ScanPhase, params: dict):
        yield PluginEvent(event_type="STARTED", message=f"Scanning {target}")
        # ... 执行逻辑 ...
```

---

## 🏗️ 架构概览

```
🐯trix
├── 🖥️ Desktop (Frontend)    # React + Tauri, 用户交互
├── 🔌 Plugins               # 独立的安全工具集 (Nuclei, SQLMap, Custom...)
├── 🧠 Engine (Core)         # 确定性状态机
│   ├── Phase Manager        # 阶段流转控制
│   ├── Event Bus            # 实时消息总线
│   └── Scan Controller      # 任务调度
└── 💾 Storage               # SQLite 数据持久化
```

---

## 🤝 贡献参与

欢迎提交 Pull Request！无论是新的插件、UI 改进还是核心优化。

## � 许可证

Apache 2.0 License
