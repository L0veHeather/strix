# 🦉 Strix: 自主 AI 安全代理

[English](README.md) | [中文](README_ZH.md)

**Strix** 是一个先进的开源自主 AI 代理，旨在执行全面的安全评估和渗透测试。Strix 就像一支技术娴熟的白帽黑客团队，能够动态分析您的应用程序，识别漏洞，并通过真实的漏洞利用概念验证 (PoC) 进行验证。

与依赖静态规则的传统扫描器不同，Strix 使用大型语言模型 (LLM) 来理解应用程序的上下文，规划复杂的攻击向量，并实时调整其策略。

## 🚀 快速开始（一键启动）

```bash
# 克隆并启动
git clone https://github.com/your-org/strix.git
cd strix

# 一键启动（启动后端 + Web UI）
./start.sh

# 或启动 Tauri 桌面应用
./start.sh desktop
```

启动脚本会自动完成：
1. ✅ 检查依赖（Python、Node.js）
2. ✅ 设置 Python 虚拟环境
3. ✅ 安装前端依赖
4. ✅ 启动后端 API 服务器（端口 8000）
5. ✅ 启动 Web UI（端口 5173）
6. ✅ 自动打开浏览器

**访问地址：**
- 🌐 Web UI: http://localhost:5173
- 📡 API: http://localhost:8000
- 📖 API 文档: http://localhost:8000/docs

---

## ✨ 核心能力

### 🛡️ 高级漏洞检测
Strix 不仅仅是简单的签名匹配，它使用 AI 来理解业务逻辑和上下文：
- **OWASP API Top 10**：全面覆盖，包括使用 **Akto** 成熟库检测的 BOLA、批量赋值 (Mass Assignment) 和失效的身份验证。
- **IDOR & 访问控制**：通过多账号测试，高级检测不安全的直接对象引用。
- **参数模糊测试**：集成 **Arjun** 以发现隐藏参数和遗留端点。
- **Header 操控**：自动化的 **Whitepass 风格** Header 绕过技术（IP 欺骗、认证绕过）。
- **客户端攻击**：检测 XSS（反射型/存储型）、开放重定向和 CSRF。
- **服务端漏洞**：SSRF、RCE 和 SQL 注入测试。

### 🔮 全知测试 (水晶盒模式 / Crystal-Box)
Strix 通过利用完整的部署上下文，超越了传统的扫描方式：
- **基础设施感知**：分析 `Dockerfile`、`docker-compose.yml` 和 `.env` 以映射内部网络和服务。
- **深度逻辑评估**：将基础设施发现与代码分析和动态测试相关联。
- **全链条利用**：跨层级链接漏洞（例如，利用代码中的 SSRF 访问在 docker-compose 中发现的内部 Redis 服务）。
- **类 IAST 容器分析**：使用 `--deploy` 模式，Strix 会自动启动目标并读取容器日志，以观察攻击期间的运行时行为。

### 🧠 代理智能 (Agentic Intelligence)
- **自适应规划**：计算 **目标复杂度指数 (TCI)** 以定制扫描策略（例如，“快速扫描” vs “深度潜入”）。
- **多代理编排**：专业代理协作：
    - **编排器 (Orchestrator)**：管理整体任务。
    - **JSRouteAnalyzer**：使用 **urlfinder** 和 AI 深度分析 JavaScript 文件。
    - **验证代理 (Validation Agent)**：使用可复现的 PoC 验证发现，确保 **零误报**。
- **深度思考**：利用“思考”模型分析复杂的逻辑缺陷和边缘情况。

### 💻 强大的界面
- **实时 TUI**：基于终端的交互式 UI，带有 **实时统计面板**，显示代理状态、Token 使用量、成本和漏洞严重程度细分。
- **全功能 HTTP 代理**：拦截和篡改流量以进行深度检查。
- **浏览器自动化**：无头浏览器用于测试现代 SPA 和身份验证流程。

---

## 🔄 Strix 工作原理（确定性阶段驱动工作流）

Strix 遵循**代码控制**的**基于阶段**的方法论，确保完整覆盖：

1.  **👀 枚举阶段 (ENUMERATION)**
    *   从目标发现 URL、端点和参数
    *   LLM 分析 HTTP 响应以提取链接和表单字段
    *   **代码**管理任务队列并防止重复
    *   **转换条件**：未发现新 URL 时

2.  **🔍 参数扩展阶段 (PARAM_EXPANSION)**
    *   LLM 建议隐藏参数（API 密钥、调试模式、管理员标志）
    *   **代码**为所有已知 URL 上的每个参数创建测试任务
    *   使用 AI 推理预测参数名称
    *   **转换条件**：所有参数测试已排队时

3.  **⚡ 漏洞测试阶段 (VULNERABILITY_TEST)**
    *   测试 OWASP Top 10、API 安全问题、逻辑缺陷
    *   LLM 检测漏洞*指标*（而非确认）
    *   **新功能**：自动 HTTP 方法枚举（GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD）
    *   疑似漏洞 → 排队等待验证
    *   **转换条件**：所有漏洞测试完成时

4.  **✅ LLM验证阶段 (LLM_VERIFICATION)（零误报）**
    *   **LLM 职责**：生成 PoC 策略（载荷、预期指标）
    *   **代码职责**：执行 PoC，使用模式匹配验证
    *   类型特定验证器：XSS、SQLi、SSRF、XXE、RCE、IDOR
    *   **仅报告代码确认**的漏洞
    *   **转换条件**：所有 PoC 验证完成时

5.  **🔗 深度分析阶段 (DEEP_ANALYSIS)**
    *   识别漏洞链和利用路径
    *   规划多步攻击（例如 SSRF → 内部 Redis 访问）
    *   **转换条件**：分析完成时

6.  **📊 总结阶段 (SUMMARY)**
    *   生成最终报告
    *   包含复现步骤的全面发现
    *   **扫描完成**：代码确定完成，而非 LLM

**核心保证**：发现漏洞不会停止扫描。无论发现如何，所有阶段都会完成。

---

## 🚀 安装

### 前置条件
1.  **Python 3.12+**：后端需要此版本。
2.  **Node.js 18+**：桌面 UI 需要此版本。
3.  **LLM API Key**：访问强大的 LLM（例如 OpenAI GPT-4o, Claude 3.5 Sonnet）。

### 一键安装（推荐）
```bash
# 克隆仓库
git clone https://github.com/your-org/strix.git
cd strix

# 赋予启动脚本执行权限
chmod +x start.sh

# 启动一切
./start.sh
```

### 手动安装

#### 后端（Python）
```bash
# 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate

# 安装 Strix
pip install -e .
```

#### 前端（Node.js）
```bash
cd desktop
pnpm install
```

#### 安全工具（可选但推荐）
```bash
# 通过辅助脚本安装
./start.sh tools

# 或手动安装：
# Go 工具（需要已安装 Go）
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Python 工具
pipx install sqlmap
```

### 通过 pipx 安装（仅 CLI）
```bash
pipx install .
```

### 通过 pip 安装
```bash
pip install .
```

---

## ⚙️ 配置

设置环境变量：

```bash
# 必需: LLM 提供商
export STRIX_LLM="openai/gpt-4o"
export LLM_API_KEY="sk-..."

# 可选: 遥测与研究
export PERPLEXITY_API_KEY="pplx-..."  # 用于网络搜索研究
export LANGFUSE_PUBLIC_KEY="..."      # 用于追踪
```

---

## 💻 使用方法

### 🖥️ 桌面 UI（推荐）

全新的 Strix 桌面 UI 提供可视化界面来管理扫描：

```bash
# 启动 Web UI + 后端
./start.sh dev

# 或启动原生桌面应用（Tauri）
./start.sh desktop
```

**功能特性：**
- 📊 实时扫描进度与阶段可视化
- 🔌 插件管理（安装/启用/禁用）
- 📈 漏洞仪表盘，按严重程度分类
- 📄 导出报告（JSON、Markdown、SARIF）
- 🌙 深色/浅色主题支持

### CLI 扫描
```bash
strix --target https://example.com
```

### 🔮 全知扫描 (水晶盒模式)
提供完整的上下文以进行尽可能深度的评估：
```bash
strix --target https://app.example.com \
      --source ./src \
      --docker ./docker-compose.yml
```
这启用了 **全知工作流**，Strix 将协同分析基础设施、代码和实时应用程序。

### 🔄 组合 DAST + SAST + IAST
为了进行终极安全评估，部署您的目标并启用所有分析模式：
```bash
strix --target http://localhost:8080 \
      --source ./src \
      --docker ./docker-compose.yml \
      --deploy
```
| 模式 | 描述 |
|------|-------------|
| DAST | 针对运行中目标的动态测试 |
| SAST | `./src` 中的静态代码分析 |
| IAST | 容器日志分析 (SQL, 错误, 堆栈追踪) |

### 基于范围的扫描 (企业级)
对于复杂的任务，使用范围文件定义目标、凭据和排除项。

**scope.yaml:**
```yaml
targets:
  - name: "Main App"
    url: "https://app.example.com"
    credentials:
      - username: "admin"
        password_env: "ADMIN_PASS"
```

**运行:**
```bash
strix --scope ./scope.yaml
```

### 自定义指令
指导代理关注特定的威胁：
```bash
strix --target https://api.app.com --instruction "Focus on BOLA vulnerabilities in the /users endpoint using Arjun for parameter discovery."
```

### 🎲 可重现扫描
用于合规测试或调试，使用固定种子获得确定性结果：
```bash
# 相同种子 = 相同扫描行为
strix --target https://example.com --seed 12345

# 验证之前的发现
strix --target https://example.com --seed 12345  # 相同结果
```

### ⚡ 性能选项
Strix 自动优化性能：
- **并发请求**：最多 10 个并行 HTTP 请求（可配置）
- **连接池**：重用 TCP 连接以提高效率
- **方法枚举**：测试所有 HTTP 方法（GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD）

**结果**：比顺序执行快 5-10 倍

---

## 🛠️ 自定义与开发指南

Strix 的设计初衷就是易于扩展。以下是如何根据您的需求定制 Strix：

### 1. 完善漏洞检测方式
要修改 Strix 检测漏洞的 *逻辑* 或添加新的攻击向量，请编辑 `strix/prompts/vulnerabilities/` 中的提示词模块。
*   **位置**: `strix/prompts/vulnerabilities/*.jinja`
*   **操作**: 编辑 `<methodology>` (方法论) 和 `<automation_patterns>` (自动化模式) 部分。
*   **示例**: 要添加一种新的 JWT 绕过技术，请编辑 `jwt.jinja` 并在 `<automation_patterns>` 块中添加具体的 Python 代码模式。

### 2. 增加新的检测工具
Strix 支持代理使用的自定义 Python 工具。
*   **位置**: `strix/tools/`
*   **如何添加**:
    1.  创建一个新文件 (例如 `strix/tools/my_custom_tool.py`)。
    2.  定义您的函数并使用 `@register_tool` 装饰器。
    3.  在 `strix/tools/registry.py` 中导入您的工具。
```python
from strix.tools.registry import register_tool

@register_tool(sandbox_execution=True) # 如果需要访问本地网络，设为 False
def my_custom_tool(target_url: str) -> dict:
    """代理能看到的工具描述，用于理解何时使用此工具。"""
    # 您的逻辑代码
    return {"status": "success", "data": ...}
```

### 3. 修改 Agent 配置 (如过期时间)
*   **超时时间**: 设置 `AGENT_TIMEOUT_MINUTES` 环境变量以限制子代理的运行时间（默认：30分钟）。
*   **最大迭代次数**:修改 `strix/interface/tui.py` 或 `strix/agents/StrixAgent/strix_agent.py` 中的 `max_iterations`。

### 4. 限制检测方式
如果您希望限制代理只进行特定类型的测试（例如，*仅* SQL 注入）：
*   **CLI 指令**: 使用 `--instruction` 参数。
    ```bash
    strix --target ... --instruction "只测试 SQL 注入。不要进行模糊测试或 XSS 测试。"
    ```
*   **TCI 覆盖**: 您可以修改 `strix/core/tci.py` 强制过滤特定模块，尽管通常基于指令的引导就足够了。

---

## 🏗️ 架构设计

Strix 构建在现代化、模块化的技术栈之上：
- **核心**: Python 3.12+ 配合 Pydantic 进行强大的数据验证
- **后端**: FastAPI 服务器，支持 WebSocket 实时更新
- **前端**: Tauri 2.0 + React + TypeScript 桌面应用程序
- **插件**: 可扩展的安全工具插件系统（Nuclei、HTTPX、ffuf 等）
- **可观察性**: OpenTelemetry 和 Langfuse 深度追踪智能体思考过程

### 🔌 基于插件的架构 (v2.0)

Strix v2.0 引入了**无 Docker 依赖的插件系统**，原生运行安全工具：

```
┌─────────────────────────────────────────────────────────────────┐
│                      Strix 桌面 UI                              │
│                   (Tauri + React + TypeScript)                  │
├─────────────────────────────────────────────────────────────────┤
│                       FastAPI 后端                              │
│                     (REST API + WebSocket)                      │
├─────────────────────────────────────────────────────────────────┤
│                         扫描引擎                                │
│    ┌──────────────┬──────────────┬──────────────────────┐      │
│    │   事件总线   │  阶段管理器  │     结果收集器       │      │
│    └──────────────┴──────────────┴──────────────────────┘      │
├─────────────────────────────────────────────────────────────────┤
│                        插件注册表                               │
│    ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐     │
│    │ Nuclei │ │ HTTPX  │ │  ffuf  │ │ Katana │ │ SQLMap │     │
│    └────────┘ └────────┘ └────────┘ └────────┘ └────────┘     │
├─────────────────────────────────────────────────────────────────┤
│                        LLM 集成                                 │
│           (规划、分析、验证、链式利用)                          │
└─────────────────────────────────────────────────────────────────┘
```

**内置插件：**

| 插件 | 阶段 | 描述 |
|--------|-------|-------------|
| `nuclei` | 漏洞扫描 | 基于模板的漏洞扫描 |
| `httpx` | 侦察 | HTTP 探测和技术检测 |
| `ffuf` | 枚举 | Web 内容发现和模糊测试 |
| `katana` | 侦察 | Web 爬虫和 URL 发现 |
| `sqlmap` | 利用 | SQL 注入检测和利用 |

**创建自定义插件：**

```yaml
# plugins/my-plugin/manifest.yaml
name: my-scanner
version: "1.0.0"
description: "我的自定义安全扫描器"
phases: [VULNERABILITY_SCAN]
capabilities: [WEB_SCANNING]

executable:
  binary: my-scanner
  install_method: go
  install_command: "go install github.com/example/my-scanner@latest"
```

### 🎯 确定性阶段驱动扫描架构

**全新设计**：Strix v2.0 引入完全重构的扫描引擎，具有确定性流程控制：

#### 核心原则
1. **代码控制流程**：`ScanController` 管理所有阶段转换和扫描完成——LLM 智能体仅分析数据
2. **基于阶段的执行**：严格的顺序阶段确保完整覆盖
3. **任务队列驱动**：所有工作项通过托管队列处理
4. **零提前终止**：发现漏洞不会停止扫描

#### 扫描阶段

```
枚举 → 参数扩展 → 漏洞测试 → LLM验证 → 深度分析 → 总结
```

| 阶段 | LLM 职责 | 代码职责 | 输出 |
|-------|----------|-----------|--------|
| **枚举 (ENUMERATION)** | 从响应中提取 URL/参数 | 执行 HTTP 请求，管理队列 | 新扫描目标 |
| **参数扩展 (PARAM_EXPANSION)** | 建议隐藏参数 | 为每个参数创建测试任务 | 参数测试任务 |
| **漏洞测试 (VULNERABILITY_TEST)** | 检测漏洞指标 | 执行测试，跟踪覆盖率 | 疑似漏洞 |
| **LLM验证 (LLM_VERIFICATION)** | 生成 PoC 策略 | 执行 PoC，验证结果 | 已确认漏洞 |
| **深度分析 (DEEP_ANALYSIS)** | 识别漏洞利用链 | 协调多步测试 | 链式漏洞利用 |
| **总结 (SUMMARY)** | 总结发现 | 生成最终报告 | 扫描完成 |

#### 核心组件

**ScanController** (`strix/core/scan_controller.py`)
- 扫描状态的**唯一真相来源**
- 管理任务队列（FIFO 执行）
- 强制执行阶段转换（无 LLM 输入）
- 通过硬编码条件确定扫描完成：
  ```python
  is_complete = (队列为空 AND 阶段==总结 AND 总结已执行)
  ```

**ScanTask** (`strix/core/scan_phase.py`)
- 表示单个工作单元（URL + 方法 + 参数 + 阶段）
- 通过签名去重以防止无限循环
- 跟踪已测试漏洞以确保覆盖率

**PoCValidator** (`strix/core/poc_validator.py`)
- 疑似漏洞的**基于代码的验证**
- 类型特定验证器：XSS、SQLi、SSRF、XXE、RCE、IDOR
- LLM 生成 PoC 策略 → 代码验证 → 仅报告已确认漏洞

**Pydantic 模式** (`strix/core/phase_schemas.py`)
- 严格验证所有 LLM 输出
- 防止格式错误的 JSON 导致的静默失败
- 发现的 URL、参数、漏洞的类型安全

#### LLM 约束

LLM **严格禁止**：
- ❌ 决定何时转换阶段
- ❌ 确定扫描完成
- ❌ 声明漏洞为"已确认"
- ❌ 在控制器激活时调用 `finish_scan` 工具

LLM **仅允许**：
- ✅ 分析 HTTP 响应以提取数据
- ✅ 建议参数和攻击向量
- ✅ 生成 PoC 测试策略
- ✅ 识别潜在漏洞指标

#### 性能优化

**HTTP 方法枚举**
- 自动测试 GET、POST、PUT、DELETE、PATCH、OPTIONS、HEAD
- 发现方法特定漏洞（例如不安全的 PUT 上传）
- 比仅测试 GET 全面 7 倍

**并发执行** (`strix/core/concurrent_executor.py`)
- 并行 HTTP 请求（可配置，默认：10 个并发）
- 连接池提高效率
- **比顺序执行快 5-10 倍**
- 速率限制以尊重目标服务器

**可重现扫描**
- `--seed` 参数实现确定性 LLM 采样
- 相同种子 → 相同 URL 发现 → 相同测试序列
- 支持合规验证和调试

```bash
# 可重现扫描
strix --target example.com --seed 42

# 所有使用 seed=42 的运行产生相同的任务序列
```

---

## 🚀 增强功能 (对比原版 Strix)

此 Fork 版本扩展了 [原版 Strix](https://github.com/usestrix/strix)，增加了重要的新功能，重点在于 **代理间协作** 和 **灰盒测试**：

### 🧠 高级代理协作 (Advanced Agent Coordination)
| 功能 | 原版 Strix | 此版本 |
|---------|---------------|--------------|
| **代理角色** | 通用代理 | **专用角色**：`BlackboxScanner` (黑盒扫描), `WhiteboxVerifier` (白盒验证), `GrayboxMonitor` (灰盒监控) |
| **通信** | 基础消息传递 | **双向移交 (Bidirectional Handoff)**：<br>1. 黑盒 -> 白盒 (定位触发点)<br>2. 白盒 -> 黑盒 (验证代码缺陷) |
| **验证** | 主要为自主黑盒 | **静默检测**：即使 HTTP 响应正常 (200 OK)，灰盒也能通过 **内部日志/数据库** 发现隐蔽漏洞 |

### 🔮 全知测试 (水晶盒模式)
| 功能 | 描述 |
|---------|-------------|
| **基础设施分析** | 阶段 0 分析 `Dockerfile`、`docker-compose.yml` 和 `.env` 文件 |
| **灰盒工作流** | 将静态代码分析与动态测试结果相关联 |
| **全链条利用** | 跨基础设施、代码和运行时层级链接漏洞 |
| **状态监控** | **新增**：代理现在可以在容器内执行命令（`psql`, `cat logs`）以确认不可见的副作用（盲注 SQLi, RCE） |

### 🔄 组合 DAST + SAST + IAST
| 模式 | 新 CLI 标志 | 能力 |
|------|--------------|------------|
| SAST | `--source ./path` | 本地源代码的静态分析 |
| DAST | `--target URL` | 针对运行目标的动态测试 |
| IAST | `--docker ./docker-compose.yml --deploy` | 自动部署目标容器，监控日志，**以及检查内部状态** |

### 🛠️ 新增 CLI 参数
```
-S, --source PATH    Path to local source code directory
-D, --docker PATH    Path to docker-compose.yml or Dockerfile
-C, --container ID   Name/ID of existing container to attach
    --deploy         Auto-deploy target containers before testing
```

### 📦 新增组件
| 文件 | 用途 |
|------|---------|
| `strix/runtime/deployment_manager.py` | Docker-compose 编排与命令执行 |
| `strix/tools/container_tools.py` | 用于日志读取和容器内 **任意命令执行** 的工具 |
| `strix/prompts/coordination/agent_roles.jinja` | 角色定义和协作协议 |

### 🧠 代理增强
- **基础设施代理**：用于阶段 0 基础设施映射的新代理类型
- **灰盒监控者 (Graybox Monitor)**：使用 `execute_container_command` 检查 DB/文件系统变更的新角色
- **全知工作流**：基础设施 → 代码 → 验证 → 报告 → 修复

### 示例：完全全知扫描
```bash
strix --target http://localhost:8080 \
      --source ./src \
      --docker ./docker-compose.yml \
      --deploy \
      --instruction "Focus on SSRF. Use the GrayboxMonitor to check if the request hit the internal Redis."
```
