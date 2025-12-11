# 🦉 Strix: 自主 AI 安全代理

[English](README.md) | [中文](README_ZH.md)

**Strix** 是一个先进的开源自主 AI 代理，旨在执行全面的安全评估和渗透测试。Strix 就像一支技术娴熟的白帽黑客团队，能够动态分析您的应用程序，识别漏洞，并通过真实的漏洞利用概念验证 (PoC) 进行验证。

与依赖静态规则的传统扫描器不同，Strix 使用大型语言模型 (LLM) 来理解应用程序的上下文，规划复杂的攻击向量，并实时调整其策略。

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

## 🔄 Strix 如何工作 (工作流)

Strix 遵循结构化的、类似黑客的方法论：

1.  **👀 侦察与范围确定**
    *   Strix 首先映射攻击面。
    *   它使用 **urlfinder** 从 JS 文件中提取 URL，使用 **Arjun** 查找隐藏参数。
    *   计算 **目标复杂度指数 (TCI)** 以确定扫描深度。

2.  **📝 战略规划**
    *   基于侦察数据，AI 生成动态的 **扫描计划**。
    *   它优先考虑高风险区域（例如，“测试管理 API 的 BOLA 漏洞”，“模糊测试上传端点”）。

3.  **⚡ 执行与分析**
    *   **代理 (Agents)** 使用一套工具（浏览器、代理、终端）执行计划步骤。
    *   **Akto 集成**：使用数千种经过验证的 API 安全测试模式。
    *   **Whitepass 逻辑**：使用 Header 操控自动尝试绕过 403/401 错误。

4.  **✅ 验证 (承诺“零误报”)**
    *   每一个潜在发现都会发送给 **验证代理**。
    *   代理尝试使用生成的 Python PoC 复现漏洞。
    *   只有利用成功的漏洞才会被报告。

5.  **📊 报告**
    *   发现结果实时显示在 TUI 中。
    *   在 `strix_runs/` 目录生成包含复现步骤的综合报告。

---

## 🚀 安装

### 前置条件
1.  **Docker**：Strix 在 Docker 中运行其沙箱环境。
2.  **Python 3.12+**：CLI 需要此版本。
3.  **LLM API Key**：访问强大的 LLM（例如 OpenAI GPT-4o, Claude 3.5 Sonnet）。

### 通过 pipx 安装 (推荐)
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

### 基础扫描
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

---

## 🏗️ 架构

Strix 构建在现代模块化堆栈之上：
- **核心**：Python 3.12+ 配合 Pydantic 进行强大的数据验证。
- **沙箱**：Docker 容器用于安全地执行工具。
- **可观测性**：OpenTelemetry 和 Langfuse 用于深度追踪代理思维。
- **UI**：基于 Textual 的 TUI，提供丰富的终端体验。

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
