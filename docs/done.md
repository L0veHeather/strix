# Strix 重构完成记录

## 概述

本文档记录了 Strix 项目从原始 Agent-based 架构到 Plugin + UI 架构的完整重构过程，包括原始能力分析和新增/修改的具体实现。

---

## 一、原始项目能力分析

### 1.1 核心架构

| 模块 | 文件位置 | 原始能力 |
|------|----------|----------|
| **Agent 系统** | `strix/agents/` | 基于 LangGraph 的多 Agent 协作架构 |
| **Base Agent** | `strix/agents/base_agent.py` | Agent 基类，提供工具绑定、状态管理 |
| **Planner** | `strix/agents/planner.py` | 任务规划和子任务分解 |
| **State** | `strix/agents/state.py` | Agent 状态定义（TypedDict） |
| **StrixAgent** | `strix/agents/StrixAgent/` | 主扫描 Agent，漏洞发现逻辑 |
| **JSRouteAnalyzer** | `strix/agents/JSRouteAnalyzer/` | JavaScript 路由提取分析 |

### 1.2 LLM 集成（原始）

**文件**: `strix/llm/`

```python
# 原始 LLM 配置方式
# 通过环境变量配置
STRIX_LLM="openai/gpt-4o"           # 模型选择
OPENAI_API_KEY="sk-xxx"             # API Key
STRIX_LLM_TIMEOUT=600               # 超时时间
STRIX_ENABLE_PROMPT_CACHING=true    # Prompt 缓存
```

**核心方法**:
- `get_llm()` - 获取 LiteLLM 实例
- `LLMConfig` - 配置数据类
- 支持 OpenAI/Anthropic/Ollama 等多 Provider

### 1.3 工具系统（原始）

**文件**: `strix/tools/`

| 工具 | 功能 | 实现方式 |
|------|------|----------|
| `nuclei_scan` | 漏洞扫描 | 直接调用 nuclei CLI |
| `httpx_probe` | HTTP 探测 | 调用 httpx CLI |
| `ffuf_fuzz` | 目录/参数爆破 | 调用 ffuf CLI |
| `curl_request` | HTTP 请求 | subprocess 调用 curl |
| `browser_tool` | 浏览器自动化 | Playwright |

### 1.4 运行时环境（原始）

**文件**: `strix/runtime/`

- Docker 沙箱执行
- 依赖 Kali Linux 镜像
- 所有工具通过容器内执行

### 1.5 Scope 系统（原始）

**文件**: `strix/scope/`

- 目标范围控制
- 白名单/黑名单
- YAML 配置文件

---

## 二、重构后新增能力

### 2.1 插件系统架构

#### 2.1.1 BasePlugin 抽象类

**新增文件**: `strix/plugins/base.py`

```python
class BasePlugin(ABC):
    """插件基类 - 所有插件必须继承"""
    
    @abstractmethod
    async def execute(self, context: PluginContext) -> PluginResult:
        """执行插件逻辑"""
        pass
    
    @abstractmethod
    async def validate_config(self, config: Dict[str, Any]) -> bool:
        """验证插件配置"""
        pass
    
    @abstractmethod
    async def check_dependencies(self) -> DependencyStatus:
        """检查依赖是否满足"""
        pass
    
    async def install_dependencies(self) -> bool:
        """自动安装依赖"""
        pass
```

**关键数据结构**:
- `PluginContext` - 执行上下文（target, config, phase, scan_id）
- `PluginResult` - 执行结果（status, findings, raw_output, metrics）
- `DependencyStatus` - 依赖状态（satisfied, missing, install_commands）

#### 2.1.2 插件清单系统

**新增文件**: `strix/plugins/manifest.py`

```python
@dataclass
class PluginManifest:
    """插件元数据定义"""
    name: str                    # 插件名称
    version: str                 # 版本号
    description: str             # 描述
    author: str                  # 作者
    phase: ScanPhase             # 所属扫描阶段
    dependencies: List[str]      # 系统依赖
    python_deps: List[str]       # Python 依赖
    config_schema: Dict          # 配置 JSON Schema
    capabilities: List[str]      # 能力标签
    
    @classmethod
    def from_yaml(cls, path: Path) -> "PluginManifest":
        """从 YAML 文件加载清单"""
        pass
```

**扫描阶段枚举**:
```python
class ScanPhase(Enum):
    RECONNAISSANCE = "reconnaissance"    # 信息收集
    DISCOVERY = "discovery"              # 资产发现
    VULNERABILITY = "vulnerability"      # 漏洞扫描
    EXPLOITATION = "exploitation"        # 漏洞利用
    POST_EXPLOITATION = "post_exploitation"  # 后渗透
```

#### 2.1.3 插件加载器

**新增文件**: `strix/plugins/loader.py`

```python
class PluginLoader:
    """动态插件加载器"""
    
    def __init__(self, plugin_dirs: List[Path]):
        self.plugin_dirs = plugin_dirs
        self.loaded_plugins: Dict[str, Type[BasePlugin]] = {}
    
    def discover_plugins(self) -> List[PluginManifest]:
        """扫描目录发现所有插件"""
        pass
    
    def load_plugin(self, name: str) -> BasePlugin:
        """动态加载指定插件"""
        # 1. 查找 manifest.yaml
        # 2. 动态导入 Python 模块
        # 3. 实例化插件类
        pass
    
    def reload_plugin(self, name: str) -> BasePlugin:
        """热重载插件"""
        pass
```

#### 2.1.4 插件注册表

**新增文件**: `strix/plugins/registry.py`

```python
class PluginRegistry:
    """全局插件注册表 - 单例模式"""
    
    _instance: Optional["PluginRegistry"] = None
    
    def register(self, plugin: BasePlugin) -> None:
        """注册插件"""
        pass
    
    def get_by_phase(self, phase: ScanPhase) -> List[BasePlugin]:
        """按阶段获取插件"""
        pass
    
    def get_by_capability(self, capability: str) -> List[BasePlugin]:
        """按能力获取插件"""
        pass
```

---

### 2.2 扫描引擎

#### 2.2.1 事件总线

**新增文件**: `strix/engine/event_bus.py`

```python
class EventBus:
    """异步事件总线"""
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._queue: asyncio.Queue = asyncio.Queue()
    
    async def publish(self, event: ScanEvent) -> None:
        """发布事件"""
        await self._queue.put(event)
    
    def subscribe(self, event_type: str, handler: Callable) -> None:
        """订阅事件"""
        pass
    
    async def start(self) -> None:
        """启动事件处理循环"""
        while True:
            event = await self._queue.get()
            await self._dispatch(event)
```

**事件类型**:
```python
@dataclass
class ScanEvent:
    type: str           # scan_started, phase_completed, finding_discovered, scan_completed
    scan_id: str
    timestamp: datetime
    data: Dict[str, Any]
```

#### 2.2.2 阶段管理器

**新增文件**: `strix/engine/phase_manager.py`

```python
class PhaseManager:
    """扫描阶段编排"""
    
    def __init__(self, registry: PluginRegistry):
        self.registry = registry
        self.phase_order = [
            ScanPhase.RECONNAISSANCE,
            ScanPhase.DISCOVERY,
            ScanPhase.VULNERABILITY,
            ScanPhase.EXPLOITATION,
        ]
    
    async def execute_phase(
        self, 
        phase: ScanPhase, 
        context: ScanContext
    ) -> PhaseResult:
        """执行单个阶段的所有插件"""
        plugins = self.registry.get_by_phase(phase)
        results = []
        for plugin in plugins:
            result = await plugin.execute(context)
            results.append(result)
        return PhaseResult(phase=phase, plugin_results=results)
    
    async def run_pipeline(self, context: ScanContext) -> ScanResult:
        """执行完整扫描流水线"""
        pass
```

#### 2.2.3 结果收集器

**新增文件**: `strix/engine/result_collector.py`

```python
class ResultCollector:
    """扫描结果聚合和持久化"""
    
    def __init__(self, db: Database):
        self.db = db
        self.findings: List[Finding] = []
    
    async def add_finding(self, finding: Finding) -> None:
        """添加发现"""
        self.findings.append(finding)
        await self.db.save_finding(finding)
    
    async def generate_report(self, format: str = "json") -> str:
        """生成报告"""
        pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "total": len(self.findings),
            "by_severity": self._group_by_severity(),
            "by_type": self._group_by_type(),
        }
```

#### 2.2.4 扫描引擎主类

**新增文件**: `strix/engine/scan_engine.py`

```python
class ScanEngine:
    """扫描引擎 - 核心调度器"""
    
    def __init__(self):
        self.registry = PluginRegistry.get_instance()
        self.event_bus = EventBus()
        self.phase_manager = PhaseManager(self.registry)
        self.result_collector = ResultCollector()
    
    async def start_scan(self, config: ScanConfig) -> str:
        """启动扫描任务"""
        scan_id = str(uuid.uuid4())
        
        # 发布开始事件
        await self.event_bus.publish(ScanEvent(
            type="scan_started",
            scan_id=scan_id,
            data={"target": config.target}
        ))
        
        # 创建上下文
        context = ScanContext(
            scan_id=scan_id,
            target=config.target,
            config=config,
        )
        
        # 执行扫描流水线
        result = await self.phase_manager.run_pipeline(context)
        
        return scan_id
    
    async def pause_scan(self, scan_id: str) -> bool:
        """暂停扫描"""
        pass
    
    async def resume_scan(self, scan_id: str) -> bool:
        """恢复扫描"""
        pass
    
    async def stop_scan(self, scan_id: str) -> bool:
        """停止扫描"""
        pass
```

#### 2.2.5 LLM 集成层

**新增文件**: `strix/engine/llm_integration.py`

```python
class LLMIntegration:
    """LLM 与扫描引擎集成"""
    
    def __init__(self, llm_config: Optional[Dict] = None):
        self.config = llm_config or self._load_config()
        self.llm = self._init_llm()
    
    async def analyze_target(self, target: str) -> TargetAnalysis:
        """分析目标，推荐扫描策略"""
        prompt = self._build_analysis_prompt(target)
        response = await self.llm.acomplete(prompt)
        return self._parse_analysis(response)
    
    async def interpret_results(
        self, 
        findings: List[Finding]
    ) -> ResultInterpretation:
        """解释扫描结果"""
        pass
    
    async def suggest_next_actions(
        self, 
        context: ScanContext
    ) -> List[SuggestedAction]:
        """建议下一步操作"""
        pass
    
    async def generate_exploit(
        self, 
        vulnerability: Finding
    ) -> Optional[str]:
        """生成漏洞利用代码"""
        pass
```

---

### 2.3 存储层

#### 2.3.1 数据模型

**新增文件**: `strix/storage/models.py`

```python
from sqlalchemy import Column, String, Integer, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class Scan(Base):
    """扫描任务"""
    __tablename__ = "scans"
    
    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, paused, completed, failed
    config = Column(JSON)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    """扫描发现"""
    __tablename__ = "findings"
    
    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"))
    type = Column(String)                    # vulnerability, info, misconfiguration
    severity = Column(String)                # critical, high, medium, low, info
    title = Column(String)
    description = Column(Text)
    evidence = Column(JSON)                  # 证据数据
    plugin_name = Column(String)             # 发现来源插件
    created_at = Column(DateTime)
    scan = relationship("Scan", back_populates="findings")

class PluginExecution(Base):
    """插件执行记录"""
    __tablename__ = "plugin_executions"
    
    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"))
    plugin_name = Column(String)
    phase = Column(String)
    status = Column(String)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    output = Column(JSON)
    metrics = Column(JSON)                   # 执行指标

class Setting(Base):
    """系统设置"""
    __tablename__ = "settings"
    
    key = Column(String, primary_key=True)
    value = Column(Text)
    updated_at = Column(DateTime)
```

#### 2.3.2 数据库连接

**新增文件**: `strix/storage/database.py`

```python
class Database:
    """数据库管理"""
    
    def __init__(self, db_url: str = "sqlite:///strix.db"):
        self.engine = create_async_engine(db_url)
        self.session_factory = async_sessionmaker(self.engine)
    
    async def init_db(self) -> None:
        """初始化数据库表"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    async def get_session(self) -> AsyncSession:
        """获取数据库会话"""
        return self.session_factory()
    
    # CRUD 操作
    async def create_scan(self, scan: Scan) -> Scan: ...
    async def get_scan(self, scan_id: str) -> Optional[Scan]: ...
    async def update_scan(self, scan_id: str, **kwargs) -> Scan: ...
    async def save_finding(self, finding: Finding) -> Finding: ...
    async def get_findings(self, scan_id: str) -> List[Finding]: ...
```

---

### 2.4 FastAPI 服务器

#### 2.4.1 应用入口

**新增文件**: `strix/server/app.py`

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from strix.server.routes import scans, plugins, results, websocket, settings

app = FastAPI(
    title="Strix API",
    description="Strix Security Scanner API",
    version="2.0.0"
)

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 路由注册
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(plugins.router, prefix="/api/plugins", tags=["plugins"])
app.include_router(results.router, prefix="/api/results", tags=["results"])
app.include_router(websocket.router, prefix="/ws", tags=["websocket"])
app.include_router(settings.router, prefix="/api/settings", tags=["settings"])

@app.on_event("startup")
async def startup():
    await database.init_db()
    await plugin_loader.discover_plugins()
```

#### 2.4.2 扫描路由

**新增文件**: `strix/server/routes/scans.py`

```python
router = APIRouter()

@router.post("/", response_model=ScanResponse)
async def create_scan(request: ScanRequest):
    """创建新扫描"""
    scan_id = await scan_engine.start_scan(request.config)
    return ScanResponse(scan_id=scan_id, status="started")

@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    """获取扫描状态"""
    pass

@router.post("/{scan_id}/pause")
async def pause_scan(scan_id: str):
    """暂停扫描"""
    pass

@router.post("/{scan_id}/resume")
async def resume_scan(scan_id: str):
    """恢复扫描"""
    pass

@router.delete("/{scan_id}")
async def stop_scan(scan_id: str):
    """停止扫描"""
    pass

@router.get("/")
async def list_scans(skip: int = 0, limit: int = 20):
    """获取扫描列表"""
    pass
```

#### 2.4.3 插件路由

**新增文件**: `strix/server/routes/plugins.py`

```python
router = APIRouter()

@router.get("/")
async def list_plugins():
    """获取所有插件"""
    plugins = registry.get_all()
    return [plugin.manifest.to_dict() for plugin in plugins]

@router.get("/{name}")
async def get_plugin(name: str):
    """获取插件详情"""
    pass

@router.post("/{name}/install")
async def install_plugin_deps(name: str):
    """安装插件依赖"""
    pass

@router.get("/{name}/status")
async def get_plugin_status(name: str):
    """获取插件状态"""
    pass
```

#### 2.4.4 设置路由（LLM 配置）

**新增文件**: `strix/server/routes/settings.py`

```python
router = APIRouter()

# 支持的 LLM Provider 列表
LLM_PROVIDERS = [
    {
        "id": "openai",
        "name": "OpenAI",
        "requires_key": True,
        "key_env": "OPENAI_API_KEY",
        "models": [
            {"id": "openai/gpt-4o", "name": "GPT-4o", "description": "最强大的模型"},
            {"id": "openai/gpt-4o-mini", "name": "GPT-4o Mini", "description": "快速经济"},
        ]
    },
    {
        "id": "anthropic",
        "name": "Anthropic",
        "requires_key": True,
        "key_env": "ANTHROPIC_API_KEY",
        "models": [
            {"id": "anthropic/claude-sonnet-4-20250514", "name": "Claude Sonnet 4", "description": "最新模型"},
        ]
    },
    {
        "id": "ollama",
        "name": "Ollama (Local)",
        "requires_key": False,
        "default_base": "http://localhost:11434",
        "models": [
            {"id": "ollama/llama3.2", "name": "Llama 3.2", "description": "本地运行"},
            {"id": "ollama/qwen2.5", "name": "Qwen 2.5", "description": "中文优化"},
        ]
    },
    # ... DeepSeek, Custom
]

@router.get("/providers")
async def get_providers():
    """获取支持的 LLM Provider 列表"""
    return {"providers": LLM_PROVIDERS}

@router.get("/llm")
async def get_llm_config():
    """获取当前 LLM 配置"""
    config = {
        "model": os.getenv("STRIX_LLM", "openai/gpt-4o"),
        "timeout": int(os.getenv("STRIX_LLM_TIMEOUT", "600")),
        "enable_caching": os.getenv("STRIX_ENABLE_PROMPT_CACHING", "true") == "true",
    }
    # 检查哪些 Provider 已配置
    configured = {}
    for provider in LLM_PROVIDERS:
        if provider.get("key_env"):
            configured[provider["id"]] = bool(os.getenv(provider["key_env"]))
    
    return {"config": config, "configured_providers": configured}

@router.put("/llm")
async def update_llm_config(config: LLMConfig):
    """更新 LLM 配置"""
    # 保存到数据库
    await db.save_setting("llm_model", config.model)
    await db.save_setting("llm_timeout", str(config.timeout))
    
    # 设置环境变量（当前进程）
    os.environ["STRIX_LLM"] = config.model
    if config.api_key:
        # 根据 provider 设置对应的环境变量
        provider = config.model.split("/")[0]
        key_map = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
        if provider in key_map:
            os.environ[key_map[provider]] = config.api_key
    
    return {"status": "updated"}

@router.post("/test-llm")
async def test_llm_connection():
    """测试 LLM 连接"""
    try:
        from litellm import completion
        response = completion(
            model=os.getenv("STRIX_LLM", "openai/gpt-4o"),
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=5
        )
        return {"status": "success", "model": response.model}
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

#### 2.4.5 WebSocket 路由

**新增文件**: `strix/server/routes/websocket.py`

```python
router = APIRouter()

class ConnectionManager:
    """WebSocket 连接管理"""
    
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
    
    async def broadcast(self, scan_id: str, message: dict):
        """广播消息到订阅该扫描的所有客户端"""
        if scan_id in self.active_connections:
            for connection in self.active_connections[scan_id]:
                await connection.send_json(message)

manager = ConnectionManager()

@router.websocket("/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket, scan_id)
    try:
        while True:
            data = await websocket.receive_text()
            # 处理客户端消息
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
```

---

### 2.5 核心插件实现

#### 2.5.1 Nuclei 插件

**新增目录**: `plugins/nuclei/`

```
plugins/nuclei/
├── manifest.yaml
├── __init__.py
└── plugin.py
```

**manifest.yaml**:
```yaml
name: nuclei
version: "1.0.0"
description: Fast vulnerability scanner using templates
author: Strix Team
phase: vulnerability
dependencies:
  - nuclei
capabilities:
  - vulnerability_scanning
  - template_based
  - cve_detection
config_schema:
  type: object
  properties:
    templates:
      type: array
      description: Template paths or tags
    severity:
      type: string
      enum: [critical, high, medium, low, info]
    rate_limit:
      type: integer
      default: 150
```

**plugin.py**:
```python
class NucleiPlugin(BasePlugin):
    """Nuclei 漏洞扫描插件"""
    
    async def execute(self, context: PluginContext) -> PluginResult:
        cmd = self._build_command(context)
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        findings = self._parse_output(stdout.decode())
        return PluginResult(
            status="completed",
            findings=findings,
            raw_output=stdout.decode()
        )
    
    def _build_command(self, context: PluginContext) -> List[str]:
        cmd = ["nuclei", "-u", context.target, "-json"]
        if context.config.get("templates"):
            cmd.extend(["-t", ",".join(context.config["templates"])])
        if context.config.get("severity"):
            cmd.extend(["-s", context.config["severity"]])
        return cmd
    
    def _parse_output(self, output: str) -> List[Finding]:
        findings = []
        for line in output.strip().split("\n"):
            if line:
                data = json.loads(line)
                findings.append(Finding(
                    type="vulnerability",
                    severity=data.get("info", {}).get("severity", "info"),
                    title=data.get("info", {}).get("name", "Unknown"),
                    description=data.get("info", {}).get("description", ""),
                    evidence={"matched_at": data.get("matched-at")}
                ))
        return findings
    
    async def check_dependencies(self) -> DependencyStatus:
        result = subprocess.run(["which", "nuclei"], capture_output=True)
        if result.returncode == 0:
            return DependencyStatus(satisfied=True)
        return DependencyStatus(
            satisfied=False,
            missing=["nuclei"],
            install_commands=["go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"]
        )
```

#### 2.5.2 其他插件

| 插件 | 目录 | 功能 | 阶段 |
|------|------|------|------|
| **httpx** | `plugins/httpx/` | HTTP 探测、技术识别 | discovery |
| **ffuf** | `plugins/ffuf/` | 目录/参数爆破 | discovery |
| **katana** | `plugins/katana/` | 爬虫、URL 收集 | reconnaissance |
| **sqlmap** | `plugins/sqlmap/` | SQL 注入检测 | vulnerability |

---

### 2.6 桌面应用（Tauri + React）

#### 2.6.1 项目结构

**新增目录**: `desktop/`

```
desktop/
├── src-tauri/              # Tauri Rust 后端
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   └── src/
│       └── main.rs
├── src/                    # React 前端
│   ├── main.tsx
│   ├── App.tsx
│   ├── components/
│   │   ├── ui/             # Shadcn UI 组件
│   │   ├── layout/
│   │   │   └── sidebar.tsx
│   │   └── theme-provider.tsx
│   ├── pages/
│   │   ├── dashboard.tsx
│   │   ├── scans.tsx
│   │   ├── scan-detail.tsx
│   │   ├── plugins.tsx
│   │   ├── results.tsx
│   │   └── settings.tsx    # LLM 配置界面
│   ├── lib/
│   │   ├── api.ts          # API 客户端
│   │   ├── store.ts        # Zustand 状态管理
│   │   └── utils.ts
│   └── hooks/
│       └── use-toast.ts
├── package.json
├── vite.config.ts
├── tailwind.config.js
└── tsconfig.json
```

#### 2.6.2 Settings 页面（LLM 配置）

**文件**: `desktop/src/pages/settings.tsx`

```tsx
export default function SettingsPage() {
  // LLM 状态管理
  const [selectedProvider, setSelectedProvider] = useState("openai");
  const [selectedModel, setSelectedModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [apiBase, setApiBase] = useState("");
  const [timeout, setTimeoutValue] = useState(600);
  const [enableCaching, setEnableCaching] = useState(true);

  // API 查询
  const { data: providersData } = useQuery({
    queryKey: ["llm-providers"],
    queryFn: settingsApi.getProviders,
  });

  const { data: llmConfigData } = useQuery({
    queryKey: ["llm-config"],
    queryFn: settingsApi.getLLMConfig,
  });

  // 保存配置
  const updateConfig = useMutation({
    mutationFn: settingsApi.updateLLMConfig,
    onSuccess: () => {
      toast({ title: "Settings saved" });
    },
  });

  // 测试连接
  const testConnection = useMutation({
    mutationFn: settingsApi.testLLMConnection,
  });

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* LLM Configuration Card */}
      <Card>
        <CardHeader>
          <CardTitle>LLM Configuration</CardTitle>
        </CardHeader>
        <CardContent>
          {/* Provider 选择 */}
          <div className="grid grid-cols-5 gap-2">
            {providers.map(p => (
              <Button
                key={p.id}
                variant={selectedProvider === p.id ? "default" : "outline"}
                onClick={() => setSelectedProvider(p.id)}
              >
                {p.name}
                {configured[p.id] && <Check className="ml-2 h-4 w-4" />}
              </Button>
            ))}
          </div>

          {/* Model 选择 */}
          {currentProvider?.models.map(model => (
            <div
              key={model.id}
              className={cn(
                "p-3 rounded-lg border cursor-pointer",
                selectedModel === model.id && "border-primary"
              )}
              onClick={() => setSelectedModel(model.id)}
            >
              <p className="font-medium">{model.name}</p>
              <p className="text-xs text-muted-foreground">{model.description}</p>
            </div>
          ))}

          {/* API Key 输入 */}
          {currentProvider?.requires_key && (
            <div className="flex gap-2">
              <Input
                type={showApiKey ? "text" : "password"}
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                placeholder="Enter API key"
              />
              <Button onClick={() => setShowApiKey(!showApiKey)}>
                {showApiKey ? <EyeOff /> : <Eye />}
              </Button>
            </div>
          )}

          {/* API Base URL */}
          <Input
            value={apiBase}
            onChange={e => setApiBase(e.target.value)}
            placeholder="http://localhost:11434"
          />

          {/* 高级设置 */}
          <Input
            type="number"
            value={timeout}
            onChange={e => setTimeoutValue(parseInt(e.target.value))}
          />

          {/* 操作按钮 */}
          <Button onClick={handleSave}>Save Configuration</Button>
          <Button variant="outline" onClick={() => testConnection.mutate()}>
            Test Connection
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
```

#### 2.6.3 API 客户端

**文件**: `desktop/src/lib/api.ts`

```typescript
// LLM 配置相关类型
export interface LLMModel {
  id: string;
  name: string;
  description: string;
}

export interface LLMProvider {
  id: string;
  name: string;
  requires_key: boolean;
  key_env?: string;
  default_base?: string;
  models: LLMModel[];
}

export interface LLMConfig {
  model: string;
  api_key?: string;
  api_base?: string;
  timeout: number;
  enable_caching: boolean;
}

// Settings API
export const settingsApi = {
  getProviders: async (): Promise<{ providers: LLMProvider[] }> => {
    const res = await fetch(`${API_URL}/api/settings/providers`);
    return res.json();
  },

  getLLMConfig: async (): Promise<LLMConfigResponse> => {
    const res = await fetch(`${API_URL}/api/settings/llm`);
    return res.json();
  },

  updateLLMConfig: async (config: Partial<LLMConfig>): Promise<{ status: string }> => {
    const res = await fetch(`${API_URL}/api/settings/llm`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    });
    return res.json();
  },

  testLLMConnection: async (): Promise<{ status: string; message?: string }> => {
    const res = await fetch(`${API_URL}/api/settings/test-llm`, {
      method: "POST",
    });
    return res.json();
  },
};
```

---

### 2.7 一键启动脚本

**新增文件**: `start.sh`

```bash
#!/bin/bash
set -e

echo "🚀 Starting Strix..."

# 1. 检查 Python 环境
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required"
    exit 1
fi

# 2. 检查并安装 Python 依赖
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate
pip install -e . -q

# 3. 初始化数据库
python -c "from strix.storage.database import Database; import asyncio; asyncio.run(Database().init_db())"

# 4. 启动后端服务
echo "🔧 Starting backend server..."
uvicorn strix.server.app:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# 5. 等待后端就绪
sleep 2

# 6. 启动前端（可选）
if [ -d "desktop" ] && command -v npm &> /dev/null; then
    echo "🖥️ Starting desktop app..."
    cd desktop
    npm install -q
    npm run tauri dev &
    FRONTEND_PID=$!
    cd ..
fi

echo "✅ Strix is running!"
echo "   Backend: http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"

# 等待退出
wait $BACKEND_PID
```

---

### 2.8 Docker 修复

**修改文件**: `containers/Dockerfile`

```dockerfile
# 原始（有问题）
RUN apt-get install -y libcups2 libasound2 netcat-traditional

# 修改后（Debian t64 过渡）
RUN apt-get install -y libcups2t64 libasound2t64 netcat-traditional
```

**原因**: Debian/Kali 从 2024 年开始进行 64-bit time_t 过渡，部分包名添加了 `t64` 后缀。

---

## 三、架构对比总结

| 维度 | 原始架构 | 重构后架构 |
|------|----------|------------|
| **核心模式** | Agent-based (LangGraph) | Plugin + Engine |
| **工具调用** | Agent 动态决策 | 阶段化流水线 |
| **扩展方式** | 修改 Agent 代码 | 添加插件 YAML + Python |
| **UI** | CLI only | Tauri Desktop App |
| **数据存储** | 文件系统 | SQLite |
| **实时通信** | 无 | WebSocket |
| **LLM 配置** | 环境变量 | UI 界面配置 |
| **依赖管理** | Docker 必须 | 可选（本地安装） |

---

## 四、文件变更清单

### 新增文件

```
strix/plugins/
├── __init__.py
├── base.py              # 插件基类
├── manifest.py          # 清单系统
├── loader.py            # 动态加载器
└── registry.py          # 插件注册表

strix/engine/
├── __init__.py
├── event_bus.py         # 事件总线
├── phase_manager.py     # 阶段管理
├── result_collector.py  # 结果收集
├── scan_engine.py       # 扫描引擎
└── llm_integration.py   # LLM 集成

strix/storage/
├── __init__.py
├── models.py            # SQLAlchemy 模型
└── database.py          # 数据库连接

strix/server/
├── __init__.py
├── app.py               # FastAPI 入口
└── routes/
    ├── __init__.py
    ├── scans.py         # 扫描 API
    ├── plugins.py       # 插件 API
    ├── results.py       # 结果 API
    ├── websocket.py     # WebSocket
    └── settings.py      # 设置 API (LLM 配置)

plugins/
├── nuclei/              # Nuclei 插件
├── httpx/               # HTTPx 插件
├── ffuf/                # FFUF 插件
├── katana/              # Katana 插件
└── sqlmap/              # SQLMap 插件

desktop/                 # 完整 Tauri + React 应用
├── src-tauri/
├── src/
│   ├── pages/
│   │   └── settings.tsx # LLM 配置界面
│   └── lib/
│       └── api.ts       # settingsApi
└── ...

start.sh                 # 一键启动脚本
docs/done.md             # 本文档
```

### 修改文件

```
containers/Dockerfile    # libcups2 → libcups2t64
README.md                # 更新架构说明
README_ZH.md             # 更新中文说明
```

---

## 五、使用方式

### 5.1 一键启动

```bash
chmod +x start.sh
./start.sh
```

### 5.2 配置 LLM（UI 方式）

1. 打开桌面应用或访问 `http://localhost:8000`
2. 进入 Settings 页面
3. 选择 Provider（OpenAI/Anthropic/Ollama/DeepSeek）
4. 选择 Model
5. 输入 API Key（如果需要）
6. 点击 "Save Configuration"
7. 点击 "Test Connection" 验证

### 5.3 配置 LLM（环境变量方式）

```bash
export STRIX_LLM="openai/gpt-4o"
export OPENAI_API_KEY="sk-xxx"
# 或
export STRIX_LLM="ollama/llama3.2"
export OLLAMA_API_BASE="http://localhost:11434"
```

---

*文档生成时间: 2025-12-19*

---

## 六、客户端实时扫描输出功能（新增）

### 6.1 功能概述

实现客户端完整的扫描流程可视化，包括：
- 一键配置扫描参数（Target、Scope）
- 实时显示扫描进度和控制台输出
- 显示错误和警告信息
- 扫描完成后查看详细结果

### 6.2 控制台日志系统

#### Store 扩展

**修改文件**: `desktop/src/lib/store.ts`

```typescript
// 新增控制台日志类型
export interface ConsoleLogEntry {
  id: string;
  timestamp: Date;
  type: "info" | "output" | "error" | "warning" | "success" | "command";
  source: string;  // plugin name, phase, or system
  message: string;
  details?: unknown;
}

// Store 新增方法
interface StrixState {
  // Console output
  consoleLogs: Map<string, ConsoleLogEntry[]>;  // scan_id -> logs
  
  // Console actions
  addConsoleLog: (scanId: string, entry: Omit<ConsoleLogEntry, "id" | "timestamp">) => void;
  clearConsoleLogs: (scanId: string) => void;
  getConsoleLogs: (scanId: string) => ConsoleLogEntry[];
}
```

#### WebSocket 消息处理

**修改文件**: `desktop/src/lib/websocket.ts`

新增支持的消息类型：
- `scan.started` - 扫描开始
- `scan.progress` - 进度更新
- `scan.completed` - 扫描完成
- `scan.error` / `scan.failed` - 错误处理
- `phase.started` / `phase.completed` - 阶段状态
- `plugin.started` / `plugin.output` / `plugin.completed` - 插件执行
- `vulnerability.found` - 漏洞发现
- `llm.request` / `llm.response` - LLM 请求

```typescript
// 消息处理示例
case "plugin.output": {
  const outputData = data as { plugin: string; scan_id: string; output: string };
  store.addConsoleLog(outputData.scan_id, {
    type: "output",
    source: outputData.plugin,
    message: outputData.output.trim(),
  });
  break;
}

case "vulnerability.found": {
  const vulnData = data as { severity: string; title: string; scan_id: string };
  const severityIcon = getSeverityIcon(vulnData.severity);
  store.addConsoleLog(vulnData.scan_id, {
    type: "warning",
    source: "scanner",
    message: `${severityIcon} [${vulnData.severity.toUpperCase()}] ${vulnData.title}`,
  });
  break;
}
```

### 6.3 ScanConsole 组件

**新增文件**: `desktop/src/components/scan-console.tsx`

```tsx
interface ScanConsoleProps {
  scanId: string;
  maxHeight?: string;
  autoScroll?: boolean;
}

export function ScanConsole({ scanId, maxHeight = "400px", autoScroll = true }) {
  const logs = useStrixStore((state) => state.consoleLogs.get(scanId) || []);
  
  return (
    <div className="rounded-lg border bg-zinc-950">
      {/* Header with controls */}
      <div className="flex items-center justify-between px-4 py-2 border-b">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-green-400" />
          <span className="font-mono text-sm">Console</span>
          {/* Error/Warning counts */}
          {errorCount > 0 && <span className="text-red-400">{errorCount} errors</span>}
        </div>
        <div className="flex gap-1">
          <Button onClick={handleExport}>Export</Button>
          <Button onClick={() => clearLogs(scanId)}>Clear</Button>
        </div>
      </div>
      
      {/* Log entries */}
      <div ref={containerRef} className="overflow-auto font-mono text-sm p-3">
        {logs.map((log) => (
          <div key={log.id} className="flex gap-2 hover:bg-zinc-900/50">
            <span className="text-zinc-600">{log.timestamp.toLocaleTimeString()}</span>
            <span className={getSourceColor(log.source)}>[{log.source}]</span>
            <span className={getLogTypeColor(log.type)}>{log.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
```

功能特性：
- 实时日志展示（自动滚动）
- 日志类型过滤（all/output/error/warning/info）
- 导出为 .log 文件
- 清空日志
- 展开/收起
- 错误/警告计数显示
- 颜色高亮（按日志类型和来源）

### 6.4 扫描详情页更新

**修改文件**: `desktop/src/pages/scan-detail.tsx`

新增 Console Output 区域：

```tsx
<Card>
  <CardHeader>
    <CardTitle className="flex items-center gap-2">
      <Terminal className="h-5 w-5" />
      Console Output
    </CardTitle>
  </CardHeader>
  <CardContent className="p-0">
    <ScanConsole 
      scanId={scanId!} 
      maxHeight="500px"
    />
  </CardContent>
</Card>
```

### 6.5 扫描配置页更新

**修改文件**: `desktop/src/pages/scan.tsx`

新增功能：
1. **扫描预设** - Quick Scan / Full Scan / Recon Only
2. **LLM 配置检测** - 未配置时显示警告
3. **Scope 配置** - 文本框输入包含/排除规则
4. **更友好的阶段选择** - 带图标和描述

```tsx
const SCAN_PRESETS = [
  { 
    id: "quick", 
    name: "Quick Scan", 
    description: "Fast reconnaissance and basic vuln scan",
    phases: ["RECONNAISSANCE", "VULNERABILITY_SCAN"],
    icon: <Zap className="h-5 w-5" />,
  },
  { 
    id: "full", 
    name: "Full Scan", 
    description: "Complete security assessment",
    phases: ["RECONNAISSANCE", "ENUMERATION", "VULNERABILITY_SCAN", "EXPLOITATION", "VALIDATION"],
  },
  // ...
];
```

### 6.6 后端事件发布增强

**修改文件**: `strix/engine/phase_manager.py`

新增事件发布：
- `PLUGIN_STARTED` - 插件开始执行
- `PLUGIN_COMPLETED` - 插件执行完成（包含 findings_count, duration_ms）
- `PLUGIN_ERROR` - 插件错误

```python
async def _execute_plugin(...):
    # Emit plugin started event
    await self._event_bus.publish(Event(
        type=EventType.PLUGIN_STARTED,
        scan_id=self._scan_id,
        data={"plugin": plugin_name, "phase": phase.value},
    ))
    
    try:
        # ... execute plugin ...
        
        # Emit plugin completed event
        await self._event_bus.publish(Event(
            type=EventType.PLUGIN_COMPLETED,
            scan_id=self._scan_id,
            data={
                "plugin": plugin_name,
                "findings_count": findings_count,
                "duration_ms": duration_ms,
            },
        ))
    except Exception as e:
        # Emit plugin error event
        await self._event_bus.publish(Event(
            type=EventType.PLUGIN_ERROR,
            scan_id=self._scan_id,
            data={"plugin": plugin_name, "error": str(e)},
        ))
        raise
```

**修改文件**: `strix/engine/event_bus.py`

新增事件类型：
```python
class EventType(str, Enum):
    # ... existing ...
    SCAN_PROGRESS = "scan.progress"
    SCAN_ERROR = "scan.error"
    
    # LLM events
    LLM_REQUEST = "llm.request"
    LLM_RESPONSE = "llm.response"
    LLM_ERROR = "llm.error"
```

**修改文件**: `strix/server/routes/websocket.py`

新增 WebSocket 事件转发：
```python
event_bus.subscribe(EventType.PLUGIN_STARTED, handle_plugin_started)
event_bus.subscribe(EventType.PLUGIN_COMPLETED, handle_plugin_completed)
event_bus.subscribe(EventType.PLUGIN_ERROR, handle_plugin_error)
```

### 6.7 使用流程

1. **配置 LLM**（可选）
   - 进入 Settings → LLM Configuration
   - 选择 Provider 和 Model
   - 输入 API Key

2. **创建扫描**
   - 进入 New Scan 页面
   - 输入 Target URL
   - 选择扫描预设（Quick/Full/Recon）
   - 可选：配置 Scope、选择特定插件
   - 点击 "Start Scan"

3. **监控扫描**
   - 自动跳转到扫描详情页
   - 查看实时进度条和当前阶段
   - Console Output 显示：
     - 阶段开始/完成
     - 插件执行状态
     - 实时扫描输出
     - 发现的漏洞（带严重程度图标）
     - 错误和警告

4. **查看结果**
   - Vulnerabilities 区域显示统计和列表
   - 可导出为 JSON/Markdown/SARIF
   - Console 日志可导出为 .log 文件

### 6.8 界面展示示例

```
┌─────────────────────────────────────────────────────────────┐
│ Scan Details                                    [Pause][Stop] │
├─────────────────────────────────────────────────────────────┤
│ Status: Running - Vulnerability Scan            [====65%===] │
├─────────────────────────────────────────────────────────────┤
│ Scan Phases:                                                │
│   ✅ Reconnaissance (12.3s) - 156 findings                  │
│   ✅ Enumeration (45.2s) - 23 findings                      │
│   🔄 Vulnerability Scan (running...)                        │
│   ⏳ Exploitation                                           │
│   ⏳ Validation                                             │
├─────────────────────────────────────────────────────────────┤
│ Vulnerabilities:                                            │
│   🔴 Critical: 2  🟠 High: 5  🟡 Medium: 12  🟢 Low: 8      │
├─────────────────────────────────────────────────────────────┤
│ Console Output                            [Export][Clear]    │
├─────────────────────────────────────────────────────────────┤
│ 14:32:01 [system] 🚀 Scan started for target: https://...   │
│ 14:32:01 [system] 📋 Phases: Reconnaissance → Enumeration   │
│ 14:32:02 [RECONNAISSANCE] ▶️ Starting phase: Reconnaissance │
│ 14:32:02 [httpx] 🔧 Running plugin: httpx                   │
│ 14:32:05 [httpx] HTTP/1.1 200 OK - https://example.com      │
│ 14:32:08 [httpx] ✓ httpx completed - 156 findings           │
│ 14:32:08 [katana] 🔧 Running plugin: katana                 │
│ 14:32:15 [katana] Found: /api/v1/users                      │
│ 14:32:20 [nuclei] 🟠 [HIGH] SQL Injection in login form     │
│ 14:32:20 [nuclei]   └─ https://example.com/login?user=      │
│ ...                                                         │
└─────────────────────────────────────────────────────────────┘
```
