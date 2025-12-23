# Strix Agent Philosophy

## 核心原则 / Core Principles

This document defines the fundamental philosophy that governs how Strix Agents behave. These principles MUST be followed by all code that interacts with the LLM.

---

## 一、Agent 身份与生命周期 / Agent Identity & Lifecycle

### ✅ MUST:

- Agent 是 **持续运行的智能体**，不是一次性分析器
- Agent 的职责是：**提出下一步探索建议**，而不是给最终结论
- Agent 不能自行结束扫描，**结束条件由人或代码决定**
- 每一次 LLM 调用都被视为 **一个 Step**，而不是一次 Scan

### ❌ Anti-Patterns:

- "请分析是否存在漏洞" - LLM不应该做最终判断
- "扫描完成后给我结果" - LLM不能决定何时完成

### Implementation:

```python
# In strix/core/agent_philosophy.py
class AgentRole(str, Enum):
    EXPLORER = "explorer"      # ✅ Proposes next actions
    ANALYZER = "analyzer"      # ❌ FORBIDDEN
    EXECUTOR = "executor"      # ❌ FORBIDDEN
```

---

## 二、LLM 决策权 / LLM Decision Rights

### ✅ LLM CAN:

- 提出 **漏洞假设** (Vulnerability Hypothesis)
- 提出 **下一步探索动作** (Next Exploration Action)
- 选择 **使用哪个插件/工具** (Tool Selection)
- 每一轮只能提出 **一个动作** (Single Action Per Step)

### ❌ LLM CANNOT:

- 并行工具调用建议 (Parallel Actions)
- "可以顺便再试试……" (Side Actions)
- 决定扫描结束 (Termination)
- 直接执行任何操作 (Execution)

### Implementation:

```python
# In strix/core/llm_response_parser.py
class LLMResponseParser:
    # Rejects responses with multiple [INTENDED_ACTION] sections
    # Rejects termination attempts
    # Rejects execution claims
```

---

## 三、动作与执行解耦 / Action-Execution Decoupling

**这是最核心的原则 / This is the MOST CRITICAL principle**

### ✅ MUST:

- LLM **永远不执行** 动作
- LLM 只输出 **INTENDED_ACTION**
- 插件执行结果必须 **显式回灌给 LLM**
- LLM 不得基于假想结果继续推理

### Mandatory Output Structure:

```
[VULN_HYPOTHESIS]
<一句话描述当前假设>

[EVIDENCE]
- 证据 1
- 证据 2

[INTENDED_ACTION]
type: plugin | request
name: <工具名>
goal: <唯一目标>
expected_signal: <判断依据>
```

### Implementation:

```python
# In strix/core/step_executor.py
class StepExecutor:
    async def execute_step(self, step_output: StepOutput) -> ExecutionResult:
        # 1. Parse LLM's INTENDED_ACTION
        # 2. Execute via handler (NOT LLM)
        # 3. Create feedback message
        # 4. Return for explicit feedback to LLM

# In strix/core/step_based_loop.py
class StepBasedAgentLoop:
    async def _run_loop(self):
        # After execution, feedback is EXPLICITLY added:
        feedback_message = result.to_feedback_message()
        self.state.add_message("user", feedback_message)
```

---

## 四、插件 = LLM 的"外部器官" / Plugins as External Tools

### ✅ MUST:

- 插件是 **LLM 主动选择的**
- 插件 **不是** 流程强制步骤
- 插件调用 **理由必须明确**
- 插件失败/无结果 ≠ 扫描失败

### ❌ Anti-Patterns:

- "跑一遍 nuclei 看看" (Run full scan)
- "先扫全量再说" (Scan everything first)

### Implementation:

```python
# In strix/core/action_handlers.py
class ActionHandlerRegistry:
    # Plugins are registered but OPTIONAL
    # LLM chooses when to use via INTENDED_ACTION
    # Plugin failures are handled gracefully
```

---

## 五、状态推进规则 / State Progression Rules

### ✅ MUST:

- 每一个 Step **必须依赖新的信息**
- 没有新结果 → **不允许推进结论**
- LLM **不得重复** 提出相同动作
- 超过 N 次无进展 → **人工介入**

### Implementation:

```python
# In strix/core/agent_philosophy.py
@dataclass
class StepProgressionGuard:
    max_no_progress_steps: int = 5
    recent_actions: list[str] = field(default_factory=list)
    no_progress_count: int = 0
    
    def can_progress(self, new_action, has_new_info) -> tuple[bool, str]:
        # Blocks progression without new information
        # Detects and rejects duplicate actions
        # Triggers human intervention after N failures
```

---

## 六、漏洞确认规则 / Vulnerability Confirmation Rules

### ✅ MUST:

- **"疑似漏洞" ≠ "漏洞成立"** - Suspected ≠ Confirmed
- 必须存在 **可复现的行为变化**
- 必须说明 **误报可能性**
- **PoC 是验证，不是结论**

### Implementation:

```python
# In strix/core/agent_philosophy.py
@dataclass
class VulnerabilityStatus:
    status: str  # "suspected", "testing", "confirmed", "false_positive"
    false_positive_probability: float = 0.5  # Default 50%
    
    def is_confirmed(self) -> bool:
        # Requires reproducible behavior
        # PoC must validate
        # False positive probability < 20%
```

---

## 七、人工控制点 / Human-in-the-loop

### ✅ Human CAN:

- **批准/拒绝** 动作 (Approve/Reject)
- **修改目标** (Modify Target)
- **强制切换方向** (Redirect)
- 在任何 Step **中止 Agent** (Stop Anytime)

### ✅ Agent MUST:

- **服从** 人工 Decision

### Implementation:

```python
# In strix/core/agent_philosophy.py
class HumanDecision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    MODIFY = "modify"
    REDIRECT = "redirect"
    PAUSE = "pause"
    STOP = "stop"
    RESUME = "resume"

# In strix/core/step_based_loop.py
class StepBasedAgentLoop:
    def pause(self) -> None: ...
    def resume(self) -> None: ...
    def stop(self, reason: str) -> None: ...
    def modify_direction(self, new_instruction: str) -> None: ...
```

---

## 八、结束条件 / Termination Conditions

### ✅ Valid Termination (External Only):

1. 达到人工设定的 **Step 上限** (Step Limit)
2. 人工明确指示 **停止** (Human Stop)
3. 测试范围 **耗尽** (Scope Exhausted)

### ❌ FORBIDDEN Termination:

- "未发现漏洞，扫描结束"
- "分析完成"
- LLM 任何形式的终止声明

### Implementation:

```python
# In strix/core/agent_philosophy.py
class TerminationReason(str, Enum):
    HUMAN_STOP = "human_stop"
    STEP_LIMIT = "step_limit"
    SCOPE_EXHAUSTED = "scope_exhausted"
    TIMEOUT = "timeout"

@dataclass
class TerminationController:
    def should_terminate(self) -> tuple[bool, TerminationReason | None]:
        # ONLY checks external conditions
        # NEVER accepts LLM-initiated termination
    
    def reject_llm_termination(self, reason: str) -> str:
        # Returns message to send back to LLM
        return "TERMINATION REJECTED: You are not authorized..."
```

---

## 九、Vibe Coding 自检 / Self-Check Questions

每次改动代码时，问自己这 5 个问题：

| Question | Expected Answer |
|----------|-----------------|
| LLM 是否还能决定"下一步做什么"？ | ✅ Yes |
| LLM 是否还能改变策略？ | ✅ Yes |
| 是否存在连续自动执行？ | ❌ No |
| 是否还能被人中途打断？ | ✅ Yes |
| 插件是否仍然是可选而非强制？ | ✅ Yes |

### Implementation:

```python
# In strix/core/agent_philosophy.py
class PhilosophyValidator:
    @staticmethod
    def vibe_check() -> dict[str, bool]:
        return {
            "llm_decides_next_step": True,
            "llm_can_change_strategy": True,
            "no_continuous_auto_exec": True,
            "human_can_interrupt": True,
            "plugins_are_optional": True,
        }
```

---

## 文件结构 / File Structure

```
strix/core/
├── agent_philosophy.py      # Core principles & data structures
├── step_executor.py         # Action execution (decoupled from LLM)
├── llm_response_parser.py   # Validates LLM output format
├── step_based_loop.py       # Main agent loop with human control
├── action_handlers.py       # Handlers for different action types
└── ...

strix/agents/
├── state.py                 # Includes StepBasedState
└── StrixAgent/
    └── agent_philosophy_prompt.jinja2  # Prompt enforcing philosophy
```

---

## 使用示例 / Usage Example

```python
from strix.core.step_based_loop import create_step_based_loop
from strix.agents.state import StepBasedState

# Create state
state = StepBasedState(agent_name="SecurityExplorer")

# Create loop
loop = create_step_based_loop(
    state=state,
    llm_client=my_llm,
    max_steps=500,
    require_human_approval=False,  # Set True for critical scans
)

# Human controls
loop.on_step_proposed(lambda step: print(f"Proposed: {step}"))
loop.on_human_required(lambda reason: print(f"Human needed: {reason}"))

# Run
result = await loop.run("Scan https://target.com for vulnerabilities")

# Human can interrupt anytime
loop.pause()
loop.modify_direction("Focus on authentication")
loop.resume()
loop.stop("Manual termination")
```
