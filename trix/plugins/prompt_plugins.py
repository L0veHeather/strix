"""Prompt-Based Vulnerability Plugin System.

设计理念：
1. 插件 = LLM 提示词模板
2. LLM 负责漏洞判断（允许）
3. 代码负责流程控制（确定性）
4. 插件从 prompts/vulnerabilities/ 加载专业知识

支持的漏洞类型 (17种)：
- authentication_jwt: JWT认证漏洞
- broken_function_level_authorization: 越权访问
- business_logic: 业务逻辑漏洞
- csrf: 跨站请求伪造
- idor: 不安全的直接对象引用
- information_disclosure: 信息泄露
- insecure_file_uploads: 不安全的文件上传
- mass_assignment: 批量赋值漏洞
- open_redirect: 开放重定向
- path_traversal_lfi_rfi: 路径遍历/文件包含
- race_conditions: 竞态条件
- rce: 远程代码执行
- sql_injection: SQL注入
- ssrf: 服务端请求伪造
- subdomain_takeover: 子域名接管
- xss: 跨站脚本
- xxe: XML外部实体注入
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from trix.models.finding import ConfidenceLevel, RiskLevel, VulnFinding
from trix.models.judgment import JudgmentResult

logger = logging.getLogger(__name__)


@dataclass
class ScanContext:
    """扫描上下文 - 代码控制这些参数"""
    target: str
    parameter: str
    method: str = "GET"
    raw_request: str = ""
    raw_response: str = ""
    baseline_response: str = ""
    response_time_ms: float = 0.0
    baseline_time_ms: float = 0.0
    
    # 额外上下文
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    content_type: str = ""


class PromptBasedPlugin(ABC):
    """基于提示词的漏洞检测插件基类."""
    
    name: str = ""
    vuln_type: str = ""
    description: str = ""
    
    # 提示词文件名（对应 prompts/vulnerabilities/{prompt_file}.jinja）
    prompt_file: str = ""
    
    def get_vuln_knowledge(self) -> str:
        """加载漏洞专业知识提示词."""
        prompts_dir = Path(__file__).parent.parent / "prompts" / "vulnerabilities"
        prompt_file = prompts_dir / f"{self.prompt_file}.jinja"
        
        if prompt_file.exists():
            return prompt_file.read_text()
        return ""
    
    def get_system_prompt(self) -> str:
        """获取系统提示词"""
        return f"""你是一个专业的安全分析师，专注于 {self.description}。

你的任务是分析 HTTP 请求/响应，判断是否存在 {self.vuln_type} 漏洞。

## 分析原则：
1. 基于证据：只根据实际观察到的行为判断
2. 避免误报：只有在高度确信时才确认漏洞
3. 详细推理：解释你的判断依据
4. 提供证据：列出支持判断的具体证据

## 输出格式（必须是 JSON）：
{{
    "is_vulnerable": true/false,
    "confidence": 0.0-1.0,
    "risk_level": "critical/high/medium/low/info",
    "reasoning": "详细分析过程...",
    "evidence": ["证据1", "证据2"],
    "payload_suggestions": ["建议的payload1", "建议的payload2"],
    "remediation": "修复建议"
}}
"""
    
    @abstractmethod
    def build_prompt(self, context: ScanContext) -> str:
        """构建 LLM 分析提示词."""
        pass
    
    def parse_llm_response(self, response: str) -> JudgmentResult:
        """解析 LLM 响应"""
        try:
            data = json.loads(response)
            
            conf = data.get("confidence", 0.0)
            if conf >= 0.9:
                conf_level = ConfidenceLevel.CONFIRMED
            elif conf >= 0.7:
                conf_level = ConfidenceLevel.LIKELY
            elif conf >= 0.4:
                conf_level = ConfidenceLevel.SUSPECTED
            else:
                conf_level = ConfidenceLevel.FALSE_POSITIVE
            
            risk_map = {
                "critical": RiskLevel.CRITICAL,
                "high": RiskLevel.HIGH,
                "medium": RiskLevel.MEDIUM,
                "low": RiskLevel.LOW,
                "info": RiskLevel.INFO,
            }
            
            return JudgmentResult(
                is_vulnerable=data.get("is_vulnerable", False),
                confidence_score=conf,
                confidence_level=conf_level,
                risk_level=risk_map.get(data.get("risk_level", "info"), RiskLevel.INFO),
                reasoning=data.get("reasoning", ""),
                evidence=data.get("evidence", []),
                mutation_suggestions=data.get("payload_suggestions", []),
                remediation_advice=data.get("remediation", ""),
                raw_llm_response=response,
            )
        except json.JSONDecodeError:
            return JudgmentResult.create_negative("Failed to parse LLM response")
    
    def to_finding(self, context: ScanContext, result: JudgmentResult) -> VulnFinding | None:
        """转换为 VulnFinding"""
        if not result.is_vulnerable:
            return None
        
        return VulnFinding(
            target=context.target,
            vuln_type=self.vuln_type,
            payload="",
            raw_request=context.raw_request,
            raw_response=context.raw_response,
            llm_reasoning=result.reasoning,
            confidence_score=result.confidence_score,
            confidence_level=result.confidence_level,
            risk_level=result.risk_level,
            evidence=result.evidence,
            remediation=result.remediation_advice,
            parameter=context.parameter,
            plugin_name=self.name,
        )


# =============================================================================
# 17 种漏洞类型的提示词插件
# =============================================================================

class SQLInjectionPlugin(PromptBasedPlugin):
    """SQL 注入检测"""
    name = "sql_injection"
    vuln_type = "sqli"
    description = "SQL 注入漏洞检测"
    prompt_file = "sql_injection"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# SQL 注入漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 参数: {ctx.parameter}
- 方法: {ctx.method}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

### 基线响应
```http
{ctx.baseline_response[:2000]}
```

### 响应时间
当前: {ctx.response_time_ms:.0f}ms | 基线: {ctx.baseline_time_ms:.0f}ms

## 分析任务
判断是否存在 SQL 注入漏洞。关注：
1. SQL 错误信息
2. 响应差异（布尔盲注）
3. 时间延迟（时间盲注）
4. UNION 注入特征

请以 JSON 格式输出。
"""


class XSSPlugin(PromptBasedPlugin):
    """跨站脚本检测"""
    name = "xss"
    vuln_type = "xss"
    description = "跨站脚本 (XSS) 漏洞检测"
    prompt_file = "xss"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# XSS 跨站脚本漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 参数: {ctx.parameter}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

## 分析任务
判断是否存在 XSS 漏洞。关注：
1. 用户输入是否被反射
2. 反射内容是否经过编码
3. 反射的上下文（HTML/属性/JS）
4. 是否可注入可执行脚本

请以 JSON 格式输出。
"""


class SSRFPlugin(PromptBasedPlugin):
    """服务端请求伪造检测"""
    name = "ssrf"
    vuln_type = "ssrf"
    description = "服务端请求伪造 (SSRF) 漏洞检测"
    prompt_file = "ssrf"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# SSRF 服务端请求伪造漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 参数: {ctx.parameter}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

### 响应时间
当前: {ctx.response_time_ms:.0f}ms | 基线: {ctx.baseline_time_ms:.0f}ms

## 分析任务
判断是否存在 SSRF 漏洞。关注：
1. 内部服务信息泄露
2. 内网地址访问 (127.0.0.1, 169.254.169.254)
3. 响应时间异常
4. 错误信息泄露网络拓扑

请以 JSON 格式输出。
"""


class IDORPlugin(PromptBasedPlugin):
    """不安全的直接对象引用检测"""
    name = "idor"
    vuln_type = "idor"
    description = "不安全的直接对象引用 (IDOR) 漏洞检测"
    prompt_file = "idor"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# IDOR 不安全的直接对象引用漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 参数: {ctx.parameter}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

## 分析任务
判断是否存在 IDOR 漏洞。关注：
1. 对象 ID 是否可预测/枚举
2. 是否能访问其他用户资源
3. 权限检查是否缺失
4. 返回敏感数据

请以 JSON 格式输出。
"""


class CSRFPlugin(PromptBasedPlugin):
    """跨站请求伪造检测"""
    name = "csrf"
    vuln_type = "csrf"
    description = "跨站请求伪造 (CSRF) 漏洞检测"
    prompt_file = "csrf"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# CSRF 跨站请求伪造漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 方法: {ctx.method}
- Content-Type: {ctx.content_type}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:3000]}
```

## 分析任务
判断是否存在 CSRF 漏洞。关注：
1. 是否缺少 CSRF Token
2. Token 是否可预测
3. Referer/Origin 检查
4. 状态修改操作

请以 JSON 格式输出。
"""


class XXEPlugin(PromptBasedPlugin):
    """XML 外部实体注入检测"""
    name = "xxe"
    vuln_type = "xxe"
    description = "XML 外部实体 (XXE) 注入漏洞检测"
    prompt_file = "xxe"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# XXE XML外部实体注入漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- Content-Type: {ctx.content_type}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

## 分析任务
判断是否存在 XXE 漏洞。关注：
1. XML 解析器配置
2. 外部实体是否被解析
3. 文件内容泄露
4. SSRF via XXE

请以 JSON 格式输出。
"""


class RCEPlugin(PromptBasedPlugin):
    """远程代码执行检测"""
    name = "rce"
    vuln_type = "rce"
    description = "远程代码执行 (RCE) 漏洞检测"
    prompt_file = "rce"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# RCE 远程代码执行漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 参数: {ctx.parameter}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

### 响应时间
当前: {ctx.response_time_ms:.0f}ms | 基线: {ctx.baseline_time_ms:.0f}ms

## 分析任务
判断是否存在 RCE 漏洞。关注：
1. 命令执行结果
2. 代码执行痕迹
3. 系统信息泄露
4. 时间延迟（sleep命令）

请以 JSON 格式输出。
"""


class AuthJWTPlugin(PromptBasedPlugin):
    """JWT 认证漏洞检测"""
    name = "authentication_jwt"
    vuln_type = "auth_jwt"
    description = "JWT 认证漏洞检测"
    prompt_file = "authentication_jwt"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# JWT 认证漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- Headers: {ctx.headers}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

## 分析任务
判断是否存在 JWT 认证漏洞。关注：
1. None algorithm 攻击
2. 弱密钥
3. Token 泄露
4. 权限提升

请以 JSON 格式输出。
"""


class BrokenAuthPlugin(PromptBasedPlugin):
    """越权访问检测"""
    name = "broken_function_level_authorization"
    vuln_type = "bfla"
    description = "功能级别越权访问漏洞检测"
    prompt_file = "broken_function_level_authorization"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# 功能级别越权访问漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 方法: {ctx.method}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

## 分析任务
判断是否存在越权访问漏洞。关注：
1. 管理员功能未授权访问
2. 角色权限绕过
3. 水平/垂直越权
4. 敏感操作无权限检查

请以 JSON 格式输出。
"""


class BusinessLogicPlugin(PromptBasedPlugin):
    """业务逻辑漏洞检测"""
    name = "business_logic"
    vuln_type = "business_logic"
    description = "业务逻辑漏洞检测"
    prompt_file = "business_logic"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# 业务逻辑漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 方法: {ctx.method}
- 参数: {ctx.parameter}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

## 分析任务
判断是否存在业务逻辑漏洞。关注：
1. 流程绕过
2. 价格篡改
3. 数量限制绕过
4. 状态不一致

请以 JSON 格式输出。
"""


class InfoDisclosurePlugin(PromptBasedPlugin):
    """信息泄露检测"""
    name = "information_disclosure"
    vuln_type = "info_disclosure"
    description = "信息泄露漏洞检测"
    prompt_file = "information_disclosure"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# 信息泄露漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}

### HTTP 响应
```http
{ctx.raw_response[:8000]}
```

## 分析任务
判断是否存在信息泄露。关注：
1. 敏感配置信息
2. 堆栈跟踪/调试信息
3. 内部路径泄露
4. 版本信息/技术栈

请以 JSON 格式输出。
"""


class FileUploadPlugin(PromptBasedPlugin):
    """不安全文件上传检测"""
    name = "insecure_file_uploads"
    vuln_type = "file_upload"
    description = "不安全的文件上传漏洞检测"
    prompt_file = "insecure_file_uploads"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# 不安全文件上传漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- Content-Type: {ctx.content_type}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

## 分析任务
判断是否存在文件上传漏洞。关注：
1. 文件类型验证
2. 文件名过滤
3. 上传路径可控
4. 恶意文件执行

请以 JSON 格式输出。
"""


class MassAssignmentPlugin(PromptBasedPlugin):
    """批量赋值漏洞检测"""
    name = "mass_assignment"
    vuln_type = "mass_assignment"
    description = "批量赋值漏洞检测"
    prompt_file = "mass_assignment"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# 批量赋值漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 方法: {ctx.method}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

## 分析任务
判断是否存在批量赋值漏洞。关注：
1. 隐藏字段是否可赋值（role, isAdmin）
2. 对象属性过度绑定
3. 敏感字段修改
4. 权限提升

请以 JSON 格式输出。
"""


class OpenRedirectPlugin(PromptBasedPlugin):
    """开放重定向检测"""
    name = "open_redirect"
    vuln_type = "open_redirect"
    description = "开放重定向漏洞检测"
    prompt_file = "open_redirect"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# 开放重定向漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 参数: {ctx.parameter}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:3000]}
```

## 分析任务
判断是否存在开放重定向漏洞。关注：
1. Location header 可控
2. JS/Meta 重定向
3. URL 验证绕过
4. 白名单绕过

请以 JSON 格式输出。
"""


class PathTraversalPlugin(PromptBasedPlugin):
    """路径遍历/文件包含检测"""
    name = "path_traversal_lfi_rfi"
    vuln_type = "path_traversal"
    description = "路径遍历/本地文件包含 (LFI/RFI) 漏洞检测"
    prompt_file = "path_traversal_lfi_rfi"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# 路径遍历/文件包含漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 参数: {ctx.parameter}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

## 分析任务
判断是否存在路径遍历或文件包含漏洞。关注：
1. 文件内容泄露 (/etc/passwd)
2. 源代码泄露
3. 目录遍历 (../)
4. 远程文件包含

请以 JSON 格式输出。
"""


class RaceConditionPlugin(PromptBasedPlugin):
    """竞态条件检测"""
    name = "race_conditions"
    vuln_type = "race_condition"
    description = "竞态条件漏洞检测"
    prompt_file = "race_conditions"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# 竞态条件漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}
- 方法: {ctx.method}

### HTTP 请求
```http
{ctx.raw_request}
```

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

### 响应时间
当前: {ctx.response_time_ms:.0f}ms

## 分析任务
判断是否可能存在竞态条件漏洞。关注：
1. 非原子操作
2. TOCTOU 问题
3. 余额/库存检查
4. 并发请求异常

请以 JSON 格式输出。
"""


class SubdomainTakeoverPlugin(PromptBasedPlugin):
    """子域名接管检测"""
    name = "subdomain_takeover"
    vuln_type = "subdomain_takeover"
    description = "子域名接管漏洞检测"
    prompt_file = "subdomain_takeover"
    
    def build_prompt(self, ctx: ScanContext) -> str:
        return f"""# 子域名接管漏洞分析

## 专业知识
{self.get_vuln_knowledge()}

## 待分析内容
- URL: {ctx.target}

### HTTP 响应
```http
{ctx.raw_response[:5000]}
```

## 分析任务
判断是否存在子域名接管风险。关注：
1. 悬空 DNS 记录
2. 云服务未配置
3. GitHub Pages / Heroku / S3 特征
4. 可注册接管

请以 JSON 格式输出。
"""


# =============================================================================
# 插件注册
# =============================================================================

PROMPT_PLUGINS: dict[str, PromptBasedPlugin] = {
    # 注入类
    "sqli": SQLInjectionPlugin(),
    "sql_injection": SQLInjectionPlugin(),
    "xss": XSSPlugin(),
    "xxe": XXEPlugin(),
    "rce": RCEPlugin(),
    
    # 认证授权类
    "idor": IDORPlugin(),
    "csrf": CSRFPlugin(),
    "auth_jwt": AuthJWTPlugin(),
    "authentication_jwt": AuthJWTPlugin(),
    "bfla": BrokenAuthPlugin(),
    "broken_function_level_authorization": BrokenAuthPlugin(),
    
    # 配置/信息类
    "ssrf": SSRFPlugin(),
    "info_disclosure": InfoDisclosurePlugin(),
    "information_disclosure": InfoDisclosurePlugin(),
    "open_redirect": OpenRedirectPlugin(),
    "path_traversal": PathTraversalPlugin(),
    "path_traversal_lfi_rfi": PathTraversalPlugin(),
    "lfi": PathTraversalPlugin(),
    "rfi": PathTraversalPlugin(),
    
    # 业务逻辑类
    "business_logic": BusinessLogicPlugin(),
    "race_condition": RaceConditionPlugin(),
    "race_conditions": RaceConditionPlugin(),
    "mass_assignment": MassAssignmentPlugin(),
    
    # 文件上传类
    "file_upload": FileUploadPlugin(),
    "insecure_file_uploads": FileUploadPlugin(),
    
    # 基础设施类
    "subdomain_takeover": SubdomainTakeoverPlugin(),
}


def get_prompt_plugin(vuln_type: str) -> PromptBasedPlugin | None:
    """获取指定漏洞类型的提示词插件"""
    return PROMPT_PLUGINS.get(vuln_type.lower())


def list_prompt_plugins() -> list[str]:
    """列出所有主要漏洞类型"""
    return [
        "sqli",
        "xss", 
        "xxe",
        "rce",
        "idor",
        "csrf",
        "auth_jwt",
        "bfla",
        "ssrf",
        "info_disclosure",
        "open_redirect",
        "path_traversal",
        "business_logic",
        "race_condition",
        "mass_assignment",
        "file_upload",
        "subdomain_takeover",
    ]


def get_all_plugins() -> list[PromptBasedPlugin]:
    """获取所有唯一的插件实例"""
    seen = set()
    plugins = []
    for plugin in PROMPT_PLUGINS.values():
        if plugin.name not in seen:
            seen.add(plugin.name)
            plugins.append(plugin)
    return plugins
