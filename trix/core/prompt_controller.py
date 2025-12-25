"""Prompt-Based Scan Controller.

设计理念：
- 代码控制流程（确定性）
- LLM 判断漏洞（智能判断）
- 插件 = LLM 提示词模板

流程：
1. [代码] 发送 HTTP 请求
2. [代码] 调用插件构建提示词
3. [LLM] 分析响应判断漏洞
4. [代码] 收集结果
"""

from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator, Any

import httpx
import litellm

from trix.models.finding import VulnFinding
from trix.models.request import ScanTarget
from trix.plugins.prompt_plugins import (
    PromptBasedPlugin,
    ScanContext,
    get_prompt_plugin,
    list_prompt_plugins,
)

logger = logging.getLogger(__name__)


class PromptScanController:
    """基于提示词的扫描控制器.
    
    职责分离：
    - 代码控制: 任务调度、HTTP请求、并发、结果收集
    - LLM判断: 漏洞分析、误报识别、payload建议
    
    Usage:
        async with PromptScanController(model="gpt-4o-mini") as ctrl:
            async for finding in ctrl.scan(target, ["sqli", "xss"]):
                print(finding)
    """
    
    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        max_concurrent: int = 5,
        timeout: float = 30.0,
    ):
        self.model = model
        self.api_key = api_key
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        
        self._client: httpx.AsyncClient | None = None
        self._semaphore: asyncio.Semaphore | None = None
        
        # 统计
        self.stats = {
            "requests": 0,
            "llm_calls": 0,
            "findings": 0,
        }
    
    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
        )
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        return self
    
    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()
    
    async def scan(
        self,
        target: ScanTarget,
        vuln_types: list[str] | None = None,
    ) -> AsyncIterator[VulnFinding]:
        """扫描目标.
        
        流程（代码控制）：
        1. 获取基线响应
        2. 对每个漏洞类型，使用对应的提示词插件
        3. LLM 分析响应
        4. 返回确认的漏洞
        
        Args:
            target: 扫描目标
            vuln_types: 要检测的漏洞类型列表
        """
        # 默认检测所有类型
        vuln_types = vuln_types or list_prompt_plugins()
        
        # 1. [代码] 获取基线
        baseline = await self._get_baseline(target)
        
        # 2. [代码] 对每个参数和漏洞类型进行测试
        for param in target.parameters or ["id"]:
            for vuln_type in vuln_types:
                plugin = get_prompt_plugin(vuln_type)
                if not plugin:
                    logger.warning(f"Unknown vuln type: {vuln_type}")
                    continue
                
                # 3. [代码] 发送测试请求
                request_str, response = await self._send_request(target, param)
                
                # 4. [代码] 构建上下文
                context = ScanContext(
                    target=target.url,
                    parameter=param,
                    method=target.method,
                    raw_request=request_str,
                    raw_response=response.text if not response.error else str(response.error),
                    baseline_response=baseline.text if baseline else "",
                    response_time_ms=response.response_time_ms,
                    baseline_time_ms=baseline.response_time_ms if baseline else 0,
                )
                
                # 5. [LLM] 分析漏洞
                finding = await self._analyze_with_llm(plugin, context)
                
                if finding:
                    self.stats["findings"] += 1
                    yield finding
    
    async def _get_baseline(self, target: ScanTarget) -> Any:
        """[代码控制] 获取基线响应"""
        try:
            resp = await self._client.request(
                target.method,
                target.url,
                headers=target.headers,
            )
            return type("Response", (), {
                "text": resp.text[:5000],
                "response_time_ms": resp.elapsed.total_seconds() * 1000,
            })()
        except Exception as e:
            logger.error(f"Baseline failed: {e}")
            return None
    
    async def _send_request(
        self,
        target: ScanTarget,
        param: str,
    ) -> tuple[str, Any]:
        """[代码控制] 发送 HTTP 请求"""
        async with self._semaphore:
            self.stats["requests"] += 1
            
            # 构建请求
            url = target.url
            if "?" in url:
                url = f"{url}&{param}=test"
            else:
                url = f"{url}?{param}=test"
            
            request_str = f"{target.method} {url} HTTP/1.1\nHost: {target.url.split('/')[2]}"
            
            try:
                resp = await self._client.get(url, headers=target.headers)
                response = type("Response", (), {
                    "text": resp.text[:5000],
                    "response_time_ms": resp.elapsed.total_seconds() * 1000,
                    "error": None,
                })()
            except Exception as e:
                response = type("Response", (), {
                    "text": "",
                    "response_time_ms": 0,
                    "error": str(e),
                })()
            
            return request_str, response
    
    async def _analyze_with_llm(
        self,
        plugin: PromptBasedPlugin,
        context: ScanContext,
    ) -> VulnFinding | None:
        """[LLM判断] 使用插件提示词分析漏洞"""
        self.stats["llm_calls"] += 1
        
        # 构建提示词
        system_prompt = plugin.get_system_prompt()
        user_prompt = plugin.build_prompt(context)
        
        try:
            # 调用 LLM
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=1500,
                response_format={"type": "json_object"},
                api_key=self.api_key,
            )
            
            # 解析响应
            content = response.choices[0].message.content
            result = plugin.parse_llm_response(content)
            
            # 转换为 Finding
            return plugin.to_finding(context, result)
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return None


# =============================================================================
# 便捷函数
# =============================================================================

async def quick_scan(
    url: str,
    vuln_types: list[str] | None = None,
    model: str = "gpt-4o-mini",
) -> list[VulnFinding]:
    """快速扫描 - 一行代码调用.
    
    Example:
        findings = await quick_scan("https://example.com/api?id=1", ["sqli", "xss"])
    """
    target = ScanTarget(url=url, parameters=["id"])
    findings = []
    
    async with PromptScanController(model=model) as ctrl:
        async for finding in ctrl.scan(target, vuln_types):
            findings.append(finding)
    
    return findings
