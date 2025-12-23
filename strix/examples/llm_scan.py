#!/usr/bin/env python3
"""Example: LLM-driven vulnerability scanning.

Demonstrates the new architecture:
- Controller handles HTTP requests and orchestration
- Plugins generate payloads (no judgment logic)
- LLM Brain makes vulnerability decisions

Usage:
    python -m strix.examples.llm_scan --target https://example.com --api-key YOUR_KEY
"""

import argparse
import asyncio
import logging
import os

from strix.brain.openai_judge import OpenAIJudge
from strix.core.llm_controller import ScanController
from strix.models.request import ScanTarget
from strix.plugins.vulns.sqli import SQLiPlugin


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main():
    parser = argparse.ArgumentParser(description="LLM-driven vulnerability scanner")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--parameter", default="id", help="Parameter to test")
    parser.add_argument("--model", default="gpt-4o-mini", help="LLM model to use")
    parser.add_argument("--api-key", help="OpenAI API key (or set OPENAI_API_KEY)")
    args = parser.parse_args()
    
    # Initialize LLM Judge
    api_key = args.api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.error("Please provide --api-key or set OPENAI_API_KEY")
        return
    
    llm_judge = OpenAIJudge(model=args.model, api_key=api_key)
    
    # Initialize plugins
    plugins = [
        SQLiPlugin(),
    ]
    
    # Create target
    target = ScanTarget(
        url=args.target,
        method="GET",
        parameters=[args.parameter],
    )
    
    print(f"\n{'='*60}")
    print(f"LLM-Driven Vulnerability Scanner")
    print(f"{'='*60}")
    print(f"Target: {target.url}")
    print(f"Parameter: {args.parameter}")
    print(f"Model: {args.model}")
    print(f"Plugins: {[p.name for p in plugins]}")
    print(f"{'='*60}\n")
    
    # Run scan
    findings = []
    async with ScanController(llm_judge=llm_judge, max_concurrent=5) as controller:
        async for finding in controller.scan(target, plugins):
            findings.append(finding)
            print(f"\n[+] VULNERABILITY FOUND!")
            print(f"    Type: {finding.vuln_type}")
            print(f"    Risk: {finding.risk_level.value}")
            print(f"    Confidence: {finding.confidence_score:.0%}")
            print(f"    Payload: {finding.payload[:50]}...")
            print(f"    Reasoning: {finding.llm_reasoning[:100]}...")
    
    # Print summary
    stats = controller.get_stats()
    print(f"\n{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Requests sent: {stats['requests_sent']}")
    print(f"Payloads tested: {stats['payloads_tested']}")
    print(f"LLM calls: {stats['llm_calls']}")
    print(f"Findings confirmed: {stats['findings_confirmed']}")
    print(f"{'='*60}\n")
    
    if findings:
        print("\n=== FINDINGS DETAIL ===\n")
        for i, finding in enumerate(findings, 1):
            print(f"--- Finding {i} ---")
            print(finding)
            print()


if __name__ == "__main__":
    asyncio.run(main())
