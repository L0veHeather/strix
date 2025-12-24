# tests/mock_target.py
"""
模拟靶场服务器 - 用于测试 Strix 漏洞检测能力

提供以下漏洞端点:
1. /vuln/sqli - Time-based SQL 注入
2. /vuln/xss - Reflected XSS

启动:
    python tests/mock_target.py

靶场地址: http://localhost:9000
"""

import uvicorn
import asyncio
from fastapi import FastAPI, Request, Response
import time

app = FastAPI(
    title="Strix Mock Target",
    description="模拟靶场，用于测试 Strix AI 漏洞扫描器",
    version="1.0.0"
)


# 1. 模拟 Time-based SQL 注入
# 漏洞点：如果参数 id 包含 'sleep'，则强制延迟，模拟数据库行为
@app.get("/vuln/sqli")
async def sqli_time(id: str = ""):
    print(f"[Server] 收到 SQLi 测试请求: id={id}")
    
    # 模拟简单的 WAF：拦截 'UNION SELECT'
    if "union select" in id.lower():
        return Response(content="WAF Blocked", status_code=403)

    # 模拟漏洞：只有当 payload 逻辑正确时才延迟
    if "' and sleep(" in id.lower() or "' and benchmark(" in id.lower():
        # 提取延迟时间 (简化逻辑)
        print(f"[Server] 触发延迟逻辑！")
        await asyncio.sleep(3) 
        return {"id": id, "name": "user_data"}
    
    return {"id": id, "name": "user_data"}


# 2. 模拟 Reflected XSS
# 漏洞点：query 参数原样输出，没有任何过滤
@app.get("/vuln/xss")
def xss_reflected(query: str = ""):
    print(f"[Server] 收到 XSS 测试请求: query={query}")
    # 这是一个极其明显的漏洞
    html_content = f"<html><body><h1>Search Result: {query}</h1></body></html>"
    return Response(content=html_content, media_type="text/html")


# 3. 模拟 Error-based SQL 注入
@app.get("/vuln/sqli-error")
def sqli_error(id: str = ""):
    print(f"[Server] 收到 Error SQLi 请求: id={id}")
    
    # 模拟 SQL 语法错误
    if "'" in id:
        error_msg = f"""
        <html>
        <body>
        <h1>Database Error</h1>
        <pre>
        Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/html/search.php on line 42
        You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{id}' at line 1
        </pre>
        </body>
        </html>
        """
        return Response(content=error_msg, media_type="text/html", status_code=500)
    
    return {"id": id, "data": "normal_response"}


# 4. 健康检查
@app.get("/health")
def health():
    return {"status": "ok", "message": "Mock target is running"}


# 5. 首页
@app.get("/")
def index():
    return {
        "name": "Strix Mock Target",
        "endpoints": [
            {"path": "/vuln/sqli?id=<payload>", "vuln": "Time-based SQLi"},
            {"path": "/vuln/sqli-error?id=<payload>", "vuln": "Error-based SQLi"},
            {"path": "/vuln/xss?query=<payload>", "vuln": "Reflected XSS"},
            {"path": "/health", "vuln": "None (health check)"},
        ]
    }


if __name__ == "__main__":
    print("=" * 50)
    print("🎯 启动模拟靶场: http://localhost:9000")
    print("=" * 50)
    print("\n可用端点:")
    print("  - GET /vuln/sqli?id=<payload>       (Time-based SQLi)")
    print("  - GET /vuln/sqli-error?id=<payload> (Error-based SQLi)")
    print("  - GET /vuln/xss?query=<payload>     (Reflected XSS)")
    print("  - GET /health                       (Health check)")
    print("\n示例测试:")
    print("  curl 'http://localhost:9000/vuln/sqli?id=1'")
    print("  curl 'http://localhost:9000/vuln/xss?query=<script>alert(1)</script>'")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=9000)
