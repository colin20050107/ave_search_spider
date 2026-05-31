"""
ave.ai 搜索服务 - FastAPI 后端
=============================
提供 HTTP API 接口, 外部可通过请求此接口获取 ave.ai 搜索结果

启动: uvicorn ave_search_server:app --host 127.0.0.1 --port 8000
接口: POST /api/search
浏览器请求可以拿到数据:http://127.0.0.1:8000/api/search?keyword=BTC
"""

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import asyncio
from typing import Optional
import time

from request_token import (
    get_auth_token,
    search_token,
    parse_search_result,
)

app = FastAPI(
    title="ave.ai Search API",
    description="ave.ai 搜索接口封装, 自动处理 request_id 加密和 x-auth token 获取",
    version="1.0.0",
)

# 缓存 token (避免频繁请求)
_token_cache = {"token": "", "expires_at": 0}


async def get_cached_token() -> str:
    """获取缓存的 token, 如果过期则重新获取"""
    now = time.time()
    if _token_cache["token"] and _token_cache["expires_at"] > now:
        return _token_cache["token"]

    # Token 有效期约 7 天, 但我们每 6 天刷新一次
    token = await asyncio.to_thread(get_auth_token, "web")
    _token_cache["token"] = token
    _token_cache["expires_at"] = now + 6 * 24 * 3600
    return token


@app.get("/")
async def root():
    return {"service": "ave.ai Search API", "endpoint": "/api/search"}


@app.get("/api/search")
@app.post("/api/search")
async def api_search(
    keyword: str = Query(..., description="搜索关键词, 如 BTC, ETH, 合约地址"),
    chain: str = Query("", description="链过滤, 如 bsc, solana, tron, ethereum, 空=所有链"),
):
    """
    搜索 token/contract/wallet

    示例:
      GET /api/search?keyword=BTC
      GET /api/search?keyword=0x5bb2a95f3713e3e35332c98a90e78a286991e060&chain=depass
    """
    try:
        x_auth = await get_cached_token()
        result = await asyncio.to_thread(search_token, keyword, chain, x_auth)

        if result.get("status") != 1:
            return JSONResponse(
                status_code=502,
                content={"error": "upstream error", "detail": result.get("msg", "unknown")},
            )

        tokens = parse_search_result(result)

        return {
            "success": True,
            "keyword": keyword,
            "chain": chain,
            "total": len(tokens),
            "tokens": tokens,
        }
    except Exception as e:
        # Token 可能过期, 清除缓存并重试一次
        _token_cache["token"] = ""
        try:
            x_auth = await get_cached_token()
            result = await asyncio.to_thread(search_token, keyword, chain, x_auth)
            tokens = parse_search_result(result)
            return {
                "success": True,
                "keyword": keyword,
                "chain": chain,
                "total": len(tokens),
                "tokens": tokens,
            }
        except Exception as e2:
            return JSONResponse(
                status_code=500,
                content={"success": False, "error": str(e2)},
            )


@app.post("/api/token")
async def api_get_token():
    """手动刷新 x-auth token"""
    try:
        _token_cache["token"] = ""
        token = await get_cached_token()
        return {"success": True, "x_auth": token}
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)},
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
