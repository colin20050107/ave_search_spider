"""
ave.ai request_id 生成 & 搜索接口
===============================
完整流程:
  1. 获取服务器时间 (GET /v1api/v2/settings/serverTime)
  2. 生成随机 visitor_id (32位hex, 模拟 FingerprintJS 指纹)
  3. 构建明文: visitor_id + "$" + platform + "$1.0.0$r1r$" + pow_value
  4. RSA-OAEP-SHA-256 公钥加密 -> Base64 -> request_id
  5. POST /v1api/v1/captcha/requestToken {request_id} -> 获取 x-auth token
  6. GET /v2api/token/v1/query?keyword=... 携带 x-auth -> 搜索结果

算法特点:
  - 加密: RSA-OAEP with SHA-256, 2048-bit key
  - 指纹: FingerprintJS (浏览器指纹), 可随机32位hex替代
  - 时间戳: server_time + 本地时间戳后3位
  - 固定盐值: "$1.0.0$r1r$"
  - 平台: web (桌面) / h5 (移动端)
"""

import requests
import subprocess
import time
import random
import os
import json

# ============================================================
# 配置
# ============================================================
BASE_URL = "https://api.agacve.com"
SERVER_TIME_URL = f"{BASE_URL}/v1api/v2/settings/serverTime"
CAPTCHA_URL = f"{BASE_URL}/v1api/v1/captcha/requestToken"
SEARCH_URL = f"{BASE_URL}/v2api/token/v1/query"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENCRYPT_SCRIPT = os.path.join(SCRIPT_DIR, "encrypt_request_id.js")

# HEADERS = {
#     "accept": "*/*",
#     "ave-platform": "web",
#     "content-type": "application/json",
#     "origin": "https://ave.ai",
#     "referer": "https://ave.ai/",
#     "user-agent": (
#         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
#         "AppleWebKit/537.36 (KHTML, like Gecko) "
#         "Chrome/148.0.0.0 Safari/537.36"
#     ),
# }

HEADERS = {
    'accept': '*/*',
    'accept-language': 'zh-CN,zh;q=0.9,nso;q=0.8',
    'ave-platform': 'web',
    'cache-control': 'no-cache',
    'content-type': 'application/json',
    'origin': 'https://ave.ai',
    'pragma': 'no-cache',
    'priority': 'u=1, i',
    'referer': 'https://ave.ai/',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
}


def generate_visitor_id() -> str:
    """生成随机 visitor ID (模拟 FingerprintJS 的 32 位 hex visitorId)"""
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def get_server_time() -> int:
    """获取服务器时间戳 (秒)"""
    resp = requests.get(SERVER_TIME_URL, headers=HEADERS, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != 1:
        raise Exception(f"serverTime API error: {data}")
    return data["data"]["server_time"]


def build_pow_value(server_time: int) -> str:
    """构建 PoW 值: server_time + 本地时间戳后3位"""
    local_ts = str(int(time.time() * 1000))
    return str(server_time) + local_ts[-3:]


def generate_request_id(visitor_id: str, platform: str, pow_value: str) -> str:
    """调用 Node.js 脚本进行 RSA-OAEP 加密, 生成 request_id"""
    result = subprocess.run(
        ["node", ENCRYPT_SCRIPT, visitor_id, platform, pow_value],
        capture_output=True,
        text=True,
        timeout=15,
        cwd=SCRIPT_DIR,
    )
    if result.returncode != 0:
        raise Exception(f"Node.js error: {result.stderr}")
    return result.stdout.strip()


def get_captcha_token(request_id: str) -> str:
    """用 request_id 换取 x-auth token"""
    resp = requests.post(
        CAPTCHA_URL,
        headers=HEADERS,
        json={"request_id": request_id},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != 1:
        raise Exception(f"captcha API error: {data}")
    return data["data"]["id"]


def get_auth_token(platform: str = "web") -> str:
    """
    完整 token 获取流程: server_time -> encrypt -> captcha -> token
    """
    server_time = get_server_time()
    visitor_id = generate_visitor_id()
    pow_value = build_pow_value(server_time)
    request_id = generate_request_id(visitor_id, platform, pow_value)
    print('获取request_id: ',request_id)
    token = get_captcha_token(request_id)
    return token


def search_token(keyword: str, chain: str = "", x_auth: str = "") -> dict:
    """
    搜索 token/contract/wallet
    """
    params = {
        "keyword": keyword,
        "self_address": "",
        "chain": chain,
    }

    search_headers = HEADERS.copy()
    search_headers["lang"] = "en"
    if x_auth:
        search_headers["x-auth"] = x_auth

    resp = requests.get(SEARCH_URL, params=params, headers=search_headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def parse_search_result(data: dict) -> list[dict]:
    """解析搜索结果"""
    tokens = []
    token_list = data.get("data", {}).get("token_list", [])

    for t in token_list:
        tokens.append({
            "token": t.get("token", ""),
            "chain": t.get("chain", ""),
            "symbol": t.get("symbol", ""),
            "name": t.get("name", ""),
            "price_usd": t.get("current_price_usd"),
            "price_change_24h": t.get("t_price_change_24h"),
            "volume_24h": t.get("tx_volume_u_24h"),
            "tx_count_24h": t.get("tx_count_24h"),
            "holders": t.get("holders"),
            "pool_size": t.get("pool_size"),
            "launchpad": t.get("launchpad", ""),
        })

    return tokens


def main():
    keyword = "BTC"

    print(f"搜索关键词: {keyword}")
    print("-" * 60)

    try:
        # 自动获取 token
        x_auth = get_auth_token()
        print("获取 x-auth token...")
        print(f"Token: {x_auth}")

        # 搜索
        print(f"\n搜索 {keyword}...")
        result = search_token(keyword=keyword, x_auth=x_auth)
        tokens = parse_search_result(result)
        # print(result)

        print(f"状态: {result.get('msg')}")
        print(f"结果数: {len(tokens)}")
        print()

        # for i, t in enumerate(tokens, 1):
        #     print(f"--- #{i} ---")
        #     print(f"  名称: {t['name']} ({t['symbol']})")
        #     print(f"  合约: {t['token']}")
        #     print(f"  链:   {t['chain']}")
        #     print(f"  价格: ${t['price_usd']}")
        #     print(f"  24h涨跌: {t['price_change_24h']}%")
        #     print()

    except Exception as e:
        print(f"请求失败: {e}")


if __name__ == "__main__":
    main()
