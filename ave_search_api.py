"""
ave.ai 搜索接口还原
===================
搜索接口 URL: https://alrse3.com/v2api/token/v1/query
请求方式: GET
查询参数:
  - keyword: 搜索关键词 (如 "BTC")
  - self_address: 用户钱包地址 (可为空)
  - chain: 链过滤 (可为空，表示所有链)

所需请求头:
  - ave-platform: web
  - lang: en
  - x-auth: localStorage.getItem("ave_token") — 从浏览器本地存储获取
  - origin: https://ave.ai
  - referer: https://ave.ai/

x-auth 获取方式 (任选其一):
  1. 浏览器 DevTools > Application > Local Storage > ave_token
  2. 浏览器 DevTools > Network > 任意 alrse3.com 请求 > Request Headers > x-auth
  3. 在控制台执行: localStorage.getItem("ave_token")
"""

import requests
import json

# ============================================================
# 搜索接口
# ============================================================
# SEARCH_URL = "https://alrse3.com/v2api/token/v1/query"
SEARCH_URL = "https://api.agacve.com/v2api/token/v1/query"

# 公共请求头
# HEADERS = {
#     "accept": "*/*",
#     "accept-language": "zh-CN,zh;q=0.9",
#     "ave-platform": "web",
#     "content-type": "application/json",
#     "lang": "en",
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
    'lang': 'en',
    'origin': 'https://ave.ai',
    'pragma': 'no-cache',
    'priority': 'u=1, i',
    'referer': 'https://ave.ai/',
    'sec-ch-ua': '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
    # 'x-auth': '1609b5596c160d9bdfbf37fdbd7058ad1780198093616542713',
}


def search_token(keyword: str, chain: str = "", x_auth: str = "") -> dict:
    """
    搜索 token/contract/wallet

    对应页面 class="text-12px ml-4px text-[--third-text]"
    文本为 "Search token/contract/wallet" 的搜索框

    Args:
        keyword: 搜索关键词，如 "BTC", "ETH", 合约地址等
        chain: 链名称过滤，如 "bsc", "solana", "tron", "ethereum" 等，空字符串=所有链
        x_auth: x-auth token (首次可尝试不带)

    Returns:
        API 响应 JSON
    """
    params = {
        "keyword": keyword,
        "self_address": "",
        "chain": chain,
    }

    headers = HEADERS.copy()
    if x_auth:
        headers["x-auth"] = x_auth

    resp = requests.get(SEARCH_URL, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def parse_search_result(data: dict) -> list[dict]:
    """
    解析搜索结果，提取关键交易数据字段

    Returns:
        token 列表，每项包含:
        - token: 合约地址
        - chain: 链
        - symbol: 代币符号
        - name: 代币名称
        - price_usd: 当前价格 (USD)
        - price_change_24h: 24h 价格变化百分比
        - volume_24h: 24h 成交量 (USD)
        - tx_count_24h: 24h 交易笔数
        - holders: 持有者数量
        - mc_usd: 市值 (估算: price * total_supply)
        - pool_size: 流动性池大小
        - launchpad: 发射平台
    """
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
    x_auth = "1609b5596c160d9bdfbf37fdbd7058ad1780198093616542713"

    print(f"搜索关键词: {keyword}")
    print(f"请求 URL: {SEARCH_URL}?keyword={keyword}&self_address=&chain=")
    print("-" * 60)

    try:
        result = search_token(keyword=keyword,x_auth=x_auth)
        tokens = parse_search_result(result)

        print(f"状态: {result.get('msg')}")
        print(f"结果数: {len(tokens)}")
        print()

        for i, t in enumerate(tokens, 1):
            print(f"--- #{i} ---")
            print(f"  名称: {t['name']} ({t['symbol']})")
            print(f"  合约: {t['token']}")
            print(f"  链:   {t['chain']}")
            print(f"  价格: ${t['price_usd']}")
            print(f"  24h涨跌: {t['price_change_24h']}%")
            print(f"  24h成交量: ${t['volume_24h']:,.2f}")
            print(f"  24h交易数: {t['tx_count_24h']}")
            print(f"  持有者: {t['holders']}")
            print(f"  发射平台: {t['launchpad']}")
            print()

        # 输出完整 JSON 供调试
        # print("=" * 60)
        # print("完整 JSON 响应 (保存到文件):")
        # with open("search_result.json", "w", encoding="utf-8") as f:
        #     json.dump(result, f, ensure_ascii=False, indent=2)
        # print("已保存到 search_result.json")

    except Exception as e:
        print(f"请求失败: {e}")
        print()
        print("=" * 60)
        print("注意: 如果请求被拦截，可能需要以下任一项:")
        print("1. x-auth token (从浏览器 DevTools > Network > 请求头中复制)")
        print("2. 通过 Cloudflare 验证 (建议用浏览器先访问 ave.ai 获取 cookie)")
        print("3. 代理 IP (海外环境)")


if __name__ == "__main__":
    main()
