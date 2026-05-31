# ave.ai 搜索接口逆向分析报告

## 1. 概述

ave.ai 是一个加密货币数据平台。其搜索接口 (`/v2api/token/v1/query`) 需要 `x-auth` token，该 token 通过 `/v1api/v1/captcha/requestToken` 获取，而这个接口需要 RSA-OAEP 加密的 `request_id` 参数。

## 2. 完整请求流程

```
┌──────────────────────────────────────────────────────────────┐
│                    1. 获取服务器时间                           │
│  GET /v1api/v2/settings/serverTime                           │
│  响应: {"data":{"server_time":1780205478}}                   │
├──────────────────────────────────────────────────────────────┤
│                    2. 构建加密明文                             │
│  visitorId = FingerprintJS 32位hex指纹 (可随机)              │
│  platform  = "web" (桌面) 或 "h5" (移动端)                   │
│  powValue  = server_time + 本地时间戳后3位                    │
│  plaintext = "{visitorId}${platform}$1.0.0$r1r${powValue}"  │
├──────────────────────────────────────────────────────────────┤
│                    3. RSA-OAEP 加密                           │
│  算法: RSA-OAEP, SHA-256, 2048-bit                          │
│  公钥: DER/SPKI 格式, 硬编码在 vemachine.js                  │
│  输出: Base64 (344 字符)                                     │
├──────────────────────────────────────────────────────────────┤
│                    4. 获取 x-auth token                       │
│  POST /v1api/v1/captcha/requestToken                         │
│  Body: {"request_id":"<RSA密文>"}                             │
│  响应: {"data":{"id":"<token>","image":""}}                  │
├──────────────────────────────────────────────────────────────┤
│                    5. 搜索请求                                │
│  GET /v2api/token/v1/query?keyword=BTC&self_address=&chain=  │
│  Headers: x-auth: <token>, lang: en, ave-platform: web       │
│  响应: {"data":{"token_list":[...]}}                         │
└──────────────────────────────────────────────────────────────┘
```

## 3. 混淆代码分析

### 3.1 源文件

| 文件 | 大小 | 说明 |
|------|------|------|
| `vemachine.js` | 212KB | 核心模块，包含加密和 token 获取 |
| `Bv7wBlte.js` | 9.8MB | Nuxt 主应用包 |

### 3.2 混淆层级

**第一层 - 外层 IIFE 自保护**
```javascript
((function (_0x5a4ace, _0xcc7489) {
  var _0x5292c9 = a0_0x3f75,
    _0x1a0aee = _0x5a4ace();
  while (!![]) {
    try {
      var _0xc33f86 = parseInt(_0x5292c9(0x95)) / 0x1 + ...;
      if (_0xc33f86 === _0xcc7489) break;
      else _0x1a0aee["push"](_0x1a0aee["shift"]());
    } catch (_0x58f78e) {
      _0x1a0aee["push"](_0x1a0aee["shift"]());
    }
  }
})(a0_0x536d, 0xc53e7)
```

**第二层 - UMD 模块包装**
```javascript
(function (_0x333f59, _0x5e6b4d) {
  typeof exports == "object" && typeof module < "u"
    ? _0x5e6b4d(exports)           // CommonJS
    : typeof define == "function" && define.amd
      ? define(["exports"], _0x5e6b4d)  // AMD
      : _0x5e6b4d((_0x333f59.vemachine = {}));  // 全局变量
})(this, function (_0x16c15a) { ... })
```

**第三层 - 双层字符串表**

外层 `a0_0x536d` 数组 (2000+ 条目):
```javascript
function a0_0x536d() {
  var _0x419788 = [
    "WXYxz", "standard", "#divAgahi", ...,  // 2000+ 个字符串
    "https://api.agacve.com",
    "/v1api/v1/captcha/requestToken",
    ...
  ];
  return _0x419788;
}
function a0_0x3f75(_0x2dc0e4, _0x190d63) {
  var _0x536dd6 = a0_0x536d();
  return _0x536dd6[_0x2dc0e4 - 0x8c];  // 索引偏移 0x8C
}
```

内层 `_0x31523b` 数组 (40 条目):
```javascript
function _0x31523b() {
  const _0x4801eb = [
    "load", "json", "domain", "userAgent", "subtle",
    "data", "parse", "stringify", "encryptMessage", "status", ...
  ];
  return _0x4801eb;
}
function _0x4a2dc4(_0x5a39b6) {
  return _0x1fb1ab[_0x5a39b6 - 0x177];  // 索引偏移 0x177
}
```

**第四层 - 控制流平坦化**

使用 Generator 状态机模式:
```javascript
function _0x2469ca(_0x408239, _0xe6c402, _0x473d73, _0x25725e) {
  return new Promise(function (_0x23ed25, _0x3cb83c) {
    function _0x411c65(_0x3e3460) {
      try { _0x4eac44(_0x25725e.next(_0x3e3460)); }
      catch (_0x5f35a1) { _0x3cb83c(_0x5f35a1); }
    }
    function _0x5da700(_0x24128e) {
      try { _0x4eac44(_0x25725e.throw(_0x24128e)); }
      catch (_0x53fef1) { _0x3cb83c(_0x53fef1); }
    }
    function _0x4eac44(_0xb0ec69) {
      _0xb0ec69.done ? _0x23ed25(_0xb0ec69.value)
        : Promise.resolve(_0xb0ec69.value).then(_0x411c65, _0x5da700);
    }
    _0x4eac44(_0x25725e.next());
  });
}
```

**第五层 - 死代码注入**

大量无关代码混入，包括:
- AdBlock 检测规则 (CSS 选择器)
- 字体检测列表
- 反调试陷阱
- 虚假的 DOM 操作函数

### 3.3 反混淆步骤

使用 AST 反混淆技能 (`ast-deobfuscation`):

1. **结构标准化** (`normalize-structure.js`)
   - 展开逗号表达式
   - 提升 IIFE 内部函数
   - 标准化变量声明

2. **虚假分支清理** (`prune-fake-branches.js`)
   - 移除永不执行的分支 (`if ("PxcLO" !== _0x14fb84(0x2cb))` 总是 true)
   - 移除死代码块

3. **字符串表解析** (手动)
   - 解析 `a0_0x536d` 数组中的所有字符串
   - 替换 `_0x1a6c4b(0xXXX)` → 实际字符串
   - 替换 `_0x4a2dc4(0xXXX)` → 实际字符串

4. **重命名标识符** (`rename-identifiers.js`)
   - `_0x32e40c` → `encryptMessage`
   - `_0x13f15c` → `generateToken`
   - `_0x5dcde7` → `PUBLIC_KEY_DER`

## 4. 核心算法

### 4.1 RSA 公钥

- **格式**: DER/SPKI (SubjectPublicKeyInfo)
- **密钥长度**: 2048-bit
- **指数**: 65537 (0x10001)
- **编码**: 296 字节原始 DER

```javascript
const PUBLIC_KEY_DER = [
  0x30, 0x82, 0x01, 0x22,  // SEQUENCE header
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,  // OID: RSA-OAEP
  0x03, 0x82, 0x01, 0x0f, 0x00,  // BIT STRING
  0x30, 0x82, 0x01, 0x0a,  // SEQUENCE
  0x02, 0x82, 0x01, 0x01, 0x00,  // INTEGER (modulus, 257 bytes)
  0xa7, 0xba, 0xf1, ... , 0xb9,  // Modulus data
  0x02, 0x03, 0x01, 0x00, 0x01,  // INTEGER (exponent: 65537)
];
```

### 4.2 加密算法

```
RSA-OAEP with SHA-256
├── 公钥: 2048-bit RSA (SPKI/DER 格式)
├── 哈希: SHA-256
├── 标签: 空 (默认)
└── 输出: 256 字节密文 → Base64 → 344 字符
```

### 4.3 消息格式

```
{visitorId}${platform}$1.0.0$r1r${powValue}

示例:
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6$web$1.0.0$r1r$1780205478046
│                               │ │   │         │ │              │
└─ 32位hex指纹                  │ │   │         │ └─ PoW值(13位)
                                │ │   │         └─ 固定盐
                                │ │   └─ 版本号
                                │ └─ 平台 (web/h5)
                                └─ 分隔符
```

### 4.4 FingerprintJS 指纹

avai.ai 内嵌了 FingerprintJS v3.4.2 (minified)。指纹组件包括:

| 组件 | 说明 |
|------|------|
| fonts | 系统字体检测 |
| canvas | Canvas 2D 指纹 |
| audio | AudioContext 指纹 |
| webgl | WebGL 渲染器指纹 |
| platform | navigator.platform |
| userAgent | navigator.userAgent |
| languages | navigator.languages |
| screenResolution | screen.width/height |
| colorDepth | screen.colorDepth |
| timezone | Intl.DateTimeFormat().resolvedOptions().timeZone |
| hardwareConcurrency | navigator.hardwareConcurrency |
| deviceMemory | navigator.deviceMemory |
| plugins | navigator.plugins |
| touchSupport | 触摸支持检测 |
| vendor | navigator.vendor |
| math | Math 精度指纹 |

**重要发现**: 服务器**不严格校验** visitorId 的具体值。使用随机生成的 32 位 hex 字符串即可通过验证。

### 4.5 PoW (Proof-of-Work)

```
powValue = String(server_time) + String(Date.now()).slice(-3)
```

- `server_time`: 从 `/v1api/v2/settings/serverTime` 获取 (UNIX 秒)
- `slice(-3)`: 本地时间戳后 3 位数字
- 用途: 防止重放攻击

## 5. 项目文件说明

### 5.1 Node.js 加密模块

`encrypt_request_id.js` - 纯 Node.js 实现:

```bash
# 用法
node encrypt_request_id.js <visitorId> <platform> <powValue>
node encrypt_request_id.js --test
```

```javascript
const { encryptRequestId, buildRequestId, generateVisitorId } = require('./encrypt_request_id.js');
```

### 5.2 Python 请求模块

`request_token.py` - 完整请求流程:

```python
from request_token import get_auth_token, search_token

# 自动获取 token 并搜索
x_auth = get_auth_token(platform="web")
result = search_token(keyword="BTC", x_auth=x_auth)
```

### 5.3 FastAPI 服务

`ave_search_server.py` - HTTP API 服务:

```bash
uvicorn ave_search_server:app --host 0.0.0.0 --port 8000
```

```bash
# 搜索接口
curl "http://localhost:8000/api/search?keyword=BTC&chain=bsc"

# 手动刷新 token
curl -X POST "http://localhost:8000/api/token"
```

### 5.4 反混淆产物

`deobfuscated/` 目录:
- `00_source.js` - 原始混淆代码
- `01_normalize.js` - 结构标准化后
- `02_prune.js` - 虚假分支清理后
- `deobfuscated_algorithm.js` - 手动反混淆后的核心算法

## 6. HTTP 请求参数

### 6.1 请求头

```python
HEADERS = {
    "accept": "*/*",
    "ave-platform": "web",        # 必填: web 或 h5
    "content-type": "application/json",
    "lang": "en",                 # 搜索接口需要
    "origin": "https://ave.ai",
    "referer": "https://ave.ai/",
    "user-agent": "Mozilla/5.0 ...",
}
```

### 6.2 x-auth Token 有效期

- 有效期为 7 天 (167 小时)
- 存储在 localStorage: `ave_token` 和 `ave_token_time`
- 也写入 cookie: `ave_token=<token>; expires=<date>; path=/`

## 7. 安全注意事项

1. **不要频繁请求**: 每次调用都消耗服务器 RSA 解密资源
2. **缓存 token**: x-auth token 有效期 7 天，不要每次搜索都重新获取
3. **Rate limiting**: 频繁获取新 token 可能触发风控
4. **IP 限制**: 建议使用代理轮换

## 8. 参考资源

- RSA-OAEP: [RFC 8017](https://tools.ietf.org/html/rfc8017#section-7.1)
- FingerprintJS: [GitHub](https://github.com/fingerprintjs/fingerprintjs)
- Web Crypto API: [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
