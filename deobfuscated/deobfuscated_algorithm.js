/**
 * ave.ai vemachine.js - 反混淆后的核心算法
 * ==========================================
 *
 * 原始文件: vemachine.js (212KB, 多层OB混淆)
 * 反混淆步骤:
 *   1. 结构标准化 (normalize-structure.js)
 *   2. 虚假分支清理 (prune-fake-branches.js)
 *   3. 字符串表手动解析
 *
 * 下面是从混淆代码中提取的核心算法。
 */

// ============================================================
// 1. RSA 公钥 (DER/SPKI 格式, 2048-bit)
// ============================================================
const PUBLIC_KEY_DER = new Uint8Array([
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
  0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa7, 0xba, 0xf1, 0x0a, 0xcf, 0x94, 0x17,
  0x94, 0x23, 0x01, 0x95, 0x98, 0xeb, 0x73, 0xb0, 0xd6, 0xb3, 0x58, 0xe2, 0x9a, 0xed, 0xa2, 0xb2, 0x11, 0x6b, 0x00,
  0x0b, 0x96, 0xa1, 0x9c, 0x5a, 0xb0, 0xcf, 0xd9, 0x32, 0xaa, 0x0b, 0xa5, 0xcb, 0xc9, 0xb2, 0x42, 0xc0, 0xe6, 0x7c,
  0x1c, 0x21, 0x98, 0xcf, 0x31, 0xdd, 0x40, 0x91, 0x41, 0x2d, 0xbf, 0x30, 0x95, 0xb6, 0x80, 0x27, 0x18, 0x36,
  0xfc, 0x6f, 0xa0, 0x97, 0x03, 0x7f, 0x1e, 0x9d, 0x71, 0x36, 0xe6, 0x30, 0xea, 0xe2, 0x7b, 0x2d, 0x31, 0x4c, 0x64,
  0x21, 0x6c, 0x53, 0x94, 0x5e, 0x2f, 0x16, 0x7c, 0xde, 0xe5, 0x6c, 0xfe, 0xe1, 0xbc, 0xd2, 0xfc, 0xab, 0xa5,
  0xa8, 0x8d, 0xf9, 0xe5, 0x39, 0xf0, 0x1f, 0x63, 0xd7, 0x6f, 0xb0, 0xe1, 0x56, 0xc8, 0xbf, 0x87, 0x5d, 0xd1,
  0xae, 0x48, 0x2c, 0x04, 0x0c, 0x2e, 0x32, 0x50, 0x89, 0x48, 0x22, 0x19, 0xf0, 0xf8, 0x24, 0x8f, 0x62, 0x73, 0xca,
  0x82, 0x37, 0x03, 0xa8, 0xda, 0xcb, 0xb7, 0xc1, 0xd2, 0xad, 0x84, 0xc7, 0xa0, 0xe5, 0x66, 0x21, 0x61, 0x7b, 0x4a,
  0x27, 0x25, 0x01, 0x24, 0xc9, 0xf9, 0xa1, 0xd2, 0x9d, 0xed, 0x73, 0x90, 0x3b, 0xb2, 0xa6, 0xb2, 0xe1, 0xf2, 0xf9,
  0xd1, 0x1b, 0xba, 0xd4, 0x8f, 0xb8, 0x2d, 0xa4, 0x4d, 0x8f, 0xb2, 0xd9, 0xbc, 0xc7, 0x51, 0xd4, 0xd8, 0x79,
  0x4a, 0x7a, 0x53, 0xf1, 0x94, 0x64, 0x28, 0xc7, 0x8a, 0xb6, 0x42, 0x50, 0x24, 0x32, 0x08, 0x13, 0xc4, 0xf2, 0x75,
  0xa8, 0x09, 0x18, 0xe1, 0x3f, 0xdf, 0x9e, 0xc1, 0x22, 0x92, 0x44, 0xf6, 0x93, 0x38, 0x6f, 0xee, 0x89, 0xca, 0xcd,
  0xd5, 0xc5, 0x19, 0x0b, 0x93, 0x9a, 0x97, 0xd3, 0xcf, 0x8a, 0x01, 0x80, 0x27, 0xc8, 0x24, 0x29, 0x33, 0xc3, 0x81,
  0x91, 0xc5, 0x3d, 0x74, 0xca, 0xb9, 0x02, 0x03, 0x01, 0x00, 0x01,
]);

// ============================================================
// 2. Base64 编码 (btoa polyfill without TextEncoder overhead)
// ============================================================
function base64Encode(uint8Array) {
  return btoa(String.fromCharCode(...uint8Array));
}

// ============================================================
// 3. RSA-OAEP 加密 (encryptMessage / _0x32e40c)
// ============================================================
// 原始代码:
//   async function _0x32e40c(_0x5959ba, _0x566ef6) {
//     const _0x4d2b11 = await _0x5d54cd(_0x5959ba, 'encrypt');
//     const _0x1924e3 = new TextEncoder();
//     const _0x33821c = _0x1924e3.encode(_0x566ef6);
//     const _0x36baed = await crypto.subtle.encrypt(
//       { name: 'RSA-OAEP' },  // hash defaults to SHA-256 via key import
//       _0x4d2b11,
//       _0x33821c
//     );
//     return base64Encode(_0x36baed);
//   }
//
// _0x5d54cd 导入公钥:
//   crypto.subtle.importKey('spki', derBytes, {name:'RSA-OAEP', hash:'SHA-256'}, true, ['encrypt'])

async function encryptMessage(publicKeyDerBytes, plaintext) {
  // 导入 RSA 公钥
  const publicKey = await crypto.subtle.importKey(
    'spki',
    publicKeyDerBytes,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );

  // 编码消息
  const encoder = new TextEncoder();
  const encoded = encoder.encode(plaintext);

  // RSA-OAEP SHA-256 加密
  const encrypted = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    encoded
  );

  // Base64 输出
  return base64Encode(new Uint8Array(encrypted));
}

// ============================================================
// 4. FingerprintJS 指纹生成 (内嵌版)
// ============================================================
// 原始代码使用内嵌的 FingerprintJS (v3.4.2) 收集浏览器指纹:
//   - fonts (字体检测)
//   - canvas (Canvas 指纹)
//   - audio (AudioContext 指纹)
//   - webgl (WebGL 指纹)
//   - navigator 属性 (platform, userAgent, languages, etc.)
//   - screen 属性 (resolution, colorDepth)
//   - timezone
//   - plugins, mimeTypes
//   - 等各种浏览器特征
//
// 指纹组件经过 MurmurHash3 x64 128-bit 哈希后得到 32 位 hex visitorId
//
// 实际测试: 服务器不严格校验 visitorId 的具体值, 只需:
//   1. 长度正确 (32 位 hex)
//   2. 格式正确 (hex 字符)
//   3. 每次请求使用不同的 visitorId (模拟真实浏览器行为)
//
// 因此简化为随机生成:

function generateVisitorId() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================
// 5. 服务器时间获取 (fingerprint PoW)
// ============================================================
// 原始代码中的 _0x193b10 函数:
//   function _0x193b10(_0x12b451, _0x5c803d = "") {
//     let url = (_0x5c803d || baseURL()) + '/v1api/v2/settings/serverTime';
//     return fetch(url, {
//       method: 'GET',
//       headers: { 'Content-Type': 'application/json', 'Ave-Platform': _0x12b451 || 'web' }
//     })
//     .then(resp => resp.json())
//     .then(jsonData => {
//       const data = jsonData['data'];
//       return data['status'] === 0
//         ? Promise.reject(data['error'])
//         : Promise.resolve(Number(String(data['server_time'] || 0) + String(Date.now()).slice(-3)));
//     });
//   }
//
// 返回: server_time (秒) + 本地时间戳后3位 → 如 "1780205478000"

async function getServerTimePow(platform) {
  const baseURL = 'https://api.agacve.com';
  const url = baseURL + '/v1api/v2/settings/serverTime';
  const resp = await fetch(url, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Ave-Platform': platform || 'web',
      'Origin': 'https://ave.ai',
      'Referer': 'https://ave.ai/',
    }
  });
  const jsonData = await resp.json();
  const serverTime = jsonData.data.server_time;
  // 拼接本地时间戳后3位
  return String(serverTime) + String(Date.now()).slice(-3);
}

// ============================================================
// 6. 完整的 generateToken 流程 (_0x13f15c)
// ============================================================
// 原始代码:
//   async function _0x13f15c(_0x94040b = !0x1, _0x3bb4c3 = "") {
//     // 检查 window/navigator/document 存在 (浏览器环境)
//     if (!window?.navigator || !window?.document) return reject("Not in browser");
//     if (!checkCrypto()) return reject("not supported");
//
//     // 检查 localStorage 缓存的 token
//     let cachedTime = localStorage.getItem('ave_token_time') || '0';
//     let cachedToken = localStorage.getItem('ave_token') || fromCookie();
//     if (!forceRefresh && cachedToken && (Date.now() - Number(cachedTime)) < 167 * 3600 * 1000) {
//       return cachedToken; // 7天内有效, 直接返回缓存
//     }
//
//     // 1. 获取指纹 visitorId
//     let fpResult = await fingerprintLibrary.load();
//     let visitorId = fpResult.visitorId;
//
//     // 2. 判断平台
//     let ua = navigator.userAgent;
//     let platform = /(iPhone|iPad|iPod|Android)/i.test(ua) ? 'h5' : 'web';
//
//     // 3. 获取时间戳
//     let timestamp = Date.now();
//
//     // 4. 获取 PoW 值 (serverTime + 本地时间戳后3位)
//     let powValue = await getServerTimePow(platform, baseURL)
//       .then(() => timestamp); // fallback 到本地时间戳
//
//     // 5. 构建明文
//     let plaintext = visitorId + '$' + platform + '$1.0.0$r1r$' + powValue;
//
//     // 6. RSA-OAEP 加密 → request_id
//     let requestId = await encryptMessage(PUBLIC_KEY_DER, plaintext);
//
//     // 7. 请求 captcha token
//     let token = await fetchCaptchaToken(requestId, platform, baseURL);
//
//     // 8. 保存到 localStorage/cookie
//     if (token) saveToken(token);
//
//     return token;
//   }

async function generateToken(forceRefresh = false, baseURL = '') {
  const apiBase = baseURL || 'https://api.agacve.com';

  // 1. 获取指纹
  const visitorId = generateVisitorId();

  // 2. 平台判断
  // const ua = navigator.userAgent;
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36'
  const platform = /(iPhone|iPad|iPod|Android)/i.test(ua) ? 'h5' : 'web';

  // 3. 获取服务器时间 PoW
  let powValue;
  try {
    powValue = await getServerTimePow(platform);
  } catch (e) {
    // Fallback: 使用本地时间戳
    powValue = String(Date.now());
  }

  // 4. 构建明文: visitId$platform$1.0.0$r1r$powValue
  const plaintext = visitorId + '$' + platform + '$1.0.0$r1r$' + powValue;

  // 5. RSA-OAEP 加密
  const requestId = await encryptMessage(PUBLIC_KEY_DER, plaintext);
  console.log('requestsId= ',requestId)
  // 6. 请求 captcha token
  const captchaUrl = apiBase + '/v1api/v1/captcha/requestToken';
  const captchaResp = await fetch(captchaUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Ave-Platform': platform,
      'Origin': 'https://ave.ai',
      'Referer': 'https://ave.ai/',
    },
    body: JSON.stringify({ request_id: requestId }),
  });
  const captchaData = await captchaResp.json();

  if (captchaData.status !== 1) {
    throw new Error('captcha error: ' + JSON.stringify(captchaData));
  }
  var x_auth = captchaData.data.id
  console.log('x_auth= ',x_auth)
  return x_auth;
}
await generateToken()
// console.log('x_auth= ',x_auth)
// ============================================================
// 7. API 端点汇总
// ============================================================
const API_ENDPOINTS = {
  baseURL: 'https://api.agacve.com',
  serverTime: '/v1api/v2/settings/serverTime',       // GET  - 获取服务器时间
  captchaRequest: '/v1api/v1/captcha/requestToken',  // POST - 获取 x-auth token
  search: '/v2api/token/v1/query',                   // GET  - 搜索接口
};

// ============================================================
// 8. 算法特点总结
// ============================================================
/*
 * 加密算法:     RSA-OAEP with SHA-256 (2048-bit key)
 * 公钥:         DER/SPKI 格式, 硬编码在 JS 中
 * 消息格式:     {visitorId}${platform}$1.0.0$r1r${powValue}
 * visitorId:    FingerprintJS v3.4.2 生成的 32 位 hex 浏览器指纹
 * platform:     "web" (桌面) 或 "h5" (移动端)
 * powValue:     server_time + 本地时间戳后3位 (防重放)
 * 固定盐值:     "$1.0.0$r1r$" (版本号)
 * 输出:         Base64 编码的 RSA 密文 (344 字符)
 *
 * 混淆技术:
 *   - 双层字符串表 (a0_0x536d + _0x31523b)
 *   - OB 风格 _0x 标识符
 *   - 控制流平坦化 (generator state machine)
 *   - 死代码注入 (adblock 检测、CSS 选择器等无关代码)
 *   - 不透明谓词 (字符串比较死分支)
 *   - 自执行 IIFE 包装
 */
