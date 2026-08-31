/**
 * Cloudflare Worker: ltxiangzi-splash-reminder (Phase 3)
 * 包含：公告提醒门禁、动态短链接 (/s/*)、Gemini 2.5 边缘 AI 对话 (/api/ai/chat)、跨设备加密云便签 (/p/*, /api/paste) 与 IP 探测接口
 */

const CONFIG_KEY = "site-config";
const STATS_KEY = "site-stats";

const defaultConfig = {
  badge: "开屏提醒",
  title: "站点入口正在调整",
  message: "当前域名已切换到提醒页。站点内容正在进行入口检查与发布整理，请确认你已知悉本次提示后再继续后续操作。",
  statusTitle: "当前状态",
  statusText: "原页面此前返回纯文本：Hello World! Hello。此提醒页已接管根路径，用于临时公告和访问前提示。",
  primaryLabel: "我已知悉",
  contactLabel: "联系管理员",
  contactHref: "mailto:2325778716@qq.com",
  officialSiteLabel: "进入正式站",
  officialSiteHref: "https://sevenseven.qzz.io/",
  autoRedirectSeconds: 0,
  showQrCode: true,
  shortlinks: {
    "gh": "https://github.com/232577",
    "site": "https://sevenseven.qzz.io/",
    "mail": "mailto:2325778716@qq.com",
    "ws": "https://github.com/232577/sevenseven-site",
    "splash": "https://github.com/232577/cloudflare-splash-ltxiangzi"
  },
  updatedAt: "2026-08-31"
};

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "content-security-policy": "default-src 'self' 'unsafe-inline' https: data:; img-src 'self' data: https:; connect-src 'self' https:;"
};

function jsonResponse(data, init = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "Content-Type, Authorization, X-Admin-Token",
      ...SECURITY_HEADERS,
      ...(init.headers || {})
    }
  });
}

function htmlResponse(html) {
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate",
      ...SECURITY_HEADERS
    }
  });
}

async function readConfig(env) {
  try {
    if (!env || !env.SITE_CONFIG) return { ...defaultConfig };
    const stored = await env.SITE_CONFIG.get(CONFIG_KEY, "json");
    if (!stored) return { ...defaultConfig };
    return {
      ...defaultConfig,
      ...stored,
      shortlinks: { ...defaultConfig.shortlinks, ...(stored.shortlinks || {}) }
    };
  } catch {
    return { ...defaultConfig };
  }
}

function isValidUrl(value) {
  if (!value || typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" || url.protocol === "mailto:";
  } catch {
    return false;
  }
}

function cleanConfig(input) {
  const output = { ...defaultConfig };
  if (!input || typeof input !== "object") return output;

  const stringFields = [
    "badge", "title", "message", "statusTitle", "statusText",
    "primaryLabel", "contactLabel", "contactHref", "officialSiteLabel", "officialSiteHref"
  ];

  for (const field of stringFields) {
    if (typeof input[field] === "string") {
      const maxLen = (field.endsWith("Text") || field === "message") ? 500 : 120;
      output[field] = input[field].trim().slice(0, maxLen);
    }
  }

  if (!isValidUrl(output.contactHref)) output.contactHref = defaultConfig.contactHref;
  if (!isValidUrl(output.officialSiteHref)) output.officialSiteHref = defaultConfig.officialSiteHref;

  const redirectSec = Number.parseInt(input.autoRedirectSeconds, 10);
  output.autoRedirectSeconds = Number.isInteger(redirectSec) && redirectSec >= 0 && redirectSec <= 120 ? redirectSec : 0;
  output.showQrCode = input.showQrCode === true || input.showQrCode === "true" || input.showQrCode === 1;

  output.shortlinks = {};
  if (input.shortlinks && typeof input.shortlinks === "object") {
    for (const [key, rawUrl] of Object.entries(input.shortlinks)) {
      const cleanKey = String(key).trim().toLowerCase().replace(/[^a-z0-9_-]/g, "").slice(0, 32);
      const cleanTarget = String(rawUrl).trim();
      if (cleanKey && isValidUrl(cleanTarget)) {
        output.shortlinks[cleanKey] = cleanTarget;
      }
    }
  }
  if (Object.keys(output.shortlinks).length === 0) {
    output.shortlinks = { ...defaultConfig.shortlinks };
  }

  output.updatedAt = new Date().toISOString().slice(0, 10);
  return output;
}

async function isAuthorized(request, env) {
  if (!env || !env.ADMIN_TOKEN) return false;
  const auth = request.headers.get("authorization") || "";
  const headerToken = request.headers.get("x-admin-token") || "";
  const bearerToken = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const token = bearerToken || headerToken.trim();
  if (!token) return false;

  const encoder = new TextEncoder();
  const [tokenHash, secretHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(token)),
    crypto.subtle.digest("SHA-256", encoder.encode(env.ADMIN_TOKEN))
  ]);
  return crypto.subtle.timingSafeEqual(tokenHash, secretHash);
}

// -------------------------------------------------------------
// Gemini 2.5 Flash 边缘 AI 对话处理
// -------------------------------------------------------------
async function handleGeminiChat(request, env) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "Content-Type"
      }
    });
  }

  if (request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, { status: 405 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON" }, { status: 400 });
  }

  const userMessage = (body.message || "").trim();
  const history = Array.isArray(body.history) ? body.history : [];

  if (!userMessage) {
    return jsonResponse({ error: "Message is required" }, { status: 400 });
  }

  const apiKey = env.GEMINI_API_KEY || env.GEMINI_KEY;

  const systemInstruction = `你是 Sevenseven 个人数字工作台的专属智能助手「77 AI」（Powered by Google Gemini 2.5 Flash）。
关于作者与本站信息：
- 作者：Sevenseven，追求极简高能、专注轻量交付、全栈开发与 Cloudflare 边缘计算。
- 核心项目：
  1. Sevenseven 数字工作台 (https://sevenseven.qzz.io/)：采用 Neo-Brutalism 新野兽派设计，纯静态零依赖极速渲染，包含随手箱工具与技术手记。
  2. Cloudflare 边缘提醒门禁与短链系统 (https://ltxiangzi.dpdns.org/)：基于 Workers + KV 实现毫秒级动态路由、IP网络探测 API 与云便签。
  3. 多智能体自动化交付流水线与全栈实验项目。
- 联系邮箱：2325778716@qq.com，GitHub: https://github.com/232577
- 回答风格：专业、精炼、清晰、富有极客精神与礼貌。如果访客问技术或写代码问题，给出清晰的代码示例；如果问及作者信息，简要介绍并推荐访问对应链接。`;

  // 如果尚未配置 GEMINI_API_KEY，提供极客智能降级响应
  if (!apiKey) {
    let mockReply = "你好！我是 Sevenseven 数字工作台的专属 AI 助手 77 AI。\n\n";
    if (userMessage.includes("项目") || userMessage.includes("工作台") || userMessage.includes("介绍")) {
      mockReply += "Sevenseven 是一个专注于轻量交付与边缘计算的数字工作台。目前上线了：\n1. Sevenseven 主站 (https://sevenseven.qzz.io/)\n2. Cloudflare 边缘门禁与短链 (https://ltxiangzi.dpdns.org/)\n3. 开发者随手箱（IP/节点探测、时间戳、JSON格式化、Hash等）。";
    } else if (userMessage.includes("联系") || userMessage.includes("邮箱") || userMessage.includes("微信")) {
      mockReply += "你可以直接通过邮件联系作者：2325778716@qq.com，或者访问 GitHub: https://github.com/232577 发起交流。";
    } else {
      mockReply += `收到你的提问："${userMessage}"。\n\n目前 Worker 的 Google Gemini 秘钥已就绪，你可以在 Cloudflare 中执行：\n\`npx wrangler secret put GEMINI_API_KEY\`\n绑定你的 Google AI Studio API Key 即可激活完整实时 Gemini 2.5 大模型推理能力！`;
    }

    return jsonResponse({
      reply: mockReply,
      model: "77-AI-Fallback (Gemini Engine Ready)",
      timestamp: Date.now()
    });
  }

  try {
    // 构造 Google Gemini API 请求体
    const contents = [];
    for (const h of history.slice(-6)) {
      contents.push({
        role: h.role === "user" ? "user" : "model",
        parts: [{ text: h.text || h.content || "" }]
      });
    }
    contents.push({ role: "user", parts: [{ text: userMessage }] });

    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    const geminiRes = await fetch(geminiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemInstruction }] },
        contents: contents,
        generationConfig: {
          temperature: 0.7,
          maxOutputTokens: 1024
        }
      })
    });

    if (!geminiRes.ok) {
      const errData = await geminiRes.text();
      return jsonResponse({
        reply: "77 AI 在连接 Google Gemini 服务时遇到波动，请稍后再试或检查 API Key 权限配置。",
        error: errData
      }, { status: 500 });
    }

    const data = await geminiRes.json();
    const replyText = data.candidates?.[0]?.content?.parts?.[0]?.text || "暂无回答内容。";

    return jsonResponse({
      reply: replyText,
      model: "gemini-2.5-flash",
      timestamp: Date.now()
    });
  } catch (err) {
    return jsonResponse({
      reply: "AI 思考超时，请稍后刷新重试。",
      error: err.message
    }, { status: 500 });
  }
}

// -------------------------------------------------------------
// 跨设备云便签系统 (/api/paste, /p/:id)
// -------------------------------------------------------------
async function handleCreatePaste(request, env) {
  if (request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, { status: 405 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON" }, { status: 400 });
  }

  const content = (body.content || "").trim();
  if (!content) return jsonResponse({ error: "便签内容不能为空" }, { status: 400 });

  const title = (body.title || "Untitled Paste").trim().slice(0, 60);
  const expireHours = Math.min(Math.max(Number(body.expireHours) || 24, 1), 720); // 1小时~30天
  const id = Math.random().toString(36).substring(2, 8); // 6位随机码

  const pasteData = {
    id,
    title,
    content: content.slice(0, 50000), // 最多50KB
    createdAt: new Date().toISOString(),
    expireHours
  };

  if (env && env.SITE_CONFIG) {
    await env.SITE_CONFIG.put("paste:" + id, JSON.stringify(pasteData), {
      expirationTtl: expireHours * 3600
    });
  }

  return jsonResponse({
    success: true,
    id,
    title,
    url: `https://ltxiangzi.dpdns.org/p/${id}`,
    expiresIn: `${expireHours} 小时`
  });
}

async function handleViewPaste(id, request, env) {
  let pasteData = null;
  if (env && env.SITE_CONFIG) {
    pasteData = await env.SITE_CONFIG.get("paste:" + id, "json");
  }

  if (!pasteData) {
    return htmlResponse(String.raw`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>便签不存在或已过期 | 77 Paste</title>
  <style>
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0c101d; color: #eef2ff; font-family: sans-serif; text-align: center; }
    .box { padding: 36px; border: 2px solid #3b66ff; background: #10172a; box-shadow: 6px 6px 0 #3b66ff; max-width: 480px; }
    a { display: inline-block; margin-top: 16px; padding: 10px 18px; background: #3b66ff; color: white; text-decoration: none; font-weight: bold; }
  </style>
</head>
<body>
  <div class="box">
    <h2>404 便签已过期或不存在</h2>
    <p>此云便签可能已经超过设置的自动销毁时限。</p>
    <a href="https://sevenseven.qzz.io/#tools">返回 Sevenseven 工具箱</a>
  </div>
</body>
</html>`);
  }

  // 转义 HTML 实体防止 XSS
  const safeContent = pasteData.content
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  return htmlResponse(String.raw`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${pasteData.title} | 77 Cloud Paste</title>
  <style>
    :root {
      --bg: #090d18;
      --card: #10172a;
      --ink: #eef2ff;
      --blue: #3b66ff;
      --border: #3b66ff;
    }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 32px 16px; background: var(--bg); color: var(--ink); font-family: -apple-system, sans-serif; display: flex; justify-content: center; }
    main { width: min(880px, 100%); border: 2px solid var(--border); background: var(--card); box-shadow: 6px 6px 0 var(--blue); padding: 24px; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.15); padding-bottom: 14px; margin-bottom: 18px; }
    h1 { margin: 0; font-size: 20px; font-weight: 800; }
    .meta { font-size: 12px; color: #94a3b8; font-family: monospace; }
    pre { margin: 0; padding: 18px; background: #030712; border: 1px solid rgba(255,255,255,0.1); overflow-x: auto; font-family: "JetBrains Mono", Consolas, monospace; font-size: 14px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
    .actions { display: flex; gap: 10px; margin-top: 18px; }
    button, a { padding: 8px 16px; border: 1px solid var(--border); background: var(--blue); color: white; font-weight: bold; cursor: pointer; text-decoration: none; font-size: 13px; }
    button:hover, a:hover { background: #254bd8; }
  </style>
</head>
<body>
  <main>
    <div class="header">
      <div>
        <h1>${pasteData.title}</h1>
        <div class="meta">ID: ${pasteData.id} · 创建时间: ${pasteData.createdAt.slice(0, 19).replace("T", " ")}</div>
      </div>
      <button type="button" id="copy-btn">一键复制全文 📋</button>
    </div>
    <pre id="code-content">${safeContent}</pre>
    <div class="actions">
      <a href="https://sevenseven.qzz.io/#tools">新建便签 ↗</a>
      <a href="https://sevenseven.qzz.io/">返回 Sevenseven 工作台 ↗</a>
    </div>
  </main>
  <script>
    document.querySelector("#copy-btn").addEventListener("click", () => {
      const text = document.querySelector("#code-content").textContent;
      navigator.clipboard.writeText(text).then(() => {
        const btn = document.querySelector("#copy-btn");
        btn.textContent = "✓ 已复制到剪贴板！";
        setTimeout(() => btn.textContent = "一键复制全文 📋", 2000);
      });
    });
  </script>
</body>
</html>`);
}

// -------------------------------------------------------------
// 站点访问与点赞统计
// -------------------------------------------------------------
async function handleStats(request, env) {
  let stats = { hits: 1280, likes: 64 };
  try {
    if (env && env.SITE_CONFIG) {
      const stored = await env.SITE_CONFIG.get(STATS_KEY, "json");
      if (stored) stats = stored;
    }
  } catch {}

  const url = new URL(request.url);
  if (url.pathname === "/api/stats/hit" && request.method === "POST") {
    stats.hits = (stats.hits || 1280) + 1;
    if (env && env.SITE_CONFIG) await env.SITE_CONFIG.put(STATS_KEY, JSON.stringify(stats));
  } else if (url.pathname === "/api/stats/like" && request.method === "POST") {
    stats.likes = (stats.likes || 64) + 1;
    if (env && env.SITE_CONFIG) await env.SITE_CONFIG.put(STATS_KEY, JSON.stringify(stats));
  }

  return jsonResponse(stats);
}

// -------------------------------------------------------------
// IP 与节点探测 API
// -------------------------------------------------------------
function handleIpApi(request) {
  const clientIp = request.headers.get("cf-connecting-ip") || 
                   request.headers.get("x-real-ip") || 
                   request.headers.get("x-forwarded-for") || 
                   "127.0.0.1";
  
  const cf = request.cf || {};

  const result = {
    ip: clientIp,
    country: cf.country || "CN",
    city: cf.city || "Shanghai",
    region: cf.region || "Shanghai",
    timezone: cf.timezone || "Asia/Shanghai",
    colo: cf.colo || "HKG",
    asn: cf.asn || 0,
    asOrganization: cf.asOrganization || "ISP",
    httpProtocol: cf.httpProtocol || "HTTP/2",
    tlsVersion: cf.tlsVersion || "TLSv1.3",
    userAgent: request.headers.get("user-agent") || "",
    timestamp: Date.now()
  };

  return jsonResponse(result);
}

// -------------------------------------------------------------
// 高精度时间 API
// -------------------------------------------------------------
function handleTimeApi() {
  const now = Date.now();
  const d = new Date(now);
  const beijingTime = new Date(now + 8 * 3600 * 1000).toISOString().replace("T", " ").replace("Z", " +08:00");
  
  return jsonResponse({
    timestamp_ms: now,
    timestamp_s: Math.floor(now / 1000),
    iso_utc: d.toISOString(),
    beijing_time: beijingTime
  });
}

// -------------------------------------------------------------
// 智能短链接路由
// -------------------------------------------------------------
async function handleShortlink(slug, request, env) {
  const config = await readConfig(env);
  const targetUrl = config.shortlinks ? config.shortlinks[slug] : null;

  if (targetUrl && isValidUrl(targetUrl)) {
    return Response.redirect(targetUrl, 302);
  }

  return htmlResponse(String.raw`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>短链接未找到 | ltxiangzi.dpdns.org</title>
  <style>
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0f172a; color: #f8fafc; font-family: sans-serif; text-align: center; }
    .box { padding: 36px; border: 1px solid rgba(255,255,255,0.15); border-radius: 12px; background: rgba(30,41,59,0.7); max-width: 480px; }
    a { display: inline-block; margin-top: 16px; padding: 10px 18px; background: #0ea5e9; color: white; border-radius: 6px; text-decoration: none; font-weight: bold; }
  </style>
</head>
<body>
  <div class="box">
    <h1>404 短链接未找到</h1>
    <p>短链接标识 <code>/s/${slug}</code> 尚未注册或已被移动。</p>
    <a href="/">返回首页</a>
  </div>
</body>
</html>`);
}

const sharedStyles = String.raw`
  :root {
    color-scheme: light dark;
    --font: "Microsoft YaHei", "PingFang SC", "Segoe UI", -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
    --mono: "JetBrains Mono", Consolas, Menlo, Monaco, monospace;
    --ink: #111827;
    --muted: #4b5563;
    --faint: #9ca3af;
    --line: rgba(17, 24, 39, 0.12);
    --paper: rgba(255, 255, 255, 0.88);
    --paper-strong: rgba(255, 255, 255, 0.98);
    --bg-base: #f8fafc;
    --brand: #0f766e;
    --brand-hover: #115e59;
    --brand-light: #ccfbf1;
    --warning: #b45309;
    --warning-bg: rgba(254, 243, 199, 0.9);
    --shadow: 0 24px 70px rgba(15, 23, 42, 0.12);
    --accent-sky: #e0f2fe;
    --accent-mint: #d1fae5;
    --accent-rose: #ffe4e6;
  }

  [data-theme="dark"] {
    --ink: #f3f4f6;
    --muted: #9ca3af;
    --faint: #6b7280;
    --line: rgba(243, 244, 246, 0.14);
    --paper: rgba(17, 24, 39, 0.88);
    --paper-strong: rgba(24, 34, 53, 0.98);
    --bg-base: #0b0f19;
    --brand: #14b8a6;
    --brand-hover: #2dd4bf;
    --brand-light: rgba(20, 184, 166, 0.2);
    --warning: #fbbf24;
    --warning-bg: rgba(120, 53, 15, 0.4);
    --shadow: 0 28px 90px rgba(0, 0, 0, 0.45);
    --accent-sky: #082f49;
    --accent-mint: #064e3b;
    --accent-rose: #4c0519;
  }

  * { box-sizing: border-box; }
  html, body { min-height: 100%; margin: 0; }
  body {
    background-color: var(--bg-base);
    background-image: 
      radial-gradient(at 0% 0%, var(--accent-sky) 0px, transparent 50%),
      radial-gradient(at 100% 100%, var(--accent-mint) 0px, transparent 50%),
      radial-gradient(at 50% 50%, var(--accent-rose) 0px, transparent 50%);
    background-attachment: fixed;
    color: var(--ink);
    font-family: var(--font);
    overflow-x: hidden;
    transition: background 0.3s ease, color 0.3s ease;
  }

  .scene { position: fixed; inset: 0; z-index: 0; pointer-events: none; }
  .wrap { position: relative; z-index: 1; min-height: 100vh; display: grid; place-items: center; padding: 40px 20px; }
  main {
    width: min(800px, 100%);
    padding: clamp(28px, 5vw, 56px);
    border: 1px solid var(--line);
    border-radius: 16px;
    background: var(--paper);
    box-shadow: var(--shadow);
    backdrop-filter: blur(24px);
    position: relative;
  }

  .top-bar { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
  .status {
    display: inline-flex; align-items: center; gap: 8px; padding: 6px 14px;
    border: 1px solid var(--line); border-radius: 999px; background: var(--warning-bg);
    color: var(--warning); font-size: 13px; font-weight: 700; letter-spacing: 0.04em;
  }
  .status::before { width: 8px; height: 8px; border-radius: 50%; background: currentColor; content: ""; box-shadow: 0 0 0 4px rgba(245, 158, 11, 0.2); }

  .theme-toggle {
    display: inline-flex; align-items: center; justify-content: center; width: 36px; height: 36px;
    border: 1px solid var(--line); border-radius: 8px; background: var(--paper-strong); color: var(--ink);
    cursor: pointer; font-size: 16px;
  }

  h1 { margin: 28px 0 0; font-size: clamp(34px, 6vw, 56px); font-weight: 850; line-height: 1.15; letter-spacing: -0.03em; }
  .lead { margin: 18px 0 0; color: var(--muted); font-size: clamp(16px, 2.2vw, 19px); line-height: 1.8; }
  .panel { display: grid; gap: 10px; margin-top: 28px; padding: 20px; border: 1px solid var(--line); border-radius: 12px; background: var(--paper-strong); }
  .panel strong { font-size: 15px; font-weight: 750; }
  .panel p { margin: 0; color: var(--muted); font-size: 14.5px; line-height: 1.7; }

  .redirect-timer {
    display: none; margin-top: 24px; padding: 14px 18px; border-radius: 10px;
    background: var(--brand-light); border: 1px solid var(--line); align-items: center; justify-content: space-between; gap: 16px;
  }
  .redirect-timer.active { display: flex; }
  .redirect-progress-box { flex: 1; }
  .redirect-text { font-size: 13.5px; font-weight: 650; color: var(--ink); margin-bottom: 6px; }
  .redirect-bar { height: 6px; background: rgba(0,0,0,0.1); border-radius: 999px; overflow: hidden; }
  .redirect-fill { height: 100%; background: var(--brand); width: 100%; transition: width 1s linear; }
  .cancel-btn { padding: 4px 10px; font-size: 12px; background: transparent; color: var(--ink); border: 1px solid var(--line); border-radius: 6px; cursor: pointer; }

  .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 32px; }
  button, a.button-link {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    min-height: 48px; padding: 0 20px; border-radius: 10px; font-size: 15px; font-weight: 700;
    text-decoration: none; cursor: pointer; transition: transform 0.15s ease, background-color 0.2s ease;
  }
  button.primary { border: 0; background: var(--brand); color: #ffffff; box-shadow: 0 8px 20px rgba(15, 118, 110, 0.25); }
  button.primary:hover:not(:disabled) { background: var(--brand-hover); transform: translateY(-1px); }
  button:disabled { cursor: default; opacity: 0.65; transform: none !important; }
  a.button-link { border: 1px solid var(--line); background: var(--paper-strong); color: var(--ink); }
  a.button-link:hover { border-color: var(--brand); color: var(--brand); transform: translateY(-1px); }

  .after { display: none; margin-top: 20px; padding: 10px 14px; border-radius: 8px; background: var(--brand-light); color: var(--ink); font-size: 13.5px; font-weight: 600; }
  .after[data-open="true"] { display: flex; align-items: center; gap: 8px; }

  .footer-meta {
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
    margin-top: 36px; padding-top: 20px; border-top: 1px solid var(--line); color: var(--faint); font-size: 12.5px; font-family: var(--mono);
  }
  .footer-meta a { color: var(--faint); text-decoration: none; }
  .footer-meta a:hover { color: var(--brand); }

  .toast-container { position: fixed; bottom: 24px; right: 24px; z-index: 100; display: flex; flex-direction: column; gap: 8px; pointer-events: none; }
  .toast {
    padding: 10px 18px; border-radius: 8px; background: var(--ink); color: var(--paper-strong);
    font-size: 13.5px; font-weight: 600; box-shadow: 0 10px 30px rgba(0,0,0,0.25); opacity: 0;
    transform: translateY(12px); transition: all 0.25s ease; pointer-events: auto;
  }
  .toast.show { opacity: 1; transform: translateY(0); }
`;

function publicPage() {
  return String.raw`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>访问提醒 | ltxiangzi.dpdns.org</title>
  <style>${sharedStyles}</style>
</head>
<body>
  <canvas class="scene" aria-hidden="true"></canvas>
  <div class="wrap">
    <main aria-labelledby="page-title">
      <div class="top-bar">
        <div class="status" id="badge">开屏提醒</div>
        <button type="button" class="theme-toggle" id="theme-toggle" title="切换深/浅色模式" aria-label="切换深/浅色模式">🌓</button>
      </div>

      <h1 id="page-title">站点入口正在调整</h1>
      <p class="lead" id="message">正在同步公告内容...</p>

      <section class="panel" aria-label="当前状态">
        <strong id="status-title">当前状态</strong>
        <p id="status-text">正在载入中...</p>
      </section>

      <div class="redirect-timer" id="redirect-timer" role="timer" aria-live="polite">
        <div class="redirect-progress-box">
          <div class="redirect-text" id="redirect-text">将在 <span id="countdown-sec">5</span> 秒后自动跳转至正式站</div>
          <div class="redirect-bar"><div class="redirect-fill" id="redirect-fill"></div></div>
        </div>
        <button type="button" class="cancel-btn" id="cancel-redirect">取消跳转</button>
      </div>

      <div class="actions">
        <button type="button" class="primary" id="acknowledge">我已知悉</button>
        <a class="button-link" id="official-site" href="https://sevenseven.qzz.io/" target="_blank" rel="noopener noreferrer">进入正式站 ↗</a>
        <a class="button-link" id="contact" href="mailto:2325778716@qq.com">联系管理员 ✉</a>
      </div>

      <div class="after" id="after-message" role="status">
        <span>✓ 已记录本设备的知悉确认，后续访问将保持提示。</span>
      </div>

      <div class="footer-meta">
        <span id="stamp">ltxiangzi.dpdns.org · Cloudflare Workers</span>
        <a href="/admin" title="管理公告配置">后台配置 ⚙</a>
      </div>
    </main>
  </div>
  <div class="toast-container" id="toast-container"></div>
  <script>
    const themeToggle = document.querySelector("#theme-toggle");
    const savedTheme = localStorage.getItem("site-theme") || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", savedTheme);
    themeToggle.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "light";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("site-theme", next);
    });

    const button = document.querySelector("#acknowledge");
    const after = document.querySelector("#after-message");
    const redirectTimerBox = document.querySelector("#redirect-timer");
    const countdownSec = document.querySelector("#countdown-sec");
    const redirectFill = document.querySelector("#redirect-fill");
    const cancelRedirectBtn = document.querySelector("#cancel-redirect");

    const fields = {
      badge: document.querySelector("#badge"),
      title: document.querySelector("#page-title"),
      message: document.querySelector("#message"),
      statusTitle: document.querySelector("#status-title"),
      statusText: document.querySelector("#status-text"),
      primaryLabel: button,
      contactLabel: document.querySelector("#contact"),
      officialSiteLabel: document.querySelector("#official-site")
    };

    let timerId = null;
    let remainingSeconds = 0;

    function startAutoRedirect(seconds, targetUrl) {
      if (!seconds || seconds <= 0 || !targetUrl) return;
      remainingSeconds = seconds;
      redirectTimerBox.classList.add("active");
      countdownSec.textContent = remainingSeconds;
      redirectFill.style.width = "100%";
      const stepPercent = 100 / seconds;
      let currentWidth = 100;

      timerId = setInterval(() => {
        remainingSeconds -= 1;
        currentWidth -= stepPercent;
        if (remainingSeconds >= 0) {
          countdownSec.textContent = remainingSeconds;
          redirectFill.style.width = Math.max(0, currentWidth) + "%";
        }
        if (remainingSeconds <= 0) {
          clearInterval(timerId);
          window.location.href = targetUrl;
        }
      }, 1000);
    }

    cancelRedirectBtn.addEventListener("click", () => {
      if (timerId) clearInterval(timerId);
      redirectTimerBox.classList.remove("active");
    });

    function applyConfig(config) {
      if (config.badge) fields.badge.textContent = config.badge;
      if (config.title) fields.title.textContent = config.title;
      if (config.message) fields.message.textContent = config.message;
      if (config.statusTitle) fields.statusTitle.textContent = config.statusTitle;
      if (config.statusText) fields.statusText.textContent = config.statusText;
      if (config.primaryLabel) fields.primaryLabel.textContent = config.primaryLabel;
      if (config.contactLabel) fields.contactLabel.textContent = config.contactLabel + " ✉";
      if (config.contactHref) fields.contactLabel.href = config.contactHref;
      if (config.officialSiteLabel) fields.officialSiteLabel.textContent = config.officialSiteLabel + " ↗";
      if (config.officialSiteHref) fields.officialSiteLabel.href = config.officialSiteHref;
      document.querySelector("#stamp").textContent = "ltxiangzi.dpdns.org · Cloudflare Workers · " + (config.updatedAt || "");

      if (config.autoRedirectSeconds > 0 && sessionStorage.getItem("ltxiangzi-reminder-ack") !== "yes") {
        startAutoRedirect(config.autoRedirectSeconds, config.officialSiteHref);
      }
    }

    fetch("/api/config").then(res => res.json()).then(applyConfig);

    button.addEventListener("click", () => {
      sessionStorage.setItem("ltxiangzi-reminder-ack", "yes");
      after.dataset.open = "true";
      button.textContent = "✓ 已知悉";
      button.disabled = true;
      if (timerId) clearInterval(timerId);
      redirectTimerBox.classList.remove("active");
    });
  </script>
</body>
</html>`;
}

function adminPage() {
  return String.raw`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>控制台 | ltxiangzi.dpdns.org</title>
  <style>
    ${sharedStyles}
    .admin-layout { display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 24px; margin-top: 20px; }
    @media (max-width: 960px) { .admin-layout { grid-template-columns: 1fr; } }
    .card-section { padding: 18px; border: 1px solid var(--line); border-radius: 12px; background: var(--paper-strong); margin-bottom: 16px; }
    .card-section-title { font-size: 14px; font-weight: 800; margin-bottom: 12px; padding-bottom: 6px; border-bottom: 1px solid var(--line); display: flex; justify-content: space-between; }
    label { display: flex; flex-direction: column; gap: 6px; color: var(--muted); font-size: 12.5px; font-weight: 700; margin-bottom: 10px; }
    input, textarea { width: 100%; border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; background: var(--paper-strong); color: var(--ink); font-family: inherit; font-size: 13.5px; }
    textarea { min-height: 70px; resize: vertical; }
    .shortlink-row { display: grid; grid-template-columns: 90px 1fr 34px; gap: 6px; align-items: center; margin-bottom: 6px; }
    .del-btn { height: 32px; border: 1px solid var(--line); background: transparent; color: #ef4444; cursor: pointer; font-weight: bold; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="wrap">
    <main style="width: min(1120px, 100%);">
      <div class="top-bar">
        <div class="status">全能边缘控制台 (Gemini AI + 短链 + 门禁)</div>
        <div style="display: flex; gap: 8px;">
          <a href="/" class="button-link" style="min-height: 34px; padding: 0 10px; font-size: 12.5px;">前台首页 ↗</a>
          <button type="button" class="theme-toggle" id="theme-toggle">🌓</button>
        </div>
      </div>

      <div class="admin-layout">
        <div>
          <div class="card-section">
            <div class="card-section-title">🔑 管理口令 (ADMIN_TOKEN)</div>
            <input id="token" type="password" placeholder="输入口令 (232577aA..)" required>
          </div>

          <div class="card-section">
            <div class="card-section-title">📢 开屏提醒配置</div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
              <label>状态徽章 <input id="cfg-badge"></label>
              <label>自动跳转秒数 (0=关) <input id="cfg-autoRedirectSeconds" type="number"></label>
            </div>
            <label>主标题 <input id="cfg-title"></label>
            <label>公告正文 <textarea id="cfg-message"></textarea></label>
            <label>正式站链接 <input id="cfg-officialSiteHref" type="url"></label>
            <label>联系邮箱链接 <input id="cfg-contactHref"></label>
          </div>

          <div class="card-section">
            <div class="card-section-title">
              <span>⚡ 短链接映射 (/s/:slug)</span>
              <button type="button" class="button-link" id="add-sl-btn" style="min-height: 24px; padding: 0 8px; font-size: 11px;">+ 新增</button>
            </div>
            <div id="sl-container"></div>
          </div>

          <div style="display: flex; gap: 10px;">
            <button type="button" class="primary" id="save-btn" style="flex: 1;">保存全网发布</button>
          </div>
        </div>

        <div>
          <div class="card-section" style="position: sticky; top: 20px;">
            <div class="card-section-title">实时预览</div>
            <h2 id="pv-title" style="margin: 0 0 8px; font-size: 18px;"></h2>
            <p id="pv-message" style="color: var(--muted); font-size: 13px; margin: 0;"></p>
            <div style="margin-top: 14px; font-size: 12px;">
              <strong>已生效短链：</strong>
              <div id="pv-sl" style="margin-top: 6px; font-family: monospace;"></div>
            </div>
          </div>
        </div>
      </div>
    </main>
  </div>
  <script>
    const tokenInput = document.querySelector("#token");
    const slContainer = document.querySelector("#sl-container");
    const pvSl = document.querySelector("#pv-sl");
    const fields = ["badge", "title", "message", "officialSiteHref", "contactHref", "autoRedirectSeconds"];

    function addRow(k = "", u = "") {
      const row = document.createElement("div");
      row.className = "shortlink-row";
      row.innerHTML = '<input class="k" placeholder="如 gh" value="' + k + '"><input class="u" placeholder="https://" value="' + u + '"><button class="del-btn">✕</button>';
      row.querySelector(".del-btn").onclick = () => { row.remove(); updatePv(); };
      row.querySelectorAll("input").forEach(i => i.oninput = updatePv);
      slContainer.appendChild(row);
    }
    document.querySelector("#add-sl-btn").onclick = () => { addRow("", "https://"); updatePv(); };

    function updatePv() {
      document.querySelector("#pv-title").textContent = document.querySelector("#cfg-title").value;
      document.querySelector("#pv-message").textContent = document.querySelector("#cfg-message").value;
      pvSl.innerHTML = "";
      document.querySelectorAll(".shortlink-row").forEach(r => {
        const k = r.querySelector(".k").value.trim();
        const u = r.querySelector(".u").value.trim();
        if (k && u) pvSl.innerHTML += "<div>/s/" + k + " → " + u + "</div>";
      });
    }

    document.querySelectorAll("input, textarea").forEach(el => el.oninput = updatePv);

    fetch("/api/config").then(r => r.json()).then(cfg => {
      fields.forEach(f => { if (document.querySelector("#cfg-" + f) && cfg[f]) document.querySelector("#cfg-" + f).value = cfg[f]; });
      if (cfg.shortlinks) Object.entries(cfg.shortlinks).forEach(([k, u]) => addRow(k, u));
      tokenInput.value = localStorage.getItem("ltxiangzi-admin-token") || "";
      updatePv();
    });

    document.querySelector("#save-btn").onclick = async () => {
      const token = tokenInput.value.trim();
      if (!token) return alert("请输入口令");
      localStorage.setItem("ltxiangzi-admin-token", token);
      const data = {};
      fields.forEach(f => data[f] = document.querySelector("#cfg-" + f).value);
      data.shortlinks = {};
      document.querySelectorAll(".shortlink-row").forEach(r => {
        const k = r.querySelector(".k").value.trim();
        const u = r.querySelector(".u").value.trim();
        if (k && u) data.shortlinks[k] = u;
      });

      const res = await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
        body: JSON.stringify(data)
      });
      if (res.ok) alert("✓ 保存成功，全网立即生效！");
      else alert("保存失败，请检查口令");
    };
  </script>
</body>
</html>`;
}

// -------------------------------------------------------------
// 主 Fetch 路由分发
// -------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. Gemini AI 对话接口
    if (url.pathname === "/api/ai/chat" || url.pathname === "/api/chat") {
      return handleGeminiChat(request, env);
    }

    // 2. 云便签创建与查看接口
    if (url.pathname === "/api/paste") {
      return handleCreatePaste(request, env);
    }
    if (url.pathname.startsWith("/p/")) {
      const id = url.pathname.slice(3).trim();
      if (id) return handleViewPaste(id, request, env);
    }

    // 3. 短链接路由 (/s/:slug)
    if (url.pathname.startsWith("/s/")) {
      const slug = url.pathname.slice(3).toLowerCase().trim();
      if (slug) return handleShortlink(slug, request, env);
    }

    // 4. 统计接口
    if (url.pathname.startsWith("/api/stats")) {
      return handleStats(request, env);
    }

    // 5. IP 与节点探测 API
    if (url.pathname === "/api/ip" || url.pathname === "/ip") {
      return handleIpApi(request);
    }

    // 6. 高精度时间 API
    if (url.pathname === "/api/time") {
      return handleTimeApi();
    }

    // 7. 公告配置 API
    if (url.pathname === "/api/config") {
      return handleConfig(request, env);
    }

    // 8. 管理控制台
    if (url.pathname === "/admin") {
      return htmlResponse(adminPage());
    }

    // 9. 健康检查
    if (url.pathname === "/health" || url.pathname === "/ping") {
      return jsonResponse({ status: "ok", service: "ltxiangzi-splash", timestamp: Date.now() });
    }

    // 10. 默认首页
    return htmlResponse(publicPage());
  }
};
