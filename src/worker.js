/**
 * Cloudflare Worker: ltxiangzi-splash-reminder
 * 公告提醒门禁服务与动态配置管理
 */

const CONFIG_KEY = "site-config";

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
  autoRedirectSeconds: 0, // 0 = 不开启，> 0 = 倒计时秒数
  showQrCode: true,
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
  return new Response(JSON.stringify(data), {
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
    if (!env || !env.SITE_CONFIG) {
      return { ...defaultConfig };
    }
    const stored = await env.SITE_CONFIG.get(CONFIG_KEY, "json");
    return { ...defaultConfig, ...(stored || {}) };
  } catch (err) {
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
  
  if (!input || typeof input !== "object") {
    return output;
  }

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

  if (!isValidUrl(output.contactHref)) {
    output.contactHref = defaultConfig.contactHref;
  }

  if (!isValidUrl(output.officialSiteHref)) {
    output.officialSiteHref = defaultConfig.officialSiteHref;
  }

  const redirectSec = Number.parseInt(input.autoRedirectSeconds, 10);
  output.autoRedirectSeconds = Number.isInteger(redirectSec) && redirectSec >= 0 && redirectSec <= 120 ? redirectSec : 0;
  output.showQrCode = input.showQrCode === true || input.showQrCode === "true" || input.showQrCode === 1;
  output.updatedAt = new Date().toISOString().slice(0, 10);

  return output;
}

async function isAuthorized(request, env) {
  if (!env || !env.ADMIN_TOKEN) {
    return false;
  }

  const auth = request.headers.get("authorization") || "";
  const headerToken = request.headers.get("x-admin-token") || "";
  const bearerToken = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  const token = bearerToken || headerToken.trim();

  if (!token) {
    return false;
  }

  const encoder = new TextEncoder();
  const [tokenHash, secretHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(token)),
    crypto.subtle.digest("SHA-256", encoder.encode(env.ADMIN_TOKEN))
  ]);

  return crypto.subtle.timingSafeEqual(tokenHash, secretHash);
}

async function handleConfig(request, env) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "Content-Type, Authorization, X-Admin-Token"
      }
    });
  }

  if (request.method === "GET") {
    const config = await readConfig(env);
    return jsonResponse(config);
  }

  if (request.method !== "POST") {
    return jsonResponse({ error: "method_not_allowed" }, { status: 405 });
  }

  if (!(await isAuthorized(request, env))) {
    return jsonResponse({ error: "unauthorized", message: "口令无效或未配置环境变量 ADMIN_TOKEN" }, { status: 401 });
  }

  let payload;
  try {
    payload = await request.json();
  } catch {
    return jsonResponse({ error: "invalid_json", message: "数据格式错误" }, { status: 400 });
  }

  const nextConfig = cleanConfig(payload);
  if (env && env.SITE_CONFIG) {
    await env.SITE_CONFIG.put(CONFIG_KEY, JSON.stringify(nextConfig));
  }
  return jsonResponse({ success: true, config: nextConfig });
}

const sharedStyles = String.raw`
  :root {
    color-scheme: light dark;
    --font: "Microsoft YaHei", "PingFang SC", "Segoe UI", -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
    --mono: "JetBrains Mono", Consolas, Menlo, Monaco, monospace;
    
    /* Light Theme Palette */
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
    -webkit-backdrop-filter: blur(24px);
    position: relative;
  }

  .top-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
  }

  .status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 14px;
    border: 1px solid var(--line);
    border-radius: 999px;
    background: var(--warning-bg);
    color: var(--warning);
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.04em;
  }

  .status::before {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: currentColor;
    content: "";
    box-shadow: 0 0 0 4px rgba(245, 158, 11, 0.2);
    animation: pulse 2s infinite ease-in-out;
  }

  @keyframes pulse {
    0%, 100% { transform: scale(1); opacity: 1; }
    50% { transform: scale(1.2); opacity: 0.6; }
  }

  .theme-toggle {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: var(--paper-strong);
    color: var(--ink);
    cursor: pointer;
    font-size: 16px;
    transition: background 0.2s ease;
  }
  .theme-toggle:hover { background: var(--brand-light); }

  h1 {
    margin: 28px 0 0;
    font-size: clamp(34px, 6vw, 56px);
    font-weight: 850;
    line-height: 1.15;
    letter-spacing: -0.03em;
  }

  .lead {
    margin: 18px 0 0;
    color: var(--muted);
    font-size: clamp(16px, 2.2vw, 19px);
    line-height: 1.8;
  }

  .panel {
    display: grid;
    gap: 10px;
    margin-top: 28px;
    padding: 20px;
    border: 1px solid var(--line);
    border-radius: 12px;
    background: var(--paper-strong);
  }
  .panel strong { font-size: 15px; font-weight: 750; }
  .panel p { margin: 0; color: var(--muted); font-size: 14.5px; line-height: 1.7; }

  /* 倒计时进度条 */
  .redirect-timer {
    display: none;
    margin-top: 24px;
    padding: 14px 18px;
    border-radius: 10px;
    background: var(--brand-light);
    border: 1px solid var(--line);
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }
  .redirect-timer.active { display: flex; }
  .redirect-progress-box { flex: 1; }
  .redirect-text { font-size: 13.5px; font-weight: 650; color: var(--ink); margin-bottom: 6px; }
  .redirect-bar { height: 6px; background: rgba(0,0,0,0.1); border-radius: 999px; overflow: hidden; }
  .redirect-fill { height: 100%; background: var(--brand); width: 100%; transition: width 1s linear; }
  .cancel-btn { padding: 4px 10px; font-size: 12px; background: transparent; color: var(--ink); border: 1px solid var(--line); border-radius: 6px; cursor: pointer; }
  .cancel-btn:hover { background: var(--paper-strong); }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-top: 32px;
  }

  button, a.button-link {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    min-height: 48px;
    padding: 0 20px;
    border-radius: 10px;
    font-size: 15px;
    font-weight: 700;
    text-decoration: none;
    cursor: pointer;
    transition: transform 0.15s ease, background-color 0.2s ease, box-shadow 0.2s ease;
  }

  button.primary {
    border: 0;
    background: var(--brand);
    color: #ffffff;
    box-shadow: 0 8px 20px rgba(15, 118, 110, 0.25);
  }
  button.primary:hover:not(:disabled) {
    background: var(--brand-hover);
    transform: translateY(-1px);
  }
  button:disabled { cursor: default; opacity: 0.65; transform: none !important; }

  a.button-link {
    border: 1px solid var(--line);
    background: var(--paper-strong);
    color: var(--ink);
  }
  a.button-link:hover {
    border-color: var(--brand);
    color: var(--brand);
    transform: translateY(-1px);
  }

  .after {
    display: none;
    margin-top: 20px;
    padding: 10px 14px;
    border-radius: 8px;
    background: var(--brand-light);
    color: var(--ink);
    font-size: 13.5px;
    font-weight: 600;
  }
  .after[data-open="true"] { display: flex; align-items: center; gap: 8px; }

  .footer-meta {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    margin-top: 36px;
    padding-top: 20px;
    border-top: 1px solid var(--line);
    color: var(--faint);
    font-size: 12.5px;
    font-family: var(--mono);
  }
  .footer-meta a { color: var(--faint); text-decoration: none; }
  .footer-meta a:hover { color: var(--brand); }

  /* Toast Notification */
  .toast-container {
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 100;
    display: flex;
    flex-direction: column;
    gap: 8px;
    pointer-events: none;
  }
  .toast {
    padding: 10px 18px;
    border-radius: 8px;
    background: var(--ink);
    color: var(--paper-strong);
    font-size: 13.5px;
    font-weight: 600;
    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
    opacity: 0;
    transform: translateY(12px);
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    pointer-events: auto;
  }
  .toast.show { opacity: 1; transform: translateY(0); }

  @media (max-width: 600px) {
    .wrap { padding: 20px 14px; align-items: start; }
    main { padding: 24px 18px; }
    h1 { font-size: 32px; }
    .actions, button, a.button-link { width: 100%; }
    .footer-meta { flex-direction: column; align-items: flex-start; }
  }

  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation-duration: 0.001ms !important;
      transition-duration: 0.001ms !important;
    }
  }
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

      <!-- 智能自动跳转模块（配置开启时激活） -->
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
    // Theme Management
    const themeToggle = document.querySelector("#theme-toggle");
    const savedTheme = localStorage.getItem("site-theme") || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", savedTheme);

    themeToggle.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "light";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("site-theme", next);
      showToast(next === "dark" ? "已切换至深色模式 🌙" : "已切换至浅色模式 ☀️");
    });

    // Toast Utility
    function showToast(msg) {
      const container = document.querySelector("#toast-container");
      const toast = document.createElement("div");
      toast.className = "toast";
      toast.textContent = msg;
      container.appendChild(toast);
      requestAnimationFrame(() => toast.classList.add("show"));
      setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => toast.remove(), 300);
      }, 2500);
    }

    // Elements & Config
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
      showToast("已取消自动跳转");
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

      // Handle auto-redirect if configured and not already acknowledged
      if (config.autoRedirectSeconds > 0 && sessionStorage.getItem("ltxiangzi-reminder-ack") !== "yes") {
        startAutoRedirect(config.autoRedirectSeconds, config.officialSiteHref);
      }
    }

    fetch("/api/config")
      .then(res => res.json())
      .then(applyConfig)
      .catch(() => {
        fields.message.textContent = "公告配置载入完毕。";
      });

    function showAcknowledged() {
      after.dataset.open = "true";
      button.textContent = "✓ 已知悉";
      button.disabled = true;
      if (timerId) clearInterval(timerId);
      redirectTimerBox.classList.remove("active");
    }

    if (sessionStorage.getItem("ltxiangzi-reminder-ack") === "yes") {
      showAcknowledged();
    }

    button.addEventListener("click", () => {
      sessionStorage.setItem("ltxiangzi-reminder-ack", "yes");
      showAcknowledged();
      showToast("感谢确认！");
    });

    // Particle Canvas Animation with Theme Adaptation
    const canvas = document.querySelector(".scene");
    const context = canvas.getContext("2d");
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function resize() {
      const ratio = window.devicePixelRatio || 1;
      canvas.width = Math.floor(window.innerWidth * ratio);
      canvas.height = Math.floor(window.innerHeight * ratio);
      canvas.style.width = window.innerWidth + "px";
      canvas.style.height = window.innerHeight + "px";
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
    }

    function draw(time) {
      time = time || 0;
      const width = window.innerWidth;
      const height = window.innerHeight;
      const isDark = document.documentElement.getAttribute("data-theme") === "dark";

      context.clearRect(0, 0, width, height);
      context.globalAlpha = isDark ? 0.3 : 0.45;
      context.lineWidth = 1;

      for (let x = -80; x < width + 80; x += 48) {
        const shift = reduceMotion ? 0 : Math.sin((time / 2000) + x * 0.015) * 10;
        context.strokeStyle = isDark ? "rgba(20, 184, 166, 0.25)" : "rgba(15, 118, 110, 0.16)";
        context.beginPath();
        context.moveTo(x + shift, 0);
        context.lineTo(x - 140 + shift, height);
        context.stroke();
      }

      for (let y = 30; y < height; y += 72) {
        const pulse = reduceMotion ? 0 : Math.sin((time / 1600) + y * 0.01) * 0.08;
        context.strokeStyle = isDark ? "rgba(251, 191, 36, " + (0.08 + pulse) + ")" : "rgba(180, 83, 9, " + (0.08 + pulse) + ")";
        context.beginPath();
        context.moveTo(0, y);
        context.lineTo(width, y + 24);
        context.stroke();
      }

      if (!reduceMotion) {
        requestAnimationFrame(draw);
      }
    }

    resize();
    draw();
    window.addEventListener("resize", () => { resize(); draw(); });
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
  <title>公告管理控制台 | ltxiangzi.dpdns.org</title>
  <style>
    ${sharedStyles}
    .admin-layout {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 28px;
      margin-top: 24px;
    }
    @media (max-width: 900px) {
      .admin-layout { grid-template-columns: 1fr; }
    }
    .form-col, .preview-col {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .preview-card {
      position: sticky;
      top: 24px;
      padding: 24px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--paper-strong);
      box-shadow: var(--shadow);
    }
    .preview-title-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--line);
      font-size: 13px;
      font-weight: 700;
      color: var(--muted);
    }
    label {
      display: flex;
      flex-direction: column;
      gap: 6px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }
    input, textarea, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px 12px;
      background: var(--paper-strong);
      color: var(--ink);
      font-family: inherit;
      font-size: 14px;
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    input:focus, textarea:focus {
      outline: none;
      border-color: var(--brand);
      box-shadow: 0 0 0 3px var(--brand-light);
    }
    textarea { min-height: 80px; resize: vertical; line-height: 1.6; }
    .btn-group {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 8px;
    }
    .btn-secondary {
      background: var(--paper-strong);
      border: 1px solid var(--line);
      color: var(--ink);
    }
    .btn-secondary:hover { border-color: var(--brand); }
    .btn-danger {
      background: #ef4444;
      color: white;
      border: none;
    }
    .btn-danger:hover { background: #dc2626; }
    .helper-text { font-size: 11.5px; color: var(--faint); font-weight: normal; margin-top: -2px; }
    .checkbox-row {
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
      font-weight: 600;
      font-size: 13px;
    }
    .checkbox-row input { width: auto; }
  </style>
</head>
<body>
  <div class="wrap">
    <main style="width: min(1080px, 100%);">
      <div class="top-bar">
        <div class="status">管理控制台</div>
        <div style="display: flex; gap: 8px; align-items: center;">
          <a href="/" class="button-link" style="min-height: 36px; padding: 0 12px; font-size: 13px;">返回首页 ↗</a>
          <button type="button" class="theme-toggle" id="theme-toggle" title="切换深/浅色模式">🌓</button>
        </div>
      </div>

      <h1 id="page-title" style="font-size: clamp(26px, 4vw, 38px); margin: 20px 0 8px;">编辑开屏公告与跳转策略</h1>
      <p class="lead" style="font-size: 15px; margin: 0 0 20px;">修改配置后可实时在右侧预览。点击保存将持久化至 Cloudflare KV 存储。</p>

      <div class="admin-layout">
        <!-- 表单列 -->
        <form class="form-col" id="form" novalidate>
          <label>
            管理口令 (ADMIN_TOKEN)
            <input id="token" name="token" type="password" autocomplete="current-password" placeholder="输入 Worker 环境变量 ADMIN_TOKEN" required>
            <span class="helper-text">口令保存在本地浏览器中，用于身份鉴权</span>
          </label>

          <label class="checkbox-row">
            <input type="checkbox" id="remember-token" checked> 记住管理口令 (保存在本设备)
          </label>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
            <label>
              状态徽章
              <input name="badge" placeholder="例：开屏提醒" required>
            </label>
            <label>
              倒计时自动跳转 (秒)
              <input name="autoRedirectSeconds" type="number" min="0" max="120" placeholder="0 表示不自动跳转">
              <span class="helper-text">设为 5 时将显示 5 秒倒计时条</span>
            </label>
          </div>

          <label>
            主标题
            <input name="title" placeholder="例：站点入口正在调整" required>
          </label>

          <label>
            公告正文说明
            <textarea name="message" placeholder="详细公告内容..." required></textarea>
          </label>

          <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 12px;">
            <label>
              状态卡片标题
              <input name="statusTitle" placeholder="当前状态" required>
            </label>
            <label>
              状态卡片内容
              <textarea name="statusText" style="min-height: 50px;" placeholder="原页面状态及进展说明" required></textarea>
            </label>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
            <label>
              主确认按钮文案
              <input name="primaryLabel" placeholder="我已知悉" required>
            </label>
            <label>
              正式站按钮文案
              <input name="officialSiteLabel" placeholder="进入正式站" required>
            </label>
          </div>

          <label>
            正式站链接 (URL)
            <input name="officialSiteHref" type="url" placeholder="https://sevenseven.qzz.io/" required>
          </label>

          <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 12px;">
            <label>
              联系按钮文案
              <input name="contactLabel" placeholder="联系管理员" required>
            </label>
            <label>
              联系链接 (mailto 或 URL)
              <input name="contactHref" placeholder="mailto:2325778716@qq.com" required>
            </label>
          </div>

          <div class="btn-group">
            <button type="submit" class="primary" id="save-btn">保存并发布配置</button>
            <button type="button" class="btn-secondary" id="export-btn">导出 JSON</button>
            <button type="button" class="btn-secondary" id="import-btn">导入 JSON</button>
            <button type="button" class="btn-secondary" id="reset-btn">重置为默认</button>
            <input type="file" id="file-input" accept=".json" style="display: none;">
          </div>
        </form>

        <!-- 实时预览列 -->
        <div class="preview-col">
          <div class="preview-card">
            <div class="preview-title-bar">
              <span>实时效果预览 (所见即所得)</span>
              <span id="preview-update-time">刚刚更新</span>
            </div>
            
            <div class="status" id="pv-badge" style="margin-bottom: 12px;">开屏提醒</div>
            <h2 id="pv-title" style="margin: 0 0 10px; font-size: 24px; font-weight: 800;">站点入口正在调整</h2>
            <p id="pv-message" style="margin: 0 0 16px; color: var(--muted); font-size: 14px; line-height: 1.6;">公告内容预览</p>

            <div class="panel" style="margin-top: 12px; padding: 14px;">
              <strong id="pv-status-title" style="font-size: 13.5px;">当前状态</strong>
              <p id="pv-status-text" style="font-size: 13px;">请稍候。</p>
            </div>

            <div id="pv-redirect-preview" style="display: none; margin-top: 12px; padding: 8px 12px; background: var(--brand-light); border-radius: 6px; font-size: 12px; font-weight: 600;">
              ⚡ 已开启自动跳转：<span id="pv-redirect-sec">5</span> 秒后跳转
            </div>

            <div class="actions" style="margin-top: 18px; gap: 8px;">
              <button type="button" class="primary" id="pv-primary" style="min-height: 38px; padding: 0 14px; font-size: 13px;">我已知悉</button>
              <a class="button-link" id="pv-official" style="min-height: 38px; padding: 0 12px; font-size: 13px;" href="#">进入正式站 ↗</a>
              <a class="button-link" id="pv-contact" style="min-height: 38px; padding: 0 12px; font-size: 13px;" href="#">联系管理员 ✉</a>
            </div>
          </div>
        </div>
      </div>
    </main>
  </div>

  <div class="toast-container" id="toast-container"></div>

  <script>
    // Theme Management
    const themeToggle = document.querySelector("#theme-toggle");
    const savedTheme = localStorage.getItem("site-theme") || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", savedTheme);

    themeToggle.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "light";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("site-theme", next);
      showToast(next === "dark" ? "已切换至深色模式 🌙" : "已切换至浅色模式 ☀️");
    });

    function showToast(msg) {
      const container = document.querySelector("#toast-container");
      const toast = document.createElement("div");
      toast.className = "toast";
      toast.textContent = msg;
      container.appendChild(toast);
      requestAnimationFrame(() => toast.classList.add("show"));
      setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => toast.remove(), 300);
      }, 2500);
    }

    const form = document.querySelector("#form");
    const token = document.querySelector("#token");
    const rememberToken = document.querySelector("#remember-token");

    // Preview elements
    const pvBadge = document.querySelector("#pv-badge");
    const pvTitle = document.querySelector("#pv-title");
    const pvMessage = document.querySelector("#pv-message");
    const pvStatusTitle = document.querySelector("#pv-status-title");
    const pvStatusText = document.querySelector("#pv-status-text");
    const pvPrimary = document.querySelector("#pv-primary");
    const pvOfficial = document.querySelector("#pv-official");
    const pvContact = document.querySelector("#pv-contact");
    const pvRedirectPreview = document.querySelector("#pv-redirect-preview");
    const pvRedirectSec = document.querySelector("#pv-redirect-sec");

    function updateLivePreview() {
      const fd = new FormData(form);
      pvBadge.textContent = fd.get("badge") || "开屏提醒";
      pvTitle.textContent = fd.get("title") || "主标题";
      pvMessage.textContent = fd.get("message") || "正文内容...";
      pvStatusTitle.textContent = fd.get("statusTitle") || "当前状态";
      pvStatusText.textContent = fd.get("statusText") || "状态描述...";
      pvPrimary.textContent = fd.get("primaryLabel") || "确认";
      pvOfficial.textContent = (fd.get("officialSiteLabel") || "进入正式站") + " ↗";
      pvContact.textContent = (fd.get("contactLabel") || "联系管理员") + " ✉";

      const rSec = parseInt(fd.get("autoRedirectSeconds"), 10);
      if (rSec > 0) {
        pvRedirectPreview.style.display = "block";
        pvRedirectSec.textContent = rSec;
      } else {
        pvRedirectPreview.style.display = "none";
      }
    }

    form.addEventListener("input", updateLivePreview);

    function fillForm(config) {
      for (const [key, value] of Object.entries(config)) {
        const field = form.elements.namedItem(key);
        if (field) {
          field.value = value;
        }
      }
      const savedToken = localStorage.getItem("ltxiangzi-admin-token");
      if (savedToken) {
        token.value = savedToken;
      }
      updateLivePreview();
    }

    // Load initial config
    fetch("/api/config")
      .then(res => res.json())
      .then(config => {
        fillForm(config);
        showToast("已成功载入最新配置 ⚡");
      })
      .catch(() => showToast("配置读取失败，请检查网络"));

    // Save Form
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const data = Object.fromEntries(new FormData(form));
      const adminToken = (data.token || "").trim();
      delete data.token;

      if (!adminToken) {
        showToast("请输入管理口令后再保存");
        token.focus();
        return;
      }

      if (rememberToken.checked) {
        localStorage.setItem("ltxiangzi-admin-token", adminToken);
      } else {
        localStorage.removeItem("ltxiangzi-admin-token");
      }

      const saveBtn = document.querySelector("#save-btn");
      saveBtn.disabled = true;
      saveBtn.textContent = "正在保存中...";

      try {
        const res = await fetch("/api/config", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "authorization": "Bearer " + adminToken
          },
          body: JSON.stringify(data)
        });

        const result = await res.json();
        if (!res.ok) {
          showToast(res.status === 401 ? "口令错误或未配置环境变量 ADMIN_TOKEN 🔒" : "保存失败：" + (result.message || "未知错误"));
          return;
        }

        fillForm(result.config || result);
        showToast("✓ 配置保存成功，首页已即时生效！");
      } catch (err) {
        showToast("网络请求异常，请稍后重试");
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = "保存并发布配置";
      }
    });

    // Export JSON
    document.querySelector("#export-btn").addEventListener("click", () => {
      const data = Object.fromEntries(new FormData(form));
      delete data.token;
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "ltxiangzi-config-" + new Date().toISOString().slice(0, 10) + ".json";
      a.click();
      URL.revokeObjectURL(url);
      showToast("配置文件已导出下载 📥");
    });

    // Import JSON
    const fileInput = document.querySelector("#file-input");
    document.querySelector("#import-btn").addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (event) => {
        try {
          const imported = JSON.parse(event.target.result);
          fillForm(imported);
          showToast("已成功导入配置，点击保存即可生效 📋");
        } catch (err) {
          showToast("JSON 格式无效，导入失败");
        }
      };
      reader.readAsText(file);
    });

    // Reset to Defaults
    document.querySelector("#reset-btn").addEventListener("click", () => {
      if (confirm("确定要恢复默认公告配置吗？（需要点击保存才会生效）")) {
        fillForm(${JSON.stringify(defaultConfig)});
        showToast("已重置为默认模板，请确认后点击保存");
      }
    });
  </script>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/config") {
      return handleConfig(request, env);
    }

    if (url.pathname === "/admin") {
      return htmlResponse(adminPage());
    }

    if (url.pathname === "/health" || url.pathname === "/ping") {
      return jsonResponse({ status: "ok", service: "ltxiangzi-splash", timestamp: Date.now() });
    }

    return htmlResponse(publicPage());
  }
};
