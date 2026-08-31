# Cloudflare Splash Reminder (`ltxiangzi-splash-reminder`)

基于 Cloudflare Workers + KV 构建的高性能开屏公告提醒门禁服务。用于在域名（`ltxiangzi.dpdns.org`）过渡、维护或重要通告期间接管流量，提供访问前告知与跳转引导。

---

## ✨ 核心特性

- 🚀 **极速边缘计算**：基于 Cloudflare Workers 全球边缘网络，响应时间低于 15ms。
- 📦 **KV 动态持久化**：无需重新部署代码，在管理后台修改公告即可实时全网生效。
- 🌓 **深浅色主题自适应**：支持跟随系统偏好，并提供手动切换按钮与本地记忆。
- ⚙️ **双栏所见即所得管理后台**（`/admin`）：
  - 实时表单与右侧高保真预览同步联动。
  - 支持配置导出 JSON 备份与一键导入恢复。
  - 支持一键恢复官方默认模板。
- ⚡ **智能倒计时自动跳转**：支持在后台配置 0~120 秒倒计时跳转至正式站，并提供用户“取消跳转”按钮。
- 🔒 **多重安全加固**：
  - 常量时间安全比对（`crypto.subtle.timingSafeEqual`），防止时序攻击。
  - 注入 CSP、X-Frame-Options、X-Content-Type-Options 等安全响应头。
  - 严格的 XSS 清洗与 URL 校验。

---

## 🛠️ 本地开发与调试

### 1. 安装依赖

```bash
npm install
```

### 2. 启动本地模拟环境

```bash
npm run dev
```

启动后可访问：
- 前台页面：`http://127.0.0.1:8787/`
- 管理控制台：`http://127.0.0.1:8787/admin`
- 健康检查：`http://127.0.0.1:8787/health`
- 配置接口：`http://127.0.0.1:8787/api/config`

---

## 🚀 部署指引

### 1. 配置 Wrangler 与 KV 命名空间

确认 `wrangler.jsonc` 中的 KV 配置：

```jsonc
"kv_namespaces": [
  {
    "binding": "SITE_CONFIG",
    "id": "be07ab11588842e2a7169270d32ce3ea"
  }
]
```

### 2. 设置管理口令秘钥（环境变量）

在 Cloudflare 命令行中配置后台管理密码：

```bash
npx wrangler secret put ADMIN_TOKEN
```
根据提示输入你的专属口令（例如 `MySecureToken2026!`）。

### 3. 一键发布

```bash
npm run deploy
```

---

## 📡 API 接口说明

### `GET /api/config`
获取当前生效的公告配置 JSON 数据。

### `POST /api/config`
更新公告配置（需要提供管理员口令）。

- **Headers**:
  - `Authorization: Bearer <ADMIN_TOKEN>` 或 `X-Admin-Token: <ADMIN_TOKEN>`
  - `Content-Type: application/json`
- **Request Body 示例**:
  ```json
  {
    "badge": "开屏提醒",
    "title": "站点入口调整",
    "message": "公告内容...",
    "statusTitle": "当前状态",
    "statusText": "系统正常运行",
    "primaryLabel": "我已知悉",
    "officialSiteLabel": "进入正式站",
    "officialSiteHref": "https://sevenseven.qzz.io/",
    "contactLabel": "联系管理员",
    "contactHref": "mailto:2325778716@qq.com",
    "autoRedirectSeconds": 0
  }
  ```

---

## 📄 开源与维护

- **作者**：Sevenseven
- **平台**：Cloudflare Workers

