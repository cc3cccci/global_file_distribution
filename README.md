# R2 File Distribution System (基于 Cloudflare Workers + R2 的网盘与文件分发系统)

本项目是一个轻量、快速、安全的网盘与文件分发系统，依托于 **Cloudflare Workers** 无服务器架构和 **Cloudflare R2** 廉价对象存储。除了常规的网盘管理功能外，它还特别针对**订阅文件自动同步（GeoIP/Geosite 等）**以及**多 VPS SSL 证书共享与分发**设计了专用的自动化工具。

---

## 🌟 核心功能

1. **网盘基础管理**
   * 支持文件列表展示、多级目录文件夹创建。
   * 支持重命名、移动文件（智能映射标签及分享状态）。
   * 级联删除文件夹（自动递归删除该目录下的所有对象）。

2. **超大文件分片流式上传**
   * 针对 Worker 的 128MB 内存和时间限制，实现了分片流式上传接口（`upload-init` -> `upload-part` -> `upload-complete`）。
   * 网页端直接分片上传大文件，数据直接流向 R2，不占用 Worker 进程内存，稳定可靠。

3. **三维一体安全下载机制**
   * **控制台直连**：管理员登录状态下，通过防盗链 Referer 校验直接下载。
   * **时效性分享链接**：支持生成 10 分钟有效的 HMAC 加密预签名下载链接，过期自动失效。
   * **永久公开链接**：可为特定文件（如 GeoIP 规则包、一键安装脚本）开启公开分享，通过 `https://<your-domain>/f/<filename>` 供外部软路由、VPS 零鉴权拉取，并自动禁用浏览器缓存确保拉取最新文件。

4. **订阅同步与历史版本管理**
   * **定时拉取更新**：配置外部公开的 URL（如 GitHub Release 最新包），由 Cloudflare Cron Triggers 定时任务（每天自动执行）拉取并保存到 R2 中。
   * **版本归档**：每次更新时自动将旧版本保存到 `.history/` 目录下。
   * **版本管理**：支持锁定（Pin）特定历史版本以防止被自动清理或意外删除，支持历史版本的一键回滚和清理。

5. **多 VPS 证书推送与共享分发 (新增)**
   * **独立安全令牌**：采用专用的 `CERT_PUSH_TOKEN`，与网盘管理员主密码隔离，权限最小化。
   * **上游 VPS 推送**：支持 `acme.sh` 或 `Certbot` 在证书续签完成后，通过 Web Hook 自动将最新的证书推送至网盘。
   * **下游 VPS 自动部署**：下游需要使用证书的 VPS 只需执行一键命令，即可拉取最新证书、保存持久化脚本并自动配置每日定时同步任务（cron），支持证书更新后自动重载（Reload）服务（Nginx/Caddy 等）。

---

## 🏗 架构设计

```
                         ┌─────────────────────────────┐
                         │      Web UI 管理控制台       │
                         └──────────────┬──────────────┘
                                        │ (密码认证 / HMAC 签名)
                                        ▼
  ┌─────────────────┐        ┌─────────────────────┐        ┌──────────────────┐
  │   上游 VPS      ├───────>│  Cloudflare Worker  │<───────┤  下游 VPS / 设备 │
  │ (acme.sh/Certbot│ 推送   │     (index.js)      │ 拉取   │ (软路由/Web服务) │
  └─────────────────┘        └──────────┬──────────┘        └──────────────────┘
                                        │
                                        ▼ (流式读写)
                             ┌─────────────────────┐
                             │    Cloudflare R2    │
                             │ (my-share-files 桶)  │
                             └─────────────────────┘
```

---

## ⚙️ 部署与配置

### 1. 基础配置 (`wrangler.toml`)
项目使用 `wrangler` 工具进行部署和管理。你需要配置你的 R2 存储桶名：

```toml
name = "r2-file-share"
main = "index.js"
compatibility_date = "2024-03-01"

rules = [
  { type = "Text", globs = ["**/*.html"], fallthrough = false }
]

[[r2_buckets]]
binding = "BUCKET"
bucket_name = "my-share-files" # 替换为你在 Cloudflare 创建的 R2 Bucket 名称

[triggers]
crons = ["0 4 * * *"] # 每天 UTC 时间凌晨 4:00 自动执行外部文件同步任务
```

### 2. 机密变量设置 (Secrets)
为了安全起见，所有鉴权密钥不得写入代码或 `wrangler.toml` 中，必须通过 Cloudflare Secrets 进行加密配置。

在项目根目录下执行以下命令设置密钥：

```bash
# 1. 设置网盘管理员主密码 (登录 Web UI 使用)
npx wrangler secret put AUTH_PASSWORD

# 2. 设置用于生成 HMAC 签名分享链接的密钥 (可以是任意强随机字符串)
npx wrangler secret put SECRET_KEY

# 3. 设置 VPS SSL 证书共享的专属 Token (与管理员密码分离)
npx wrangler secret put CERT_PUSH_TOKEN
```

### 3. 一键部署 Worker
```bash
npm run deploy
# 或者使用 wrangler 命令直接部署
npx wrangler deploy
```

---

## 🔐 SSL 证书共享部署方案说明

通过本项目，您可以方便地将一台 VPS 上通过 `acme.sh` 或 `Certbot` 申请的 SSL 证书，分发到多台下游 VPS 或软路由上。

### 1. 上游 VPS（证书推送端）部署
在申请了证书的 VPS 上，放置 `vps-scripts/push-cert.sh` 脚本（建议放于 `/opt/push-cert.sh`）。

**配置环境变量 `/etc/push-cert.env`**：
```bash
WORKER_URL="https://files.yourdomain.com"
CERT_PUSH_TOKEN="你在 Cloudflare Workers 配置的 Token"
```

**配置证书续签 Hook**：
* **acme.sh**：
  ```bash
  acme.sh --install-cert -d yourdomain.com \
    --reloadcmd "source /etc/push-cert.env && DOMAIN=yourdomain.com bash /opt/push-cert.sh"
  ```
* **Certbot**：
  ```bash
  certbot renew --post-hook "source /etc/push-cert.env && DOMAIN=yourdomain.com bash /opt/push-cert.sh"
  ```

### 2. 下游 VPS（证书拉取与定时同步端）部署
在下游机器上，你可以直接利用一键安装脚本完成部署：

```bash
# 首次运行一键脚本（会自动下载脚本至 /opt/pull-cert.sh 并注册每日凌晨 3 点的自动同步 cron）
RELOAD_CMD="systemctl reload nginx" curl -sS https://<你的网盘域名>/f/scripts/pull-cert.sh | bash
```

运行后，拉取的证书文件将保存在 `/etc/ssl/certs/1381799.xyz/`。

---

## 📡 API 路由列表

### 公共/匿名接口
* `GET /` 或 `/index.html`：访问网盘前端控制面板。
* `POST /api/auth`：密码登录验证。
* `GET /f/<key>`：获取设置为「公开」的文件，支持直接用 wget/curl 流式下载。
* `GET /api/download`：流式文件下载接口（包含 HMAC 时效验证或直连鉴权）。

### SSL 证书专用接口
* `POST /api/cert-push`：VPS 推送证书，Header 携带 `X-Cert-Token`。
* `GET /api/cert-pull`：下游 VPS 拉取证书，限制只读白名单内的证书文件。

### 管理员专用接口（Header 需携带 `Authorization: <AUTH_PASSWORD>`）
* `GET /api/list`：获取网盘内所有文件的对象列表。
* `POST /api/create-folder`：创建空白文件夹。
* `DELETE /api/delete?key=<key>`：级联删除文件或文件夹。
* `POST /api/rename`：重命名或移动文件。
* `GET /api/share?key=<key>`：生成 10 分钟有效的临时分享链接。
* `POST /api/public-toggle`：切换某个文件的公开分享状态。
* `POST /api/upload-init` / `upload-part` / `upload-complete`：超大文件分片流式上传。
* `GET /api/sync-config` / `POST /api/sync-config`：管理订阅自动同步列表。
* `POST /api/sync-now`：立即触发订阅文件拉取同步。
* `GET /api/sync-history` / `DELETE /api/sync-history`：管理订阅历史版本。
* `POST /api/sync-history/pin`：锁定/解锁特定历史版本防止被清理。
