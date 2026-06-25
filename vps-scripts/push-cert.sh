#!/bin/bash
# =============================================================================
# push-cert.sh — VPS SSL 证书推送脚本
# 功能：将本机续签的 SSL 证书推送到 r2-file-share 网盘，供下游 VPS 统一拉取
#
# 用法（acme.sh hook）：
#   acme.sh --issue -d yourdomain.com \
#     --reloadcmd "DOMAIN=yourdomain.com bash /opt/push-cert.sh"
#
# 用法（Certbot post-hook）：
#   certbot renew --post-hook "DOMAIN=yourdomain.com bash /opt/push-cert.sh"
#
# 用法（手动触发）：
#   DOMAIN=yourdomain.com bash /opt/push-cert.sh
#
# 环境变量（必须设置，建议写入 /etc/push-cert.env）：
#   WORKER_URL       —— Worker 地址，例如 https://r2-file-share.xxx.workers.dev
#   CERT_PUSH_TOKEN  —— 在 Cloudflare 配置的推送 Token
#   DOMAIN           —— 要推送的域名，例如 yourdomain.com
# =============================================================================

set -euo pipefail

WORKER_URL="${WORKER_URL:-https://r2-file-share.your-subdomain.workers.dev}"
CERT_PUSH_TOKEN="${CERT_PUSH_TOKEN:-}"
DOMAIN="${DOMAIN:-}"

# ---- 检查必填参数 ----
if [[ -z "$WORKER_URL" || "$WORKER_URL" == *"your-subdomain"* ]]; then
  echo "[push-cert] ERROR: WORKER_URL 未配置" >&2; exit 1
fi
if [[ -z "$CERT_PUSH_TOKEN" ]]; then
  echo "[push-cert] ERROR: CERT_PUSH_TOKEN 未配置" >&2; exit 1
fi
if [[ -z "$DOMAIN" ]]; then
  echo "[push-cert] ERROR: DOMAIN 未配置" >&2; exit 1
fi

# ---- 自动识别证书路径（acme.sh ECC / RSA / Certbot）----
if [[ -f "$HOME/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.cer" ]]; then
  CERT_SOURCE="acme_ecc"
  CERT_DIR="$HOME/.acme.sh/${DOMAIN}_ecc"
  FULLCHAIN_FILE="${CERT_DIR}/fullchain.cer"
  PRIVKEY_FILE="${CERT_DIR}/${DOMAIN}.key"
  CERT_FILE="${CERT_DIR}/${DOMAIN}.cer"
elif [[ -f "$HOME/.acme.sh/${DOMAIN}/${DOMAIN}.cer" ]]; then
  CERT_SOURCE="acme_rsa"
  CERT_DIR="$HOME/.acme.sh/${DOMAIN}"
  FULLCHAIN_FILE="${CERT_DIR}/fullchain.cer"
  PRIVKEY_FILE="${CERT_DIR}/${DOMAIN}.key"
  CERT_FILE="${CERT_DIR}/${DOMAIN}.cer"
elif [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
  CERT_SOURCE="certbot"
  FULLCHAIN_FILE="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  PRIVKEY_FILE="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
  CERT_FILE="/etc/letsencrypt/live/${DOMAIN}/cert.pem"
else
  echo "[push-cert] ERROR: 找不到 ${DOMAIN} 的证书文件" >&2; exit 1
fi

echo "[push-cert] 来源: ${CERT_SOURCE}, 域名: ${DOMAIN}"

# ---- 检查依赖 ----
if ! command -v jq &>/dev/null; then
  echo "[push-cert] ERROR: 需要安装 jq（apt install jq / yum install jq）" >&2; exit 1
fi

# ---- 读取 PEM 文件并构造 JSON（jq 转义换行符）----
FULLCHAIN_JSON=$(jq -Rs . < "$FULLCHAIN_FILE")
PRIVKEY_JSON=$(jq -Rs . < "$PRIVKEY_FILE")
CERT_JSON=$(jq -Rs . < "$CERT_FILE")

PAYLOAD=$(printf '{"domain":"%s","fullchain":%s,"privkey":%s,"cert":%s}' \
  "$DOMAIN" "$FULLCHAIN_JSON" "$PRIVKEY_JSON" "$CERT_JSON")

# ---- 推送到 Worker ----
echo "[push-cert] 正在推送到 ${WORKER_URL}/api/cert-push ..."

RESPONSE=$(curl -sS -w "\n%{http_code}" \
  -X POST "${WORKER_URL}/api/cert-push" \
  -H "Content-Type: application/json" \
  -H "X-Cert-Token: ${CERT_PUSH_TOKEN}" \
  --data-raw "$PAYLOAD" \
  --max-time 30)

HTTP_BODY=$(echo "$RESPONSE" | head -n -1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

if [[ "$HTTP_CODE" == "200" ]]; then
  echo "[push-cert] ✅ 推送成功 (HTTP ${HTTP_CODE})"
  echo "[push-cert] 响应: ${HTTP_BODY}"
else
  echo "[push-cert] ❌ 推送失败 (HTTP ${HTTP_CODE}): ${HTTP_BODY}" >&2
  exit 1
fi
