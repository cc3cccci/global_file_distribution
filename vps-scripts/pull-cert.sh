#!/bin/bash
# =============================================================================
# pull-cert.sh — 下游 VPS 从网盘拉取 SSL 证书脚本
# 功能：从 r2-file-share 网盘下载最新证书，并自动重载 nginx/caddy/haproxy
#
# 用法：
#   bash pull-cert.sh yourdomain.com /etc/nginx/ssl
#
# 或通过环境变量：
#   DOMAIN=yourdomain.com CERT_DIR=/etc/nginx/ssl bash pull-cert.sh
#
# 参数（命令行 或 环境变量，二选一）：
#   $1 / DOMAIN      —— 证书对应的域名
#   $2 / CERT_DIR    —— 本地存放证书的目录（默认 /etc/ssl/certs/<domain>）
#
# 环境变量（必须设置）：
#   WORKER_URL       —— Worker 地址，例如 https://r2-file-share.xxx.workers.dev
#   CERT_PUSH_TOKEN  —— 用于下载验证的 Token（同 push Token，走 /api/cert-pull 接口）
#
# 可选环境变量：
#   RELOAD_CMD          —— 证书更新后自动重载服务命令，例如 "systemctl reload nginx"
#   SCRIPT_INSTALL_PATH —— 脚本安装路径（默认 /opt/pull-cert.sh）
#   CRON_HOUR           —— 每天定时拉取的小时数（默认 3，即凌晨 3 点）
#   AUTO_INSTALL        —— 是否自动安装并设置定时任务（默认 true）
# =============================================================================

set -euo pipefail

DOMAIN="${1:-${DOMAIN:-}}"
CERT_DIR="${2:-${CERT_DIR:-}}"
WORKER_URL="${WORKER_URL:-}"
CERT_PUSH_TOKEN="${CERT_PUSH_TOKEN:-}"
RELOAD_CMD="${RELOAD_CMD:-}"

SCRIPT_INSTALL_PATH="${SCRIPT_INSTALL_PATH:-/opt/pull-cert.sh}"
CRON_HOUR="${CRON_HOUR:-3}"
AUTO_INSTALL="${AUTO_INSTALL:-true}"

# ---- 检查必填参数 ----
if [[ -z "$DOMAIN" ]]; then
  echo "[pull-cert] 用法: $0 <domain> [cert_dir]" >&2
  echo "[pull-cert] 例如: $0 yourdomain.com /etc/nginx/ssl" >&2
  exit 1
fi
if [[ -z "$WORKER_URL" ]]; then
  echo "[pull-cert] ERROR: WORKER_URL 未配置" >&2; exit 1
fi
if [[ -z "$CERT_PUSH_TOKEN" ]]; then
  echo "[pull-cert] ERROR: CERT_PUSH_TOKEN 未配置" >&2; exit 1
fi

# 默认证书存放目录
if [[ -z "$CERT_DIR" ]]; then
  CERT_DIR="/etc/ssl/certs/${DOMAIN}"
fi

# ======== 步骤 1：拉取证书 ========
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

echo "[pull-cert] 域名: ${DOMAIN}"
echo "[pull-cert] 本地目录: ${CERT_DIR}"

download_cert_file() {
  local filename="$1"
  local r2_key="certs/${DOMAIN}/${filename}"
  local local_path="${CERT_DIR}/${filename}"

  echo "[pull-cert] 下载 ${r2_key} ..."

  HTTP_CODE=$(curl -sS -o "$local_path" -w "%{http_code}" \
    -H "X-Cert-Token: ${CERT_PUSH_TOKEN}" \
    "${WORKER_URL}/api/cert-pull?domain=${DOMAIN}&file=${filename}" \
    --max-time 30)

  if [[ "$HTTP_CODE" == "200" ]]; then
    # 私钥权限收紧为 600
    if [[ "$filename" == "privkey.pem" ]]; then
      chmod 600 "$local_path"
    else
      chmod 644 "$local_path"
    fi
    echo "[pull-cert] ✅ ${filename} 已保存到 ${local_path}"
  else
    echo "[pull-cert] ❌ 下载 ${filename} 失败 (HTTP ${HTTP_CODE})" >&2
    rm -f "$local_path"
    return 1
  fi
}

UPDATED=0
download_cert_file "fullchain.pem" && UPDATED=$((UPDATED+1))
download_cert_file "privkey.pem"   && UPDATED=$((UPDATED+1))
download_cert_file "cert.pem"      && UPDATED=$((UPDATED+1))

echo "[pull-cert] 共更新 ${UPDATED}/3 个文件"

# ---- 可选：重载 Web 服务 ----
if [[ -n "$RELOAD_CMD" && $UPDATED -gt 0 ]]; then
  echo "[pull-cert] 执行重载命令: ${RELOAD_CMD}"
  eval "$RELOAD_CMD" && echo "[pull-cert] ✅ 服务重载成功" || echo "[pull-cert] ⚠️ 服务重载失败，请手动检查" >&2
fi

# ======== 步骤 2：保存脚本自身到指定目录（仅在开启自动安装时） ========
if [[ "$AUTO_INSTALL" == "true" ]]; then
  if [[ ! -f "$SCRIPT_INSTALL_PATH" ]]; then
    echo "[pull-cert] ▶ 安装脚本到 ${SCRIPT_INSTALL_PATH} ..."
    curl -sS "${WORKER_URL}/f/scripts/pull-cert.sh" \
      -o "$SCRIPT_INSTALL_PATH" --max-time 15
    chmod +x "$SCRIPT_INSTALL_PATH"
    echo "[pull-cert] ✅ 脚本已安装到 ${SCRIPT_INSTALL_PATH}"
  else
    echo "[pull-cert] ℹ️ 脚本已存在：${SCRIPT_INSTALL_PATH}（跳过安装）"
  fi

  # ======== 步骤 3：注册 cron 定时任务 ========
  # 拼装带有正确环境变量的定时任务，以保证 cron 执行时能找到配置
  CRON_JOB="0 ${CRON_HOUR} * * * WORKER_URL=\"${WORKER_URL}\" CERT_PUSH_TOKEN=\"${CERT_PUSH_TOKEN}\" DOMAIN=\"${DOMAIN}\" CERT_DIR=\"${CERT_DIR}\" RELOAD_CMD=\"${RELOAD_CMD}\" bash ${SCRIPT_INSTALL_PATH} >> /var/log/pull-cert.log 2>&1"
  CRON_MARKER="pull-cert.sh"

  if crontab -l 2>/dev/null | grep -q "$CRON_MARKER"; then
    echo "[pull-cert] ℹ️ cron 任务已存在（跳过注册）"
  else
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo "[pull-cert] ✅ cron 已注册：每天 ${CRON_HOUR}:00 自动同步"
  fi
fi

echo "[pull-cert] 完成"
