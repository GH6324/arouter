#!/usr/bin/env bash
set -euo pipefail

# 一键安装最新 arouter controller（从 GitHub Releases 下载二进制），创建 systemd 服务并启动。

REPO="NiuStar/arouter"
INSTALL_DIR="/opt/arouter/controller"
SERVICE_NAME="arouter-controller"
read -r -p "请输入控制器监听端口（回车默认为 8080）: " PORT_INPUT
PORT="${PORT_INPUT:-${PORT:-8080}}"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "缺少依赖: $1"; exit 1; }; }
need_cmd curl
need_cmd uname
need_cmd tar

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  echo "获取最新版本号..."
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]\+\)".*/\1/p')
fi
if [ -z "$VERSION" ]; then
  echo "无法获取版本号，请手动设置环境变量 VERSION"
  exit 1
fi

BIN_URL="https://github.com/${REPO}/releases/download/${VERSION}/arouter-controller-${OS}-${ARCH}"
TMP_BIN=$(mktemp)

echo "停止并清理旧服务（如存在）..."
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"

echo "下载 ${BIN_URL} ..."
curl -fL "$BIN_URL" -o "$TMP_BIN"
chmod +x "$TMP_BIN"

WEB_DIST_DIR="${INSTALL_DIR}/web/dist"
WEB_TAR_URL="https://github.com/${REPO}/releases/download/${VERSION}/web-dist.tar.gz"
TMP_TAR=$(mktemp)
echo "尝试下载前端资源 ${WEB_TAR_URL} ..."
if curl -fL "$WEB_TAR_URL" -o "$TMP_TAR"; then
  echo "解压前端到 ${WEB_DIST_DIR} ..."
  rm -rf "${WEB_DIST_DIR}"
  mkdir -p "${INSTALL_DIR}/web"
  tar -xzf "$TMP_TAR" -C "${INSTALL_DIR}/web"
else
  echo "未找到前端资源（可能未随 Release 发布），如需本地前端请手动放置到 ${WEB_DIST_DIR}"
fi
rm -f "$TMP_TAR"

echo "安装到 ${INSTALL_DIR} ..."
mkdir -p "${INSTALL_DIR}"
mv "$TMP_BIN" "${INSTALL_DIR}/arouter-controller"
ln -sf "${INSTALL_DIR}/arouter-controller" /usr/local/bin/arouter-controller

DB_PATH="${INSTALL_DIR}/data/arouter.db"
mkdir -p "${INSTALL_DIR}/data"

UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
WEB_DIST="${WEB_DIST:-${INSTALL_DIR}/web/dist}"
echo "写入 systemd 服务 ${UNIT_FILE} ..."
cat > "$UNIT_FILE" <<EOF
[Unit]
Description=ARouter Controller
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/local/bin/arouter-controller
Environment=CONTROLLER_ADDR=:${PORT}
Environment=DB_PATH=${DB_PATH}
Environment=WEB_DIST=${WEB_DIST}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

echo "已启动 ${SERVICE_NAME}，监听端口 ${PORT}"
IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9a-fA-F:.]+$' || true)
if [ -z "$IPS" ]; then
  echo "访问地址: http://<你的IP>:${PORT}"
else
  echo "可访问地址："
  echo "$IPS" | while read -r ip; do
    echo "  http://${ip}:${PORT}"
  done
fi
echo "首次登录请在前端页面完成用户注册/登录。"
