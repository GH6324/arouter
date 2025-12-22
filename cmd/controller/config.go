package main

import (
	"fmt"
	"sort"
	"strings"
)

func buildConfig(node Node, allNodes []Node, globalKey string, controllerBase string, settings Setting) ConfigResponse {
	wsMap := make(map[string]string, len(allNodes))
	for _, n := range allNodes {
		normalizeNodePorts(&n)
		// 若全局传输为 wss，则优先使用节点的 wss 监听端口
		if strings.EqualFold(settings.Transport, "wss") && strings.TrimSpace(n.WSSListen) != "" {
			wsMap[n.Name] = n.WSSListen
		} else {
			wsMap[n.Name] = defaultIfEmpty(n.WSListen, "18080")
		}
	}
	peers := make(map[string]string, len(node.Peers))
	for _, p := range node.Peers {
		if p.PeerName != "" {
			ws := wsMap[p.PeerName]
			if ws == "" {
				ws = "18080"
			}
			host := p.EntryIP
			if host == "" {
				host = p.PeerName
			}
			// IPv6需加[]
			if strings.Contains(host, ":") && !strings.Contains(host, "[") {
				host = "[" + host + "]"
			}
			port := ""
			if strings.HasPrefix(ws, ":") {
				port = strings.TrimPrefix(ws, ":")
			} else if strings.Contains(ws, ":") {
				parts := strings.Split(ws, ":")
				port = parts[len(parts)-1]
			} else {
				port = ws
			}
			if port == "" {
				port = "18080"
			}
			// 仅返回 host:port，由节点按 transport 组装协议
			peers[p.PeerName] = fmt.Sprintf("%s:%s", host, port)
		}
	}
	entries := make([]EntryConfig, 0, len(node.Entries))
	for _, e := range node.Entries {
		e.Listen = stripPortPrefix(e.Listen)
		entries = append(entries, EntryConfig{
			Listen: e.Listen,
			Proto:  defaultIfEmpty(e.Proto, "tcp"),
			Exit:   e.Exit,
			Remote: e.Remote,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Listen != entries[j].Listen {
			return entries[i].Listen < entries[j].Listen
		}
		if entries[i].Proto != entries[j].Proto {
			return entries[i].Proto < entries[j].Proto
		}
		if entries[i].Exit != entries[j].Exit {
			return entries[i].Exit < entries[j].Exit
		}
		return entries[i].Remote < entries[j].Remote
	})
	routes := make([]RouteConfig, 0, len(node.Routes))
	for _, r := range node.Routes {
		routes = append(routes, RouteConfig{
			Name:       r.Name,
			Exit:       r.Exit,
			Remote:     r.Remote,
			Priority:   r.Priority,
			Path:       []string(r.Path),
			ReturnPath: []string(r.ReturnPath),
		})
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Priority == routes[j].Priority {
			return routes[i].Name < routes[j].Name
		}
		return routes[i].Priority < routes[j].Priority
	})
	memLimit := node.MemLimit
	if strings.TrimSpace(memLimit) == "" {
		memLimit = "256MiB"
	}
	return ConfigResponse{
		ID:               node.Name,
		WSListen:         defaultIfEmpty(stripPortPrefix(node.WSListen), "18080"),
		WSSListen:        stripPortPrefix(node.WSSListen),
		QUICListen:       defaultIfEmpty(stripPortPrefix(node.QUICListen), stripPortPrefix(node.WSListen)),
		QUICServerName:   defaultIfEmpty(node.QUICServerName, "arouter.529851.xyz"),
		Peers:            peers,
		Entries:          entries,
		PollPeriod:       defaultIfEmpty(node.PollPeriod, "5s"),
		InsecureSkipTLS:  true,
		AuthKey:          firstNonEmpty(globalKey, node.AuthKey, randomKey()),
		MetricsListen:    defaultIfEmpty(stripPortPrefix(node.MetricsListen), "19090"),
		RerouteAttempts:  defaultInt(node.RerouteAttempts, 3),
		UDPSessionTTL:    defaultIfEmpty(node.UDPSessionTTL, "60s"),
		MTLSCert:         defaultIfEmpty(node.MTLSCert, "/opt/arouter/certs/arouter.crt"),
		MTLSKey:          defaultIfEmpty(node.MTLSKey, "/opt/arouter/certs/arouter.key"),
		MTLSCA:           node.MTLSCA,
		ControllerURL:    defaultIfEmpty(node.ControllerURL, controllerBase),
		Routes:           routes,
		Compression:      defaultIfEmpty(settings.Compression, "gzip"),
		CompressionMin:   defaultInt(settings.CompressionMin, node.CompressionMin),
		Transport:        defaultIfEmpty(settings.Transport, "quic"),
		DebugLog:         settings.DebugLog,
		TokenPath:        "/opt/arouter/.token",
		OS:               node.OSName,
		Arch:             node.Arch,
		HTTPProbeURL:     settings.HTTPProbeURL,
		ReturnAckTimeout: defaultIfEmpty(settings.ReturnAckTimeout, "10s"),
		Encryption:       settings.EncryptionPolicies,
		MaxMuxStreams:    defaultInt(settings.MaxMuxStreams, node.MaxMuxStreams),
		MuxMaxAge:        node.MuxMaxAge,
		MuxMaxIdle:       node.MuxMaxIdle,
		MemLimit:         memLimit,
	}
}

func renderConfigPullScript(installDir, configURL, token, proxy string) string {
	if strings.TrimSpace(installDir) == "" {
		installDir = "/opt/arouter"
	}
	content := strings.ReplaceAll(configPullTemplate, "__INSTALL_DIR__", installDir)
	content = strings.ReplaceAll(content, "__CONFIG_URL__", configURL)
	content = strings.ReplaceAll(content, "__TOKEN__", token)
	content = strings.ReplaceAll(content, "__PROXY_PREFIX__", proxy)
	return content
}

func installScript(configJSON string, configURL string, configPullBase string, binBase string, syncInterval string) string {
	script := `#!/usr/bin/env bash
set -euo pipefail

ensure_jq() {
  if command -v jq >/dev/null 2>&1; then
    return 0
  fi
  SUDO=""
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  fi
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -y >/dev/null 2>&1 || true
    $SUDO apt-get install -y jq >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    $SUDO yum install -y jq >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y jq >/dev/null 2>&1 || true
  elif command -v apk >/dev/null 2>&1; then
    $SUDO apk add --no-cache jq >/dev/null 2>&1 || true
  elif command -v brew >/dev/null 2>&1; then
    brew install jq >/dev/null 2>&1 || true
  fi
}

ensure_jq

NAME="arouter-node"
HOME_SAFE="${HOME:-}"
if [ -z "$HOME_SAFE" ]; then HOME_SAFE="$(eval echo ~${SUDO_USER:-$USER} 2>/dev/null || true)"; fi
if [ -z "$HOME_SAFE" ]; then HOME_SAFE="$(cd ~ 2>/dev/null && pwd || echo /tmp)"; fi
INSTALL_DIR_DEFAULT="/opt/arouter"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" = "darwin" ]; then INSTALL_DIR_DEFAULT="${HOME_SAFE}/.arouter"; fi
INSTALL_DIR="${INSTALL_DIR:-$INSTALL_DIR_DEFAULT}"
TOKEN=""
GITHUB_REPO="NiuStar/arouter"
ARCH=$(uname -m)
PROXY_PREFIX="${PROXY_PREFIX:-}"
if [ -n "$PROXY_PREFIX" ]; then
  PROXY_PREFIX="${PROXY_PREFIX%/}/"
fi

map_arch() {
  case "$1" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "unsupported" ;;
  esac
}
ARCH=$(map_arch "$ARCH")
if [ "$ARCH" = "unsupported" ]; then
  echo "Unsupported arch"; exit 1
fi

sudo mkdir -p "$INSTALL_DIR"
sudo chown "$(id -u)":"$(id -g)" "$INSTALL_DIR"
cd "$INSTALL_DIR"

CONFIG_URL="__CONFIG_URL__"

while getopts ":p:v:t:u:k:" opt; do
  case $opt in
    p) PROXY_PREFIX="$OPTARG" ;;
    v) AROUTER_VERSION="$OPTARG" ;;
    t) GITHUB_TOKEN="$OPTARG" ;;
    u) CONFIG_URL="$OPTARG" ;;
    k) TOKEN="$OPTARG" ;;
    *) ;;
  esac
done
shift $((OPTIND-1))

# append os hint to CONFIG_URL
if [[ "$CONFIG_URL" != *"os="* ]]; then
  if [[ "$CONFIG_URL" == *"?"* ]]; then SEP="&"; else SEP="?"; fi
  CONFIG_URL="${CONFIG_URL}${SEP}os=${OS}"
fi

# fetch config_pull.sh from controller
CONFIG_PULL_BASE="__CONFIG_PULL_BASE__"
CONFIG_B64=$(printf '%s' "$CONFIG_URL" | base64 | tr -d '\n')
CONFIG_PULL_URL="${CONFIG_PULL_BASE}&install_dir=${INSTALL_DIR}&config_url_b64=${CONFIG_B64}&proxy_prefix=${PROXY_PREFIX}&token_override=${TOKEN}"
echo "==> Fetching config_pull.sh..."
echo "$CONFIG_PULL_URL"
curl -v -fsSL "$CONFIG_PULL_URL" -o config_pull.sh
chmod +x config_pull.sh

echo "==> Writing config..."
cat > config.json <<'CONFIGEOF'
__CONFIG__
CONFIGEOF
echo "DEBUG: config.json written, size=$(stat -c%%s config.json 2>/dev/null || stat -f%%z config.json 2>/dev/null)" >&2
# 展开 config.json 中的路径占位符（${HOME} 或 /opt/arouter -> INSTALL_DIR）
if command -v jq >/dev/null 2>&1; then
  tmp_cfg=$(mktemp)
  jq --arg inst "$INSTALL_DIR" --arg home "$HOME" '
    def fix($v):
      if $v == null then $v else
        ($v
          | if ($home != "" and (contains("${HOME}"))) then gsub("\\$\\{HOME\\}"; $home) else . end
          | if ($inst != "" and startswith("/opt/arouter")) then sub("^/opt/arouter"; $inst) else . end);
    .mtls_cert = fix(.mtls_cert)
    | .mtls_key = fix(.mtls_key)
    | .mtls_ca = fix(.mtls_ca)
    | .token_path = fix(.token_path)
  ' config.json > "$tmp_cfg" && mv "$tmp_cfg" config.json
else
  if [ -n "$HOME" ]; then
    sed -i.bak "s#\\${HOME}#${HOME}#g" config.json || true
    rm -f config.json.bak 2>/dev/null || true
  fi
  if [ -n "$INSTALL_DIR" ]; then
    sed -i.bak "s#\"/opt/arouter#\"${INSTALL_DIR}#g" config.json || true
    rm -f config.json.bak 2>/dev/null || true
  fi
fi
# Write token if provided
if [ -n "$TOKEN" ]; then
  echo "$TOKEN" > .token
  chmod 600 .token
fi
# Extract fields after args parsed
sync_interval() {
  val=$(grep -o '"poll_period"[[:space:]]*:[[:space:]]*"[^"]*"' config.json | head -n1 | sed 's/.*:"\\([^"]*\\)".*/\\1/')
  [ -z "$val" ] && val="60s"
  echo "$val"
}

BIN_URL="__BIN_BASE__/downloads/arouter?os=${OS}&arch=${ARCH}"
echo "==> Downloading binary ${BIN_URL}"
TMP_BIN=$(mktemp)
echo "DEBUG: downloading ${BIN_URL}" >&2
if ! curl -fsSL -fL --connect-timeout 10 --max-time 60 "${BIN_URL}" -o "$TMP_BIN"; then
  status=$?
  echo "Download failed. Check controller /downloads endpoint or os/arch params."
  echo "DEBUG: curl exit code ${status}"
  exit 1
fi
chmod +x "$TMP_BIN"

HAS_SYSTEMCTL="$(command -v systemctl || true)"
IS_DARWIN=""
if [ "$OS" = "darwin" ]; then IS_DARWIN="1"; fi
echo "==> Stopping previous service (if exists)..."
if [ -n "$HAS_SYSTEMCTL" ]; then
	if systemctl is-active --quiet arouter; then
		sudo systemctl stop arouter || true
	fi
  sudo systemctl disable arouter || true
  sudo rm -f /etc/systemd/system/arouter.service
  sudo systemctl daemon-reload
fi

mv -f "$TMP_BIN" arouter

if [ -n "$HAS_SYSTEMCTL" ]; then
echo "==> Installing systemd service..."
SERVICE_FILE="/etc/systemd/system/arouter.service"
cat <<SERVICE | sudo tee "$SERVICE_FILE" >/dev/null
[Unit]
Description=ARouter Node
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/arouter -config ${INSTALL_DIR}/config.json
Environment=CONFIG_URL=${CONFIG_URL:-__CONFIG_URL__}
Environment=NODE_TOKEN=$(cat ${INSTALL_DIR}/.token 2>/dev/null || true)
Restart=always
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable arouter
sudo systemctl restart arouter
elif [ -n "$IS_DARWIN" ]; then
	PLIST="/Library/LaunchDaemons/com.arouter.node.plist"
	echo "==> Installing launchd service at ${PLIST}"
	cat <<PLIST | sudo tee "$PLIST" >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.arouter.node</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_DIR}/arouter</string>
    <string>-config</string>
    <string>${INSTALL_DIR}/config.json</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${INSTALL_DIR}/arouter.log</string>
  <key>StandardErrorPath</key><string>${INSTALL_DIR}/arouter.err</string>
</dict>
</plist>
PLIST
	sudo chown root:wheel "$PLIST"
	sudo chmod 644 "$PLIST"
	sudo launchctl unload "$PLIST" 2>/dev/null || true
	sudo launchctl load -w "$PLIST"
else
	echo "systemctl/launchctl not found, skipped service install. Binary placed at ${INSTALL_DIR}/arouter."
	echo "Please configure autostart manually."
fi

	HAS_LAUNCHCTL="$(command -v launchctl || true)"
	
	if [ -n "$HAS_SYSTEMCTL" ]; then
# 配置自动同步任务：周期拉取最新配置，变更则重启服务
echo "==> Installing config sync service..."
SYNC_SCRIPT="${INSTALL_DIR}/config_pull.sh"

cat <<SERVICE | sudo tee /etc/systemd/system/arouter-config.service >/dev/null
[Unit]
Description=ARouter Config Sync

[Service]
Type=oneshot
ExecStart=${SYNC_SCRIPT}
Environment=CONFIG_URL=${CONFIG_URL:-__CONFIG_URL__}
Environment=INSTALL_DIR=${INSTALL_DIR}
Environment=NODE_TOKEN=$(cat ${INSTALL_DIR}/.token 2>/dev/null || true)
User=root
SERVICE

cat <<SERVICE | sudo tee /etc/systemd/system/arouter-config.timer >/dev/null
[Unit]
Description=Run ARouter Config Sync periodically

[Timer]
OnBootSec=30s
OnUnitActiveSec=__SYNC_INTERVAL__

[Install]
WantedBy=timers.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable arouter-config.timer
sudo systemctl start arouter-config.timer

echo "==> Install complete. Service status:"
sudo systemctl status arouter --no-pager
elif [ -n "$IS_DARWIN" ]; then
	SYNC_SCRIPT="${INSTALL_DIR}/config_pull.sh"
	SYNC_SECS=$(echo "__SYNC_INTERVAL__" | sed 's/[^0-9]//g')
	[ -z "$SYNC_SECS" ] && SYNC_SECS=60
	PLIST="/Library/LaunchDaemons/com.arouter.config.plist"
	echo "==> Installing launchd timer for config sync (${SYNC_SECS}s)"
	cat <<PLIST | sudo tee "$PLIST" >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.arouter.config</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>${SYNC_SCRIPT}</string>
  </array>
  <key>StartInterval</key><integer>${SYNC_SECS}</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>${INSTALL_DIR}/config_pull.log</string>
  <key>StandardErrorPath</key><string>${INSTALL_DIR}/config_pull.err</string>
</dict>
</plist>
PLIST
	sudo chown root:wheel "$PLIST"
	sudo chmod 644 "$PLIST"
	sudo launchctl unload "$PLIST" 2>/dev/null || true
	sudo launchctl load -w "$PLIST"
	echo "==> Install complete. launchd services loaded (com.arouter.node, com.arouter.config)."
else
	echo "systemctl not found, skipping config sync timer install."
fi
`
	script = strings.ReplaceAll(script, "__CONFIG__", configJSON)
	script = strings.ReplaceAll(script, "__CONFIG_URL__", configURL)
	script = strings.ReplaceAll(script, "__CONFIG_PULL_BASE__", configPullBase)
	script = strings.ReplaceAll(script, "__BIN_BASE__", binBase)
	script = strings.ReplaceAll(script, "__SYNC_INTERVAL__", syncInterval)
	// choose installDir placeholder; script自身根据 OS 继续覆写为 /opt/arouter 或 $HOME/.arouter
	script = strings.ReplaceAll(script, "__INSTALL_DIR__", "/opt/arouter")
	return script
}
