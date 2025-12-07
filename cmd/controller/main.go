package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

//go:embed templates/*
var templates embed.FS

type Node struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Name           string    `gorm:"uniqueIndex" json:"name"`
	WSListen       string    `json:"ws_listen"`
	MetricsListen  string    `json:"metrics_listen"`
	AuthKey        string    `json:"auth_key"`
	InsecureSkipTLS bool     `json:"insecure_skip_tls"`
	RerouteAttempts int      `json:"reroute_attempts"`
	UDPSessionTTL   string   `json:"udp_session_ttl"`
	MTLSCert        string   `json:"mtls_cert"`
	MTLSKey         string   `json:"mtls_key"`
	MTLSCA          string   `json:"mtls_ca"`
	Entries        []Entry   `json:"entries"`
	Peers          []Peer    `json:"peers"`
}

type Entry struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	NodeID   uint   `json:"-"`
	Listen   string `json:"listen"`
	Proto    string `json:"proto"`
	Exit     string `json:"exit"`
	Remote   string `json:"remote"`
}

type Peer struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	NodeID   uint   `json:"-"`
	PeerName string `json:"peer_name"`
	Endpoint string `json:"endpoint"` // ws(s)://host:port/mesh
	EntryIP  string `json:"entry_ip"` // 对端入口 IP
	ExitIP   string `json:"exit_ip"`  // 本节点出口 IP
}

type ConfigResponse struct {
	ID              string            `json:"id"`
	WSListen        string            `json:"ws_listen"`
	Peers           map[string]string `json:"peers"`
	Entries         []EntryConfig     `json:"entries"`
	PollPeriod      string            `json:"poll_period"`
	InsecureSkipTLS bool              `json:"insecure_skip_tls"`
	AuthKey         string            `json:"auth_key"`
	MetricsListen   string            `json:"metrics_listen"`
	RerouteAttempts int               `json:"reroute_attempts"`
	UDPSessionTTL   string            `json:"udp_session_ttl"`
	MTLSCert        string            `json:"mtls_cert"`
	MTLSKey         string            `json:"mtls_key"`
	MTLSCA          string            `json:"mtls_ca"`
}

type EntryConfig struct {
	Listen string `json:"listen"`
	Proto  string `json:"proto"`
	Exit   string `json:"exit"`
	Remote string `json:"remote"`
}

func main() {
	db := mustOpenDB()
	if err := db.AutoMigrate(&Node{}, &Entry{}, &Peer{}); err != nil {
		log.Fatalf("migrate failed: %v", err)
	}

	r := gin.Default()
	tpl := template.Must(template.ParseFS(templates, "templates/*.tmpl"))
	r.SetHTMLTemplate(tpl)

	distDir := envOrDefault("WEB_DIST", "web/dist")
	if info, err := os.Stat(distDir); err == nil && info.IsDir() {
		log.Printf("serving static front-end from %s", distDir)
		r.StaticFS("/", http.Dir(distDir))
		r.NoRoute(func(c *gin.Context) {
			c.File(filepath.Join(distDir, "index.html"))
		})
	} else {
		log.Printf("static front-end not found (%s), fallback to embedded app.html", distDir)
		r.GET("/", func(c *gin.Context) {
			c.HTML(http.StatusOK, "app.html", gin.H{})
		})
	}

	api := r.Group("/api")
	api.GET("/nodes", func(c *gin.Context) {
		var nodes []Node
		db.Preload("Entries").Preload("Peers").Find(&nodes)
		c.JSON(http.StatusOK, nodes)
	})
	api.POST("/nodes", func(c *gin.Context) {
		var req Node
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			c.String(http.StatusBadRequest, "name required")
			return
		}
		req.WSListen = defaultIfEmpty(req.WSListen, ":18080")
		req.MetricsListen = defaultIfEmpty(req.MetricsListen, ":19090")
		req.AuthKey = defaultIfEmpty(req.AuthKey, randomKey())
		req.InsecureSkipTLS = true
		req.RerouteAttempts = defaultInt(req.RerouteAttempts, 3)
		req.UDPSessionTTL = defaultIfEmpty(req.UDPSessionTTL, "60s")
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})
	api.GET("/nodes/:id", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		c.JSON(http.StatusOK, node)
	})
	api.DELETE("/nodes/:id", func(c *gin.Context) {
		id := c.Param("id")
		db.Delete(&Peer{}, "node_id = ?", id)
		db.Delete(&Entry{}, "node_id = ?", id)
		db.Delete(&Node{}, "id = ?", id)
		c.Status(http.StatusNoContent)
	})
	api.POST("/nodes/:id/entries", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Entry
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		req.NodeID = node.ID
		req.Proto = defaultIfEmpty(req.Proto, "tcp")
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})
	api.POST("/nodes/:id/peers", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Peer
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		req.NodeID = node.ID
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})

	// 生成节点 config.json
	r.GET("/nodes/:id/config", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		cfg := buildConfig(node)
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-config.json"`, node.Name))
		c.JSON(http.StatusOK, cfg)
	})

	// 生成节点安装脚本
	r.GET("/nodes/:id/install.sh", func(c *gin.Context) {
		id := c.Param("id")
		baseURL := c.Request.Host
		if c.Request.TLS != nil {
			baseURL = "https://" + baseURL
		} else {
			baseURL = "http://" + baseURL
		}
		c.Header("Content-Type", "text/x-shellscript")
		c.Header("Content-Disposition", "attachment; filename=\"install.sh\"")
		c.String(http.StatusOK, installScript(baseURL, id))
	})

	addr := envOrDefault("CONTROLLER_ADDR", ":8080")
	log.Printf("controller listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("controller run failed: %v", err)
	}
}

func buildConfig(node Node) ConfigResponse {
	peers := make(map[string]string, len(node.Peers))
	for _, p := range node.Peers {
		if p.PeerName != "" {
			peers[p.PeerName] = p.Endpoint
		}
	}
	entries := make([]EntryConfig, 0, len(node.Entries))
	for _, e := range node.Entries {
		entries = append(entries, EntryConfig{
			Listen: e.Listen,
			Proto:  defaultIfEmpty(e.Proto, "tcp"),
			Exit:   e.Exit,
			Remote: e.Remote,
		})
	}
	return ConfigResponse{
		ID:              node.Name,
		WSListen:        defaultIfEmpty(node.WSListen, ":18080"),
		Peers:           peers,
		Entries:         entries,
		PollPeriod:      "5s",
		InsecureSkipTLS: node.InsecureSkipTLS,
		AuthKey:         defaultIfEmpty(node.AuthKey, randomKey()),
		MetricsListen:   defaultIfEmpty(node.MetricsListen, ":19090"),
		RerouteAttempts: defaultInt(node.RerouteAttempts, 3),
		UDPSessionTTL:   defaultIfEmpty(node.UDPSessionTTL, "60s"),
		MTLSCert:        node.MTLSCert,
		MTLSKey:         node.MTLSKey,
		MTLSCA:          node.MTLSCA,
	}
}

func installScript(baseURL, nodeID string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

NAME="%s"
CONFIG_URL="%s/nodes/%s/config"
INSTALL_DIR="${INSTALL_DIR:-/opt/arouter}"
GITHUB_REPO="NiuStar/arouter"
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

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

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "==> Fetching config..."
curl -fsSL "$CONFIG_URL" -o config.json

if [ -z "${AROUTER_VERSION:-}" ]; then
  echo "==> Detecting latest release..."
  AROUTER_VERSION=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep -Eo '"tag_name":\\s*"[^"]+"' | head -n1 | sed 's/.*"\\(.*\\)"/\\1/')
fi

if [ -z "$AROUTER_VERSION" ]; then
  echo "Failed to detect latest release"; exit 1
fi

BIN_URL="https://github.com/${GITHUB_REPO}/releases/download/${AROUTER_VERSION}/arouter-${OS}-${ARCH}"
echo "==> Downloading binary ${BIN_URL}"
curl -fL "$BIN_URL" -o arouter
chmod +x arouter

echo "==> Install complete."
echo "Run: $INSTALL_DIR/arouter -config $INSTALL_DIR/config.json"
`, nodeID, baseURL, nodeID)
}

func mustOpenDB() *gorm.DB {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		db, err := gorm.Open(sqlite.Open("arouter.db"), &gorm.Config{})
		if err != nil {
			log.Fatalf("open sqlite failed: %v", err)
		}
		return db
	}
	if strings.HasPrefix(dsn, "sqlite:") {
		path := strings.TrimPrefix(dsn, "sqlite:")
		db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
		if err != nil {
			log.Fatalf("open sqlite failed: %v", err)
		}
		return db
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("open mysql failed: %v", err)
	}
	return db
}

func defaultIfEmpty(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func defaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func randomKey() string {
	b := make([]byte, 16)
	_, _ = time.Now().UTC().MarshalBinary()
	for i := range b {
		b[i] = byte(65 + i)
	}
	return fmt.Sprintf("key-%d", time.Now().UnixNano())
}

// Utility: allow simple JSON API as well
func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
