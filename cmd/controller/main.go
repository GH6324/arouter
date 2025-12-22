package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"database/sql/driver"
	"embed"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	wscompat "arouter/internal/wscompat"
)

var buildVersion = "dev"
var jwtSecret []byte

//go:embed certs/arouter.crt
var defaultCert []byte

//go:embed certs/arouter.key
var defaultKey []byte

//go:embed config_pull.sh.tmpl
var configPullTemplate string

//go:embed dist/arouter-*
var embeddedNodeBins embed.FS

//go:embed web/dist
var embeddedWeb embed.FS

type Node struct {
	ID              uint        `gorm:"primaryKey" json:"id"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
	Name            string      `gorm:"uniqueIndex" json:"name"`
	WSListen        string      `json:"ws_listen"`
	MetricsListen   string      `json:"metrics_listen"`
	AuthKey         string      `json:"auth_key"`
	InsecureSkipTLS bool        `json:"insecure_skip_tls"`
	QUICServerName  string      `json:"quic_server_name"`
	RerouteAttempts int         `json:"reroute_attempts"`
	UDPSessionTTL   string      `json:"udp_session_ttl"`
	PollPeriod      string      `json:"poll_period"`
	MTLSCert        string      `json:"mtls_cert"`
	MTLSKey         string      `json:"mtls_key"`
	MTLSCA          string      `json:"mtls_ca"`
	ControllerURL   string      `json:"controller_url"`
	Compression     string      `json:"compression"`
	CompressionMin  int         `json:"compression_min_bytes"`
	Transport       string      `json:"transport"`
	QUICListen      string      `json:"quic_listen"`
	WSSListen       string      `json:"wss_listen"`
	Entries         []Entry     `json:"entries"`
	Peers           []Peer      `json:"peers"`
	Routes          []RoutePlan `json:"routes"`
	LastCPU         float64     `json:"cpu_usage"`
	MemUsed         uint64      `json:"mem_used_bytes"`
	MemTotal        uint64      `json:"mem_total_bytes"`
	UptimeSec       uint64      `json:"uptime_sec"`
	NetInBytes      uint64      `json:"net_in_bytes"`
	NetOutBytes     uint64      `json:"net_out_bytes"`
	NodeVersion     string      `json:"node_version"`
	LastSeenAt      time.Time   `json:"last_seen_at"`
	Token           string      `json:"token"`
	OSName          string      `json:"os_name"`
	Arch            string      `json:"arch"`
	PublicIPs       StringList  `json:"public_ips"`
	MaxMuxStreams   int         `json:"max_mux_streams"`
	MuxMaxAge       string      `json:"mux_max_age"`
	MuxMaxIdle      string      `json:"mux_max_idle"`
	MemLimit        string      `json:"mem_limit"`
}

type LinkMetric struct {
	From      string    `gorm:"primaryKey;column:from_node" json:"from"`
	To        string    `gorm:"primaryKey;column:to_node" json:"to"`
	RTTMs     int64     `json:"rtt_ms"`
	Loss      float64   `json:"loss"`
	UpdatedAt time.Time `json:"updated_at"`
}

type LinkMetricsJSON struct {
	RTTms     int64     `json:"rtt_ms"`
	Loss      float64   `json:"loss"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ReturnRouteStatus struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Node       string    `gorm:"uniqueIndex:idx_return_route" json:"node"`
	Route      string    `gorm:"uniqueIndex:idx_return_route" json:"route"`
	Entry      string    `gorm:"uniqueIndex:idx_return_route" json:"entry"`
	Exit       string    `gorm:"uniqueIndex:idx_return_route" json:"exit"`
	Auto       bool      `gorm:"uniqueIndex:idx_return_route" json:"auto"`
	Pending    int64     `json:"pending"`
	ReadyTotal int64     `json:"ready_total"`
	ReadyAt    int64     `json:"ready_at"`
	FailTotal  int64     `json:"fail_total"`
	FailAt     int64     `json:"fail_at"`
	FailReason string    `json:"fail_reason"`
}

type ReturnStatJSON struct {
	Entry      string `json:"entry"`
	Exit       string `json:"exit"`
	Route      string `json:"route"`
	Auto       bool   `json:"auto"`
	Pending    int64  `json:"pending"`
	ReadyTotal int64  `json:"ready_total"`
	ReadyAt    int64  `json:"ready_at"`
	FailTotal  int64  `json:"fail_total"`
	FailAt     int64  `json:"fail_at"`
	FailReason string `json:"fail_reason"`
}

type DiagReport struct {
	RunID  string    `json:"run_id"`
	Node   string    `json:"node"`
	At     time.Time `json:"at"`
	Lines  []string  `json:"lines"`
	Limit  int       `json:"limit"`
	Filter string    `json:"filter,omitempty"`
}

type diagRun struct {
	RunID     string
	CreatedAt time.Time
	Nodes     []string
	Reports   map[string]DiagReport
}

var (
	diagMu       sync.Mutex
	diagRuns     = make(map[string]*diagRun)
	diagRunOrder []string
)

type DiagTraceEvent struct {
	RunID      string   `json:"run_id"`
	Route      string   `json:"route"`
	Node       string   `json:"node"`
	Stage      string   `json:"stage"`
	Detail     string   `json:"detail,omitempty"`
	Session    string   `json:"session,omitempty"`
	Path       []string `json:"path,omitempty"`
	ReturnPath []string `json:"return_path,omitempty"`
	At         int64    `json:"at"`
}

type diagTraceRun struct {
	RunID     string
	CreatedAt time.Time
	Events    []DiagTraceEvent
}

var (
	diagTraceMu   sync.Mutex
	diagTraceRuns = make(map[string]*diagTraceRun)
)

type EndpointCheckResult struct {
	Node     string `json:"node"`
	Peer     string `json:"peer"`
	Endpoint string `json:"endpoint"`
	OK       bool   `json:"ok"`
	RTTMs    int64  `json:"rtt_ms"`
	Status   string `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
}

type endpointCheckRun struct {
	RunID     string
	CreatedAt time.Time
	Nodes     []string
	Results   []EndpointCheckResult
}

var (
	endpointCheckMu   sync.Mutex
	endpointCheckRuns = make(map[string]*endpointCheckRun)
)

type NodeUpdateStatus struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Node      string    `gorm:"uniqueIndex" json:"node"`
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	Reason    string    `json:"reason"`
	Forced    bool      `json:"forced"`
}

type UpdateStatusJSON struct {
	Node    string `json:"node"`
	Status  string `json:"status"`
	Version string `json:"version"`
	Reason  string `json:"reason"`
	Forced  bool   `json:"forced"`
}

type Entry struct {
	ID     uint   `gorm:"primaryKey" json:"id"`
	NodeID uint   `json:"-"`
	Listen string `json:"listen"`
	Proto  string `json:"proto"` // tcp/udp/both
	Exit   string `json:"exit"`
	Remote string `json:"remote"`
}

func stripPortPrefix(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, ":") {
		s = strings.TrimPrefix(s, ":")
	}
	return s
}

func normalizeNodePorts(n *Node) (changed bool) {
	norm := func(v string) (string, bool) {
		nv := stripPortPrefix(v)
		return nv, nv != v
	}
	if nv, diff := norm(n.WSListen); diff {
		n.WSListen = nv
		changed = true
	}
	if nv, diff := norm(n.WSSListen); diff {
		n.WSSListen = nv
		changed = true
	}
	if nv, diff := norm(n.MetricsListen); diff {
		n.MetricsListen = nv
		changed = true
	}
	if nv, diff := norm(n.QUICListen); diff {
		n.QUICListen = nv
		changed = true
	}
	return
}

func normalizeEntriesPorts(entries []Entry) (changed bool) {
	for i := range entries {
		nv := stripPortPrefix(entries[i].Listen)
		if nv != entries[i].Listen {
			entries[i].Listen = nv
			changed = true
		}
	}
	return
}

type StringList []string

func (s StringList) Value() (driver.Value, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (s *StringList) Scan(value interface{}) error {
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	default:
		return fmt.Errorf("unsupported type %T", value)
	}
}

type EncPolicy struct {
	ID     int    `json:"id"`
	Name   string `json:"name,omitempty"`
	Method string `json:"method"`
	Key    string `json:"key"`
	Enable bool   `json:"enable"` // 允许临时关闭某策略，前端控制
}

func (p *EncPolicy) normalize(idx int) {
	if p.ID == 0 {
		p.ID = idx + 1
	}
	p.Method = strings.ToLower(p.Method)
	if !p.Enable {
		p.Key = ""
		return
	}
	reqLen := 0
	switch p.Method {
	case "aes-128-gcm":
		reqLen = 16
	case "aes-256-gcm":
		reqLen = 32
	case "aes-gcm":
		if len(p.Key) > 0 {
			break
		}
		reqLen = 16
	case "chacha20-poly1305", "chacha20":
		reqLen = 32
	default:
		p.Method = "aes-128-gcm"
		reqLen = 16
	}
	keyBytes := decodeKeyFlexible(p.Key)
	if reqLen > 0 && len(keyBytes) != reqLen {
		keyBytes = randomKeyBytes(reqLen)
	}
	p.Key = base64.StdEncoding.EncodeToString(keyBytes)
}

// UnmarshalJSON 允许 id 既可为数字也可为字符串。
func (p *EncPolicy) UnmarshalJSON(data []byte) error {
	type alias EncPolicy
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		// try permissive id parsing
		var idVal int
		if b, ok := raw["id"]; ok {
			var num json.Number
			if err := json.Unmarshal(b, &num); err == nil {
				if v, err := num.Int64(); err == nil {
					idVal = int(v)
				}
			} else {
				var s string
				if err := json.Unmarshal(b, &s); err == nil {
					if v, err := strconv.Atoi(s); err == nil {
						idVal = v
					}
				}
			}
		}
		a.ID = idVal
		_ = json.Unmarshal(raw["name"], &a.Name)
		_ = json.Unmarshal(raw["method"], &a.Method)
		_ = json.Unmarshal(raw["key"], &a.Key)
	}
	p.ID = a.ID
	p.Name = a.Name
	p.Method = a.Method
	p.Key = a.Key
	p.Enable = a.Enable
	return nil
}

type EncPolicyList []EncPolicy

func decodeKeyFlexible(s string) []byte {
	if s == "" {
		return nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b
	}
	return []byte(s)
}

func randomKeyBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return []byte("fallback-random-key-32bytes-----")[:n]
	}
	return b
}

func (s EncPolicyList) Value() (driver.Value, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (s *EncPolicyList) Scan(value interface{}) error {
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	default:
		return fmt.Errorf("unsupported type %T", value)
	}
}

func (s EncPolicyList) normalize() EncPolicyList {
	out := make(EncPolicyList, 0, len(s))
	for i := range s {
		p := s[i]
		p.normalize(i)
		if p.Enable {
			out = append(out, p)
		}
	}
	return out
}

type RoutePlan struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	NodeID    uint       `json:"-"`
	Name      string     `json:"name"`
	Exit      string     `json:"exit"`
	Remote    string     `json:"remote"`
	Priority  int        `json:"priority"`
	Path      StringList `json:"path"`
	ReturnPath StringList `json:"return_path"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type Peer struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	NodeID   uint   `json:"-"`
	PeerName string `json:"peer_name"`
	Endpoint string `json:"endpoint"` // ws(s)://host:port/mesh
	EntryIP  string `json:"entry_ip"` // 对端入口 IP
	ExitIP   string `json:"exit_ip"`  // 本节点出口 IP
}

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Username     string    `gorm:"uniqueIndex" json:"username"`
	PasswordHash string    `json:"-"`
	IsAdmin      bool      `json:"is_admin"`
}

// Setting 为全局系统设置，影响所有节点。
type Setting struct {
	ID                 uint          `gorm:"primaryKey" json:"id"`
	Transport          string        `json:"transport"`
	Compression        string        `json:"compression"`
	CompressionMin     int           `json:"compression_min_bytes"`
	DebugLog           bool          `json:"debug_log"`
	HTTPProbeURL       string        `json:"http_probe_url"`
	EncryptionPolicies EncPolicyList `json:"encryption_policies"`
}

type RouteProbe struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	Node      string     `gorm:"uniqueIndex:idx_node_route" json:"node"`
	Route     string     `gorm:"uniqueIndex:idx_node_route" json:"route"`
	Path      StringList `json:"path"`
	RTTMs     int64      `json:"rtt_ms"`
	Success   bool       `json:"success"`
	Error     string     `json:"error"`
}

type UserClaims struct {
	UserID  uint `json:"uid"`
	IsAdmin bool `json:"is_admin"`
}

type ConfigResponse struct {
	ID              string            `json:"id"`
	WSListen        string            `json:"ws_listen"`
	QUICListen      string            `json:"quic_listen"`
	WSSListen       string            `json:"wss_listen"`
	QUICServerName  string            `json:"quic_server_name"`
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
	ControllerURL   string            `json:"controller_url"`
	Routes          []RouteConfig     `json:"routes,omitempty"`
	Compression     string            `json:"compression,omitempty"`
	CompressionMin  int               `json:"compression_min_bytes,omitempty"`
	Transport       string            `json:"transport,omitempty"`
	DebugLog        bool              `json:"debug_log,omitempty"`
	TokenPath       string            `json:"token_path,omitempty"`
	OS              string            `json:"os,omitempty"`
	Arch            string            `json:"arch,omitempty"`
	HTTPProbeURL    string            `json:"http_probe_url,omitempty"`
	Encryption      []EncPolicy       `json:"encryption_policies,omitempty"`
	MaxMuxStreams   int               `json:"max_mux_streams,omitempty"`
	MuxMaxAge       string            `json:"mux_max_age,omitempty"`
	MuxMaxIdle      string            `json:"mux_max_idle,omitempty"`
	MemLimit        string            `json:"mem_limit,omitempty"`
}

// applyOSOverrides 根据 os hint（例如 darwin）调整默认路径，便于节点在不同平台使用合适的目录。
func applyOSOverrides(cfg ConfigResponse, osHint string) ConfigResponse {
	if osHint == "darwin" {
		if strings.HasPrefix(cfg.MTLSCert, "/opt/arouter/") {
			cfg.MTLSCert = strings.Replace(cfg.MTLSCert, "/opt/arouter", "${HOME}/.arouter", 1)
		}
		if strings.HasPrefix(cfg.MTLSKey, "/opt/arouter/") {
			cfg.MTLSKey = strings.Replace(cfg.MTLSKey, "/opt/arouter", "${HOME}/.arouter", 1)
		}
		if strings.HasPrefix(cfg.MTLSCA, "/opt/arouter/") {
			cfg.MTLSCA = strings.Replace(cfg.MTLSCA, "/opt/arouter", "${HOME}/.arouter", 1)
		}
		if cfg.TokenPath == "" || strings.HasPrefix(cfg.TokenPath, "/opt/arouter/") {
			cfg.TokenPath = strings.Replace("/opt/arouter/.token", "/opt/arouter", "${HOME}/.arouter", 1)
		}
	}
	return cfg
}

func applyInstallDirOverrides(cfg ConfigResponse, installDir string) ConfigResponse {
	if installDir == "" {
		return cfg
	}
	replacePath := func(v string) string {
		if v == "" {
			return v
		}
		if strings.Contains(v, "${HOME}") {
			return strings.ReplaceAll(v, "${HOME}", installDir)
		}
		if strings.HasPrefix(v, "/opt/arouter") {
			return strings.Replace(v, "/opt/arouter", installDir, 1)
		}
		return v
	}
	cfg.MTLSCert = replacePath(cfg.MTLSCert)
	cfg.MTLSKey = replacePath(cfg.MTLSKey)
	cfg.MTLSCA = replacePath(cfg.MTLSCA)
	cfg.TokenPath = replacePath(cfg.TokenPath)
	return cfg
}

type RouteConfig struct {
	Name     string   `json:"name"`
	Exit     string   `json:"exit"`
	Remote   string   `json:"remote,omitempty"`
	Priority int      `json:"priority"`
	Path     []string `json:"path"`
	ReturnPath []string `json:"return_path,omitempty"`
}

type EntryConfig struct {
	Listen string `json:"listen"`
	Proto  string `json:"proto"`
	Exit   string `json:"exit"`
	Remote string `json:"remote"`
}

func normalizeStoredPorts(db *gorm.DB) {
	var nodes []Node
	if err := db.Preload("Entries").Find(&nodes).Error; err != nil {
		log.Printf("normalize ports skipped: %v", err)
		return
	}
	for i := range nodes {
		nodeChanged := normalizeNodePorts(&nodes[i])
		entryChanged := normalizeEntriesPorts(nodes[i].Entries)
		if nodeChanged {
			db.Model(&nodes[i]).Updates(map[string]interface{}{
				"ws_listen":      nodes[i].WSListen,
				"wss_listen":     nodes[i].WSSListen,
				"metrics_listen": nodes[i].MetricsListen,
				"quic_listen":    nodes[i].QUICListen,
			})
		}
		if entryChanged {
			for _, e := range nodes[i].Entries {
				db.Model(&Entry{}).Where("id = ?", e.ID).Update("listen", e.Listen)
			}
		}
	}
}

func main() {
	db := mustOpenDB()
	maybeCheckpoint(db)
	auth := NewGlobalAuth(envOrDefault("AUTH_KEY_FILE", "/app/data/auth.key"))
	globalKey := auth.LoadOrCreate()
	buildVersion = canonicalVersion(buildVersion)
	if err := db.AutoMigrate(&Node{}, &Entry{}, &Peer{}, &LinkMetric{}, &RoutePlan{}, &Setting{}, &User{}, &RouteProbe{}, &ReturnRouteStatus{}, &NodeUpdateStatus{}); err != nil {
		log.Fatalf("migrate failed: %v", err)
	}
	ensureColumns(db)
	normalizeStoredPorts(db)
	ensureGlobalSettings(db)
	jwtSecret = []byte(envOrDefault("JWT_SECRET", randomKey()))
	log.Printf("arouter controller version %s", buildVersion)

	r := gin.Default()
	enableCors := strings.ToLower(envOrDefault("ENABLE_CORS", "true"))
	if enableCors == "true" || enableCors == "1" || enableCors == "yes" {
		r.Use(func(c *gin.Context) {
			w := c.Writer
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
			h.Set("Access-Control-Max-Age", "86400")
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
		})
	}
	hub := newWSHub()

	distDir := envOrDefault("WEB_DIST", "cmd/controller/web/dist")
	if info, err := os.Stat(distDir); err == nil && info.IsDir() {
		indexFile := filepath.Join(distDir, "index.html")
		if _, err := os.Stat(indexFile); err == nil {
			log.Printf("serving static front-end from %s", distDir)
			assetsDir := filepath.Join(distDir, "assets")
			if _, err := os.Stat(assetsDir); err == nil {
				r.Static("/assets", assetsDir)
			}
			r.StaticFile("/favicon.ico", filepath.Join(distDir, "favicon.ico"))
			r.GET("/", func(c *gin.Context) {
				c.File(indexFile)
			})
			r.NoRoute(func(c *gin.Context) {
				if strings.HasPrefix(c.Request.URL.Path, "/api/") {
					c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
					return
				}
				// try to serve existing file
				path := filepath.Clean(c.Request.URL.Path)
				fpath := filepath.Join(distDir, path)
				if info, err := os.Stat(fpath); err == nil && !info.IsDir() {
					c.File(fpath)
					return
				}
				// fallback to SPA entry
				c.File(indexFile)
			})
		} else {
			log.Printf("WEB_DIST=%s exists but missing index.html, fallback to embedded assets", distDir)
			if sub, err := fs.Sub(embeddedWeb, "web/dist"); err == nil {
				efs := http.FS(sub)
				r.GET("/", func(c *gin.Context) {
					c.FileFromFS("index.html", efs)
				})
				r.NoRoute(func(c *gin.Context) {
					if strings.HasPrefix(c.Request.URL.Path, "/api/") {
						c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
						return
					}
					path := strings.TrimPrefix(filepath.Clean(c.Request.URL.Path), "/")
					if path == "" {
						path = "index.html"
					}
					if _, err := sub.Open(path); err == nil {
						c.FileFromFS(path, efs)
						return
					}
					c.FileFromFS("index.html", efs)
				})
			}
		}
	} else if sub, err := fs.Sub(embeddedWeb, "web/dist"); err == nil {
		log.Printf("serving embedded static front-end")
		efs := http.FS(sub)
		r.GET("/", func(c *gin.Context) {
			c.FileFromFS("index.html", efs)
		})
		r.NoRoute(func(c *gin.Context) {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			path := strings.TrimPrefix(filepath.Clean(c.Request.URL.Path), "/")
			if path == "" {
				path = "index.html"
			}
			// try direct file (assets/...)
			if _, err := sub.Open(path); err == nil {
				c.FileFromFS(path, efs)
				return
			}
			// fallback SPA
			c.FileFromFS("index.html", efs)
		})
	} else {
		log.Printf("static front-end not found (%s), please build React front-end into this path", distDir)
		r.GET("/", func(c *gin.Context) {
			c.String(http.StatusOK, "Front-end not found. Build React app and set WEB_DIST to its dist directory.")
		})
	}

	// 版本信息
	r.GET("/api/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"version": buildVersion})
	})

	api := r.Group("/api")
	authGroup := api.Group("")
	authGroup.Use(authUserMiddleware(db))
	authGroup.GET("/me", func(c *gin.Context) {
		u, _ := c.Get("user")
		c.JSON(http.StatusOK, u)
	})
	authGroup.GET("/users", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		var users []User
		db.Find(&users)
		c.JSON(http.StatusOK, users)
	})
	authGroup.POST("/users", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			IsAdmin  bool   `json:"is_admin"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		if req.Username == "" || req.Password == "" {
			c.String(http.StatusBadRequest, "username/password required")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		user := User{Username: req.Username, PasswordHash: string(hash), IsAdmin: req.IsAdmin}
		if err := db.Create(&user).Error; err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusCreated, user)
	})
	authGroup.PUT("/users/:id", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		id := c.Param("id")
		var req struct {
			Password string `json:"password"`
			IsAdmin  *bool  `json:"is_admin"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		updates := map[string]interface{}{}
		if req.Password != "" {
			hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			updates["password_hash"] = string(hash)
		}
		if req.IsAdmin != nil {
			updates["is_admin"] = *req.IsAdmin
		}
		if len(updates) == 0 {
			c.String(http.StatusBadRequest, "nothing to update")
			return
		}
		if err := db.Model(&User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		c.Status(http.StatusNoContent)
	})
	authGroup.DELETE("/users/:id", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		id := c.Param("id")
		if err := db.Delete(&User{}, "id = ?", id).Error; err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		c.Status(http.StatusNoContent)
	})
	// login
	api.POST("/login", func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		var cnt int64
		db.Model(&User{}).Count(&cnt)
		if cnt == 0 {
			// 首个用户自动创建为管理员
			hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			user := User{Username: req.Username, PasswordHash: string(hash), IsAdmin: true}
			if err := db.Create(&user).Error; err != nil {
				c.String(http.StatusInternalServerError, err.Error())
				return
			}
			token, _ := issueJWT(user)
			c.JSON(http.StatusOK, gin.H{"token": token, "user": user})
			return
		}
		var user User
		if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
			c.String(http.StatusUnauthorized, "invalid credentials")
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
			c.String(http.StatusUnauthorized, "invalid credentials")
			return
		}
		token, _ := issueJWT(user)
		c.JSON(http.StatusOK, gin.H{"token": token, "user": user})
	})

	// legacy secure group removed
	authGroup.GET("/nodes", func(c *gin.Context) {
		var settings Setting
		db.First(&settings)
		var nodes []Node
		db.Preload("Entries").Preload("Peers").Preload("Routes").Find(&nodes)
		for i := range nodes {
			nodeChanged := normalizeNodePorts(&nodes[i])
			entryChanged := normalizeEntriesPorts(nodes[i].Entries)
			if nodeChanged {
				db.Model(&nodes[i]).Updates(map[string]interface{}{
					"ws_listen":      nodes[i].WSListen,
					"wss_listen":     nodes[i].WSSListen,
					"metrics_listen": nodes[i].MetricsListen,
					"quic_listen":    nodes[i].QUICListen,
				})
			}
			if entryChanged {
				for _, e := range nodes[i].Entries {
					db.Model(&Entry{}).Where("id = ?", e.ID).Update("listen", e.Listen)
				}
			}
			ensureNodeToken(db, &nodes[i])
			if nodes[i].Transport == "" {
				nodes[i].Transport = settings.Transport
			}
			if nodes[i].Compression == "" {
				nodes[i].Compression = settings.Compression
			}
			if nodes[i].CompressionMin == 0 && settings.CompressionMin > 0 {
				nodes[i].CompressionMin = settings.CompressionMin
			}
		}
		c.JSON(http.StatusOK, nodes)
	})
	api.GET("/host/ips", authUserMiddleware(db), func(c *gin.Context) {
		resp := map[string]any{
			"interfaces": listPublicIfAddrs(),
		}
		if v4, v6 := detectPublicIPs(); v4 != "" || v6 != "" {
			resp["public_v4"] = v4
			resp["public_v6"] = v6
		}
		c.JSON(http.StatusOK, resp)
	})
	api.GET("/certs", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		if _, err := findNodeByToken(db, nodeToken); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		certPath := envOrDefault("AROUTER_CERT_PATH", "certs/arouter.crt")
		keyPath := envOrDefault("AROUTER_KEY_PATH", "certs/arouter.key")
		certData, err1 := os.ReadFile(certPath)
		keyData, err2 := os.ReadFile(keyPath)
		if err1 != nil || err2 != nil {
			// fallback to embedded defaults
			certData = defaultCert
			keyData = defaultKey
			if len(certData) == 0 || len(keyData) == 0 {
				c.String(http.StatusInternalServerError, fmt.Sprintf("cert read err=%v key err=%v", err1, err2))
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"cert": string(certData), "key": string(keyData)})
	})
	authGroup.POST("/nodes", func(c *gin.Context) {
		var req Node
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			c.String(http.StatusBadRequest, "name required")
			return
		}
		req.WSListen = stripPortPrefix(defaultIfEmpty(req.WSListen, "18080"))
		req.WSSListen = stripPortPrefix(req.WSSListen)
		req.MetricsListen = stripPortPrefix(defaultIfEmpty(req.MetricsListen, "19090"))
		req.QUICListen = stripPortPrefix(req.QUICListen)
		if strings.TrimSpace(req.MemLimit) == "" {
			req.MemLimit = "256MiB"
		}
		req.AuthKey = defaultIfEmpty(req.AuthKey, randomKey())
		req.InsecureSkipTLS = true
		req.RerouteAttempts = defaultInt(req.RerouteAttempts, 3)
		req.UDPSessionTTL = defaultIfEmpty(req.UDPSessionTTL, "60s")
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		ensureNodeToken(db, &req)
		c.JSON(http.StatusCreated, req)
	})
	authGroup.GET("/nodes/:id", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").Preload("Routes").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if normalizeNodePorts(&node) {
			db.Model(&node).Updates(map[string]interface{}{
				"ws_listen":      node.WSListen,
				"wss_listen":     node.WSSListen,
				"metrics_listen": node.MetricsListen,
				"quic_listen":    node.QUICListen,
			})
		}
		if normalizeEntriesPorts(node.Entries) {
			for _, e := range node.Entries {
				db.Model(&Entry{}).Where("id = ?", e.ID).Update("listen", e.Listen)
			}
		}
		var settings Setting
		db.First(&settings)
		if node.Transport == "" {
			node.Transport = settings.Transport
		}
		if node.Compression == "" {
			node.Compression = settings.Compression
		}
		if node.CompressionMin == 0 && settings.CompressionMin > 0 {
			node.CompressionMin = settings.CompressionMin
		}
		if strings.TrimSpace(node.MemLimit) == "" {
			node.MemLimit = "256MiB"
		}
		c.JSON(http.StatusOK, node)
	})
	authGroup.GET("/nodes/:id/update-status", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var status NodeUpdateStatus
		if err := db.Where("node = ?", node.Name).First(&status).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusOK, nil)
				return
			}
			c.String(http.StatusInternalServerError, "query failed")
			return
		}
		c.JSON(http.StatusOK, status)
	})
	authGroup.PUT("/nodes/:id", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Node
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		wsListen := stripPortPrefix(defaultIfEmpty(req.WSListen, node.WSListen))
		wssListen := stripPortPrefix(defaultIfEmpty(req.WSSListen, node.WSSListen))
		metricsListen := stripPortPrefix(defaultIfEmpty(req.MetricsListen, node.MetricsListen))
		quicListen := stripPortPrefix(defaultIfEmpty(req.QUICListen, node.QUICListen))
		memLimit := defaultIfEmpty(req.MemLimit, node.MemLimit)
		updates := map[string]interface{}{
			"ws_listen":        wsListen,
			"wss_listen":       wssListen,
			"metrics_listen":   metricsListen,
			"poll_period":      defaultIfEmpty(req.PollPeriod, node.PollPeriod),
			"compression":      defaultIfEmpty(req.Compression, node.Compression),
			"compression_min":  req.CompressionMin,
			"transport":        defaultIfEmpty(req.Transport, node.Transport),
			"quic_listen":      quicListen,
			"quic_server_name": defaultIfEmpty(req.QUICServerName, node.QUICServerName),
			"max_mux_streams":  req.MaxMuxStreams,
			"mux_max_age":      defaultIfEmpty(req.MuxMaxAge, node.MuxMaxAge),
			"mux_max_idle":     defaultIfEmpty(req.MuxMaxIdle, node.MuxMaxIdle),
			"mem_limit":        memLimit,
		}
		if err := db.Model(&node).Updates(updates).Error; err != nil {
			c.String(http.StatusBadRequest, "update failed: %v", err)
			return
		}
		db.Preload("Entries").Preload("Peers").Preload("Routes").First(&node, id)
		c.JSON(http.StatusOK, node)
	})
	authGroup.DELETE("/nodes/:id", func(c *gin.Context) {
		id := c.Param("id")
		db.Delete(&Peer{}, "node_id = ?", id)
		db.Delete(&Entry{}, "node_id = ?", id)
		db.Delete(&RoutePlan{}, "node_id = ?", id)
		db.Delete(&Node{}, "id = ?", id)
		c.Status(http.StatusNoContent)
	})
	authGroup.POST("/nodes/:id/force-update", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := hub.sendCommand(node.Name, map[string]any{
			"type": "force_update",
			"data": map[string]any{},
		}); err != nil {
			c.String(http.StatusServiceUnavailable, "node offline or send failed: %v", err)
			return
		}
		c.Status(http.StatusAccepted)
	})
	authGroup.POST("/nodes/:id/entries", func(c *gin.Context) {
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
		req.Listen = stripPortPrefix(req.Listen)
		req.NodeID = node.ID
		req.Proto = defaultIfEmpty(req.Proto, "tcp")
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})
	authGroup.DELETE("/nodes/:id/entries/:entryId", func(c *gin.Context) {
		id := c.Param("id")
		entryId := c.Param("entryId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := db.Delete(&Entry{}, "id = ? AND node_id = ?", entryId, id).Error; err != nil {
			c.String(http.StatusBadRequest, "delete failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})
	authGroup.POST("/nodes/:id/peers", func(c *gin.Context) {
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
	authGroup.POST("/nodes/:id/peers/auto", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.Preload("Routes").Preload("Peers").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var allNodes []Node
		db.Find(&allNodes)
		pubMap := make(map[string][]string, len(allNodes))
		selfHasV6 := false
		for _, ip := range node.PublicIPs {
			if strings.Contains(ip, ":") {
				selfHasV6 = true
				break
			}
		}
		for _, n := range allNodes {
			if len(n.PublicIPs) > 0 {
				pubMap[n.Name] = n.PublicIPs
			}
		}
		neighbors := make(map[string]struct{})
		for _, r := range node.Routes {
			for i := 0; i+1 < len(r.Path); i++ {
				if r.Path[i] == node.Name {
					neighbors[string(r.Path[i+1])] = struct{}{}
				}
			}
		}
		existing := make(map[string]*Peer, len(node.Peers))
		for i := range node.Peers {
			p := &node.Peers[i]
			existing[p.PeerName] = p
		}
		created := 0
		updated := 0
		for peerName := range neighbors {
			if peerName == "" || peerName == node.Name {
				continue
			}
			if cur, ok := existing[peerName]; ok {
				update := map[string]interface{}{}
				if cur.EntryIP == "" {
					entryIP := ""
					if ips, ok := pubMap[peerName]; ok && len(ips) > 0 {
						for _, ip := range ips {
							if selfHasV6 && strings.Contains(ip, ":") {
								entryIP = ip
								break
							}
						}
						if entryIP == "" {
							for _, ip := range ips {
								if !strings.Contains(ip, ":") {
									entryIP = ip
									break
								}
							}
						}
						if entryIP == "" {
							entryIP = ips[0]
						}
					}
					if entryIP != "" {
						update["entry_ip"] = entryIP
					}
				}
				if len(update) > 0 {
					if err := db.Model(&Peer{}).Where("id = ? AND node_id = ?", cur.ID, node.ID).Updates(update).Error; err == nil {
						updated++
					}
				}
				continue
			}
			entryIP := ""
			if ips, ok := pubMap[peerName]; ok && len(ips) > 0 {
				for _, ip := range ips {
					if selfHasV6 && strings.Contains(ip, ":") {
						entryIP = ip
						break
					}
				}
				if entryIP == "" {
					for _, ip := range ips {
						if !strings.Contains(ip, ":") {
							entryIP = ip
							break
						}
					}
				}
				if entryIP == "" {
					entryIP = ips[0]
				}
			}
			newPeer := Peer{
				NodeID:   node.ID,
				PeerName: peerName,
				EntryIP:  entryIP,
			}
			if err := db.Create(&newPeer).Error; err == nil {
				created++
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"created": created,
			"updated": updated,
		})
	})
	authGroup.POST("/peers/auto", func(c *gin.Context) {
		var nodes []Node
		db.Preload("Routes").Preload("Peers").Find(&nodes)
		var allNodes []Node
		db.Find(&allNodes)
		pubMap := make(map[string][]string, len(allNodes))
		for _, n := range allNodes {
			if len(n.PublicIPs) > 0 {
				pubMap[n.Name] = n.PublicIPs
			}
		}
		created := 0
		updated := 0
		for i := range nodes {
			node := &nodes[i]
			selfHasV6 := false
			for _, ip := range node.PublicIPs {
				if strings.Contains(ip, ":") {
					selfHasV6 = true
					break
				}
			}
			neighbors := make(map[string]struct{})
			for _, r := range node.Routes {
				for i := 0; i+1 < len(r.Path); i++ {
					if r.Path[i] == node.Name {
						neighbors[string(r.Path[i+1])] = struct{}{}
					}
				}
			}
			existing := make(map[string]*Peer, len(node.Peers))
			for i := range node.Peers {
				p := &node.Peers[i]
				existing[p.PeerName] = p
			}
			for peerName := range neighbors {
				if peerName == "" || peerName == node.Name {
					continue
				}
				if cur, ok := existing[peerName]; ok {
					if cur.EntryIP == "" {
						entryIP := ""
						if ips, ok := pubMap[peerName]; ok && len(ips) > 0 {
							for _, ip := range ips {
								if selfHasV6 && strings.Contains(ip, ":") {
									entryIP = ip
									break
								}
							}
							if entryIP == "" {
								for _, ip := range ips {
									if !strings.Contains(ip, ":") {
										entryIP = ip
										break
									}
								}
							}
							if entryIP == "" {
								entryIP = ips[0]
							}
						}
						if entryIP != "" {
							if err := db.Model(&Peer{}).Where("id = ? AND node_id = ?", cur.ID, node.ID).Updates(map[string]interface{}{
								"entry_ip": entryIP,
							}).Error; err == nil {
								updated++
							}
						}
					}
					continue
				}
				entryIP := ""
				if ips, ok := pubMap[peerName]; ok && len(ips) > 0 {
					for _, ip := range ips {
						if selfHasV6 && strings.Contains(ip, ":") {
							entryIP = ip
							break
						}
					}
					if entryIP == "" {
						for _, ip := range ips {
							if !strings.Contains(ip, ":") {
								entryIP = ip
								break
							}
						}
					}
					if entryIP == "" {
						entryIP = ips[0]
					}
				}
				newPeer := Peer{
					NodeID:   node.ID,
					PeerName: peerName,
					EntryIP:  entryIP,
				}
				if err := db.Create(&newPeer).Error; err == nil {
					created++
				}
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"created": created,
			"updated": updated,
		})
	})
	authGroup.PUT("/nodes/:id/peers/:peerId", func(c *gin.Context) {
		id := c.Param("id")
		pid := c.Param("peerId")
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
		if err := db.Model(&Peer{}).Where("id = ? AND node_id = ?", pid, id).Updates(map[string]interface{}{
			"peer_name": req.PeerName,
			"entry_ip":  req.EntryIP,
			"exit_ip":   req.ExitIP,
			"endpoint":  req.Endpoint,
		}).Error; err != nil {
			c.String(http.StatusBadRequest, "update failed: %v", err)
			return
		}
		var peer Peer
		db.First(&peer, pid)
		c.JSON(http.StatusOK, peer)
	})
	authGroup.DELETE("/nodes/:id/peers/:peerId", func(c *gin.Context) {
		id := c.Param("id")
		pid := c.Param("peerId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := db.Delete(&Peer{}, "id = ? AND node_id = ?", pid, id).Error; err != nil {
			c.String(http.StatusBadRequest, "delete failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})

	authGroup.GET("/nodes/:id/routes", func(c *gin.Context) {
		id := c.Param("id")
		var routes []RoutePlan
		db.Where("node_id = ?", id).Order("priority asc, id asc").Find(&routes)
		c.JSON(http.StatusOK, routes)
	})
	api.GET("/node-routes/:name", func(c *gin.Context) {
		// 节点 token 校验
		nodeToken := getBearerToken(c)
		if _, err := findNodeByToken(db, nodeToken); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		name := c.Param("name")
		var node Node
		if err := db.Preload("Routes").Where("name = ?", name).First(&node).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		routes := make([]RouteConfig, 0, len(node.Routes))
		for _, r := range node.Routes {
			routes = append(routes, RouteConfig{
				Name:     r.Name,
				Exit:     r.Exit,
				Remote:   r.Remote,
				Priority: r.Priority,
				Path:     []string(r.Path),
				ReturnPath: []string(r.ReturnPath),
			})
		}
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Priority == routes[j].Priority {
				return routes[i].Name < routes[j].Name
			}
			return routes[i].Priority < routes[j].Priority
		})
		c.JSON(http.StatusOK, gin.H{"routes": routes})
	})
	authGroup.POST("/nodes/:id/routes", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req RoutePlan
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		req.NodeID = node.ID
		if req.Priority == 0 {
			req.Priority = 1
		}
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})
	authGroup.PUT("/nodes/:id/routes/:routeId", func(c *gin.Context) {
		id := c.Param("id")
		rid := c.Param("routeId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req RoutePlan
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if err := db.Model(&RoutePlan{}).Where("id = ? AND node_id = ?", rid, id).Updates(map[string]any{
			"name":       req.Name,
			"exit":       req.Exit,
			"remote":     req.Remote,
			"priority":   req.Priority,
			"path":       req.Path,
			"return_path": req.ReturnPath,
			"updated_at": time.Now(),
		}).Error; err != nil {
			c.String(http.StatusBadRequest, "update failed: %v", err)
			return
		}
		var route RoutePlan
		db.First(&route, rid)
		c.JSON(http.StatusOK, route)
	})
	authGroup.DELETE("/nodes/:id/routes/:routeId", func(c *gin.Context) {
		id := c.Param("id")
		rid := c.Param("routeId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := db.Delete(&RoutePlan{}, "id = ? AND node_id = ?", rid, id).Error; err != nil {
			c.String(http.StatusBadRequest, "delete failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})

	authGroup.GET("/return-status", func(c *gin.Context) {
		var rows []ReturnRouteStatus
		db.Order("updated_at desc").Find(&rows)
		c.JSON(http.StatusOK, rows)
	})

	// 手工设置节点公网IP
	authGroup.PUT("/nodes/:id/public-ips", func(c *gin.Context) {
		id := c.Param("id")
		var req struct {
			PublicIPs []string `json:"public_ips"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		ips := make([]string, 0)
		for _, ip := range req.PublicIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
		if err := db.Model(&Node{}).Where("id = ?", id).Update("public_ips", StringList(ips)).Error; err != nil {
			c.String(http.StatusInternalServerError, "update failed: %v", err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"public_ips": ips})
	})

	api.POST("/metrics", func(c *gin.Context) {
		// 节点 token 校验
		nodeToken := getBearerToken(c)
		node, err := findNodeByToken(db, nodeToken)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var payload struct {
			From    string                     `json:"from"`
			Metrics map[string]LinkMetricsJSON `json:"metrics"`
			ReturnStats []ReturnStatJSON       `json:"return_stats"`
			Status  struct {
				CPUUsage    float64  `json:"cpu_usage"`
				MemUsed     uint64   `json:"mem_used_bytes"`
				MemTotal    uint64   `json:"mem_total_bytes"`
				UptimeSec   uint64   `json:"uptime_sec"`
				NetInBytes  uint64   `json:"net_in_bytes"`
				NetOutBytes uint64   `json:"net_out_bytes"`
				Version     string   `json:"version"`
				Transport   string   `json:"transport"`
				Compression string   `json:"compression"`
				OS          string   `json:"os"`
				Arch        string   `json:"arch"`
				PublicIPs   []string `json:"public_ips"`
			} `json:"status"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		applyMetricsPayload(db, node, payload)
		c.Status(http.StatusNoContent)
	})

	api.POST("/probe/e2e", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		node, err := findNodeByToken(db, nodeToken)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var req struct {
			Route   string   `json:"route"`
			Path    []string `json:"path"`
			RTTMs   int64    `json:"rtt_ms"`
			Success bool     `json:"success"`
			Error   string   `json:"error"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if strings.TrimSpace(req.Route) == "" || len(req.Path) == 0 {
			c.String(http.StatusBadRequest, "route and path required")
			return
		}
		probe := RouteProbe{
			Node:    node.Name,
			Route:   req.Route,
			Path:    StringList(req.Path),
			RTTMs:   req.RTTMs,
			Success: req.Success,
			Error:   req.Error,
		}
		if err := db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "node"}, {Name: "route"}},
			DoUpdates: clause.Assignments(map[string]interface{}{"path": probe.Path, "rtt_ms": probe.RTTMs, "success": probe.Success, "error": probe.Error, "updated_at": time.Now()}),
		}).Create(&probe).Error; err != nil {
			c.String(http.StatusInternalServerError, "save failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})

	// 线路测试触发：指定节点、目标（对端名称或 host），推送到节点 WS。
	authGroup.POST("/probe/request", func(c *gin.Context) {
		var req struct {
			Node   string `json:"node"`   // 节点名称
			Target string `json:"target"` // 目标节点/host
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Node) == "" || strings.TrimSpace(req.Target) == "" {
			c.String(http.StatusBadRequest, "node and target required")
			return
		}
		if err := hub.sendCommand(req.Node, map[string]any{
			"type": "probe",
			"data": map[string]any{"target": req.Target},
		}); err != nil {
			c.String(http.StatusServiceUnavailable, "node offline or send failed: %v", err)
			return
		}
		c.Status(http.StatusAccepted)
	})

	// 线路端到端延迟测试：指定节点 + 路径，控制器经 WS 下发，节点执行 HTTP 探测并回报。
	authGroup.POST("/route-test", func(c *gin.Context) {
		var req struct {
			Node   string   `json:"node"`
			Route  string   `json:"route"`
			Path   []string `json:"path"`
			Target string   `json:"target"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Node) == "" || len(req.Path) == 0 {
			c.String(http.StatusBadRequest, "node, path required")
			return
		}
		if err := hub.sendCommand(req.Node, map[string]any{
			"type": "route_test",
			"data": map[string]any{
				"route":  req.Route,
				"path":   req.Path,
				"target": req.Target,
			},
		}); err != nil {
			c.String(http.StatusServiceUnavailable, "node offline or send failed: %v", err)
			return
		}
		c.Status(http.StatusAccepted)
	})

	authGroup.POST("/route-diag/run", func(c *gin.Context) {
		var req struct {
			Node       string   `json:"node"`
			Route      string   `json:"route"`
			Path       []string `json:"path"`
			ReturnPath []string `json:"return_path"`
			Target     string   `json:"target"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Node) == "" || len(req.Path) == 0 {
			c.String(http.StatusBadRequest, "node, path required")
			return
		}
		run := newDiagTraceRun()
		// collect logs for forward + return nodes
		nodeSet := make(map[string]struct{})
		for _, p := range req.Path {
			if strings.TrimSpace(p) != "" {
				nodeSet[p] = struct{}{}
			}
		}
		for _, p := range req.ReturnPath {
			if strings.TrimSpace(p) != "" {
				nodeSet[p] = struct{}{}
			}
		}
		nodes := make([]string, 0, len(nodeSet))
		for n := range nodeSet {
			nodes = append(nodes, n)
		}
		sort.Strings(nodes)
		ensureDiagRun(run.RunID, nodes)
		offline := make([]string, 0)
		for _, name := range nodes {
			if err := hub.sendCommand(name, map[string]any{
				"type": "diag_collect",
				"data": map[string]any{
					"run_id":   run.RunID,
					"limit":        400,
					"contains":     "",
					"clear_before": true,
					"delay_ms":     12000,
				},
			}); err != nil {
				offline = append(offline, name)
			}
		}
		if err := hub.sendCommand(req.Node, map[string]any{
			"type": "route_diag",
			"data": map[string]any{
				"run_id":      run.RunID,
				"route":       req.Route,
				"path":        req.Path,
				"return_path": req.ReturnPath,
				"target":      req.Target,
			},
		}); err != nil {
			c.String(http.StatusServiceUnavailable, "node offline or send failed: %v", err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"run_id":  run.RunID,
			"offline": offline,
		})
	})

	authGroup.GET("/route-diag", func(c *gin.Context) {
		runID := strings.TrimSpace(c.Query("run_id"))
		run := getDiagTraceRun(runID)
		if run == nil {
			c.JSON(http.StatusOK, gin.H{"run_id": runID, "events": []DiagTraceEvent{}})
			return
		}
		sort.Slice(run.Events, func(i, j int) bool {
			return run.Events[i].At < run.Events[j].At
		})
		c.JSON(http.StatusOK, gin.H{
			"run_id":     run.RunID,
			"created_at": run.CreatedAt,
			"events":     run.Events,
		})
	})

	authGroup.POST("/diag/run", func(c *gin.Context) {
		var req struct {
			Nodes    []string `json:"nodes"`
			Limit    int      `json:"limit"`
			Contains string   `json:"contains"`
		}
		_ = c.ShouldBindJSON(&req)
		var nodes []Node
		db.Find(&nodes)
		targets := make([]string, 0)
		if len(req.Nodes) == 0 {
			for _, n := range nodes {
				targets = append(targets, n.Name)
			}
		} else {
			targets = append(targets, req.Nodes...)
		}
		run := newDiagRun(targets)
		sent := make([]string, 0, len(targets))
		offline := make([]string, 0)
		for _, name := range targets {
			if err := hub.sendCommand(name, map[string]any{
				"type": "diag_collect",
				"data": map[string]any{
					"run_id":   run.RunID,
					"limit":    req.Limit,
					"contains": req.Contains,
				},
			}); err != nil {
				offline = append(offline, name)
				continue
			}
			sent = append(sent, name)
		}
		c.JSON(http.StatusOK, gin.H{
			"run_id":   run.RunID,
			"sent":     sent,
			"offline":  offline,
			"nodes":    targets,
			"limit":    req.Limit,
			"contains": req.Contains,
		})
	})

	authGroup.GET("/diag", func(c *gin.Context) {
		runID := strings.TrimSpace(c.Query("run_id"))
		run := getDiagRun(runID)
		if run == nil {
			c.JSON(http.StatusOK, gin.H{"run_id": runID, "nodes": []string{}, "reports": []DiagReport{}, "missing": []string{}})
			return
		}
		reports := make([]DiagReport, 0, len(run.Reports))
		missing := make([]string, 0)
		seen := make(map[string]struct{}, len(run.Reports))
		for node, rep := range run.Reports {
			reports = append(reports, rep)
			seen[node] = struct{}{}
		}
		for _, node := range run.Nodes {
			if _, ok := seen[node]; !ok {
				missing = append(missing, node)
			}
		}
		sort.Slice(reports, func(i, j int) bool {
			return reports[i].Node < reports[j].Node
		})
		c.JSON(http.StatusOK, gin.H{
			"run_id":     run.RunID,
			"created_at": run.CreatedAt,
			"nodes":      run.Nodes,
			"reports":    reports,
			"missing":    missing,
		})
	})

	authGroup.POST("/diag/refresh", func(c *gin.Context) {
		var req struct {
			RunID    string `json:"run_id"`
			Limit    int    `json:"limit"`
			Contains string `json:"contains"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.RunID) == "" {
			c.String(http.StatusBadRequest, "run_id required")
			return
		}
		run := getDiagRun(req.RunID)
		if run == nil || len(run.Nodes) == 0 {
			c.String(http.StatusNotFound, "run not found")
			return
		}
		offline := make([]string, 0)
		for _, name := range run.Nodes {
			if err := hub.sendCommand(name, map[string]any{
				"type": "diag_collect",
				"data": map[string]any{
					"run_id":   run.RunID,
					"limit":    req.Limit,
					"contains": req.Contains,
				},
			}); err != nil {
				offline = append(offline, name)
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"run_id":  run.RunID,
			"offline": offline,
		})
	})

	// WebSocket 通道：节点推送 metrics，后续可扩展控制器下发实时指令。
	api.GET("/ws", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		node, err := findNodeByToken(db, nodeToken)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		ws, err := wscompat.Accept(c.Writer, c.Request, &wscompat.AcceptOptions{})
		if err != nil {
			return
		}
		hub.register(node.Name, ws)
		ctx := c.Request.Context()
		// 控制器也定期发 ping，避免中间设备超时关闭
		done := make(chan struct{})
		go func() {
			t := time.NewTicker(20 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-done:
					return
				case <-t.C:
					_ = ws.Ping(context.Background())
				}
			}
		}()
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				ws.Close()
				hub.unregister(node.Name, ws)
				close(done)
				return
			}
			var msg struct {
				Type string          `json:"type"`
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			switch msg.Type {
			case "metrics":
				var payload struct {
					From    string                     `json:"from"`
					Metrics map[string]LinkMetricsJSON `json:"metrics"`
					ReturnStats []ReturnStatJSON       `json:"return_stats"`
					Status  struct {
						CPUUsage    float64  `json:"cpu_usage"`
						MemUsed     uint64   `json:"mem_used_bytes"`
						MemTotal    uint64   `json:"mem_total_bytes"`
						UptimeSec   uint64   `json:"uptime_sec"`
						NetInBytes  uint64   `json:"net_in_bytes"`
						NetOutBytes uint64   `json:"net_out_bytes"`
						Version     string   `json:"version"`
						Transport   string   `json:"transport"`
						Compression string   `json:"compression"`
						OS          string   `json:"os"`
						Arch        string   `json:"arch"`
						PublicIPs   []string `json:"public_ips"`
					} `json:"status"`
				}
				if err := json.Unmarshal(msg.Data, &payload); err != nil {
					continue
				}
				if payload.From == "" {
					payload.From = node.Name
				}
				applyMetricsPayload(db, node, payload)
			case "route_test_result":
				var res struct {
					Route   string   `json:"route"`
					Path    []string `json:"path"`
					Target  string   `json:"target"`
					RTTMs   int64    `json:"rtt_ms"`
					Success bool     `json:"success"`
					Error   string   `json:"error"`
				}
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				if strings.TrimSpace(res.Route) == "" || len(res.Path) == 0 {
					continue
				}
				probe := RouteProbe{
					Node:    node.Name,
					Route:   res.Route,
					Path:    StringList(res.Path),
					RTTMs:   res.RTTMs,
					Success: res.Success,
					Error:   res.Error,
				}
				db.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "node"}, {Name: "route"}},
					DoUpdates: clause.Assignments(map[string]interface{}{"path": probe.Path, "rtt_ms": probe.RTTMs, "success": probe.Success, "error": probe.Error, "updated_at": time.Now()}),
				}).Create(&probe)
			case "update_status":
				var res struct {
					Status  string `json:"status"`
					Version string `json:"version"`
					Reason  string `json:"reason"`
					Forced  bool   `json:"forced"`
				}
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				status := NodeUpdateStatus{
					Node:    node.Name,
					Status:  res.Status,
					Version: res.Version,
					Reason:  res.Reason,
					Forced:  res.Forced,
				}
				db.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "node"}},
					DoUpdates: clause.Assignments(map[string]interface{}{"status": status.Status, "version": status.Version, "reason": status.Reason, "forced": status.Forced, "updated_at": time.Now()}),
				}).Create(&status)
			case "diag_report":
				var res struct {
					RunID   string   `json:"run_id"`
					Node    string   `json:"node"`
					At      int64    `json:"at"`
					Lines   []string `json:"lines"`
					Limit   int      `json:"limit"`
					Filter  string   `json:"filter"`
				}
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				if res.Node == "" {
					res.Node = node.Name
				}
				at := time.Now()
				if res.At > 0 {
					at = time.UnixMilli(res.At)
				}
				storeDiagReport(res.RunID, DiagReport{
					RunID:  res.RunID,
					Node:   res.Node,
					At:     at,
					Lines:  res.Lines,
					Limit:  res.Limit,
					Filter: res.Filter,
				})
			case "diag_event":
				var res DiagTraceEvent
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				if res.Node == "" {
					res.Node = node.Name
				}
				if res.At == 0 {
					res.At = time.Now().UnixMilli()
				}
				storeDiagTraceEvent(res)
			case "endpoint_check_result":
				var res struct {
					RunID   string               `json:"run_id"`
					Node    string               `json:"node"`
					Results []EndpointCheckResult `json:"results"`
				}
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				if res.Node == "" {
					res.Node = node.Name
				}
				for i := range res.Results {
					if res.Results[i].Node == "" {
						res.Results[i].Node = res.Node
					}
				}
				storeEndpointCheckResults(res.RunID, res.Results)
			default:
			}
		}
	})

	authGroup.GET("/probes", func(c *gin.Context) {
		var probes []RouteProbe
		db.Order("updated_at desc").Find(&probes)
		c.JSON(http.StatusOK, probes)
	})

	api.GET("/topology", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		if _, err := findNodeByToken(db, nodeToken); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var rows []LinkMetric
		db.Find(&rows)
		edges := make(map[string]map[string]LinkMetricsJSON)
		for _, r := range rows {
			if edges[r.From] == nil {
				edges[r.From] = make(map[string]LinkMetricsJSON)
			}
			edges[r.From][r.To] = LinkMetricsJSON{RTTms: r.RTTMs, Loss: r.Loss, UpdatedAt: r.UpdatedAt}
		}
		c.JSON(http.StatusOK, gin.H{"edges": edges})
	})

	authGroup.POST("/endpoint-check/run", func(c *gin.Context) {
		var req struct {
			Nodes []string `json:"nodes"`
		}
		_ = c.ShouldBindJSON(&req)
		var nodes []Node
		db.Find(&nodes)
		targets := make([]string, 0, len(nodes))
		if len(req.Nodes) == 0 {
			for _, n := range nodes {
				targets = append(targets, n.Name)
			}
		} else {
			targets = append(targets, req.Nodes...)
		}
		run := newEndpointCheckRun(targets)
		offline := make([]string, 0)
		for _, name := range targets {
			if err := hub.sendCommand(name, map[string]any{
				"type": "endpoint_check",
				"data": map[string]any{
					"run_id": run.RunID,
				},
			}); err != nil {
				offline = append(offline, name)
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"run_id":  run.RunID,
			"offline": offline,
		})
	})
	authGroup.GET("/endpoint-check", func(c *gin.Context) {
		runID := strings.TrimSpace(c.Query("run_id"))
		run := getEndpointCheckRun(runID)
		if run == nil {
			c.JSON(http.StatusOK, gin.H{"run_id": runID, "results": []EndpointCheckResult{}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"run_id": run.RunID, "results": run.Results, "nodes": run.Nodes})
	})

	// 提供嵌入的节点二进制下载，按 os/arch 返回对应文件。
	r.GET("/downloads/arouter", func(c *gin.Context) {
		osName := strings.ToLower(c.Query("os"))
		if osName == "" {
			osName = "linux"
		}
		arch := strings.ToLower(c.Query("arch"))
		if arch == "" {
			arch = "amd64"
		}
		filename := fmt.Sprintf("dist/arouter-%s-%s", osName, arch)
		data, err := embeddedNodeBins.ReadFile(filename)
		if err != nil {
			c.String(http.StatusNotFound, "binary not found for %s/%s", osName, arch)
			return
		}
		sum := sha256.Sum256(data)
		c.Header("X-Checksum-SHA256", hex.EncodeToString(sum[:]))
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="arouter-%s-%s"`, osName, arch))
		c.Data(http.StatusOK, "application/octet-stream", data)
	})

	// 返回填充好的 config_pull.sh
	r.GET("/nodes/:id/config_pull.sh", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		// token 校验，与 config 相同策略
		tokenHeader := getBearerToken(c)
		if tokenHeader == "" {
			if t := c.Query("token"); t != "" {
				tokenHeader = "Bearer " + t
			}
		}
		if token := strings.TrimPrefix(tokenHeader, "Bearer "); token == "" || token != node.Token {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		installDir := c.Query("install_dir")
		if strings.TrimSpace(installDir) == "" {
			installDir = "/opt/arouter"
		}
		configURL := c.Query("config_url")
		if configURL == "" {
			if b64 := c.Query("config_url_b64"); b64 != "" {
				if data, err := base64.StdEncoding.DecodeString(b64); err == nil {
					configURL = string(data)
				}
			}
		}
		if configURL == "" {
			scheme := "http"
			if c.Request.TLS != nil {
				scheme = "https"
			}
			hostBase := scheme + "://" + c.Request.Host
			configURL = fmt.Sprintf("%s/nodes/%d/config?token=%s", hostBase, node.ID, url.QueryEscape(node.Token))
		}
		proxy := c.Query("proxy_prefix")
		tokenVal := c.Query("token_override")
		if tokenVal == "" {
			tokenVal = node.Token
		}
		script := renderConfigPullScript(installDir, configURL, tokenVal, proxy)
		c.Header("Content-Type", "text/x-shellscript")
		c.String(http.StatusOK, script)
	})

	// 生成节点 config.json
	r.GET("/nodes/:id/config", func(c *gin.Context) {
		nodeToken := c.GetHeader("Authorization")
		if nodeToken == "" {
			if t := c.Query("token"); t != "" {
				nodeToken = "Bearer " + t
			}
		}
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").Preload("Routes").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if node.Token == "" {
			ensureNodeToken(db, &node)
		}
		if token := strings.TrimPrefix(nodeToken, "Bearer "); token == "" || token != node.Token {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var all []Node
		db.Find(&all)
		settings := loadSettings(db)
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		base := scheme + "://" + c.Request.Host
		cfg := buildConfig(node, all, globalKey, base, settings)
		osHint := strings.ToLower(c.Query("os"))
		cfg = applyOSOverrides(cfg, osHint)
		if dir := c.Query("install_dir"); dir != "" {
			if strings.HasSuffix(dir, "/.arouter") {
				dir = strings.TrimSuffix(dir, "/.arouter")
			}
			cfg = applyInstallDirOverrides(cfg, dir)
		}
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-config.json"`, node.Name))
		c.JSON(http.StatusOK, cfg)
	})

	// 生成节点安装脚本（内嵌 config，并包含后续自动拉取配置的 URL）
	r.GET("/nodes/:id/install.sh", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if node.Token == "" {
			ensureNodeToken(db, &node)
		}
		authHeader := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if authHeader == "" {
			authHeader = c.Query("token")
		}
		authorized := authHeader != "" && authHeader == node.Token
		if !authorized {
			if tok := getBearerToken(c); tok != "" {
				if claims, err := parseJWT(tok); err == nil {
					var u User
					if err := db.First(&u, claims.UserID).Error; err == nil {
						authorized = true
					}
				}
			}
		}
		if !authorized {
			// 最后兜底：如果没有用户存在且首次访问，直接允许下载
			var cnt int64
			db.Model(&User{}).Count(&cnt)
			if cnt == 0 {
				authorized = true
			}
		}
		if !authorized {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var all []Node
		db.Find(&all)
		settings := loadSettings(db)
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		base := scheme + "://" + c.Request.Host
		cfg := buildConfig(node, all, globalKey, base, settings)
		osHint := strings.ToLower(c.Query("os"))
		cfg = applyOSOverrides(cfg, osHint)
		data, _ := json.MarshalIndent(cfg, "", "  ")
		configURL := fmt.Sprintf("%s/nodes/%s/config?token=%s", base, id, url.QueryEscape(node.Token))
		configPullBase := fmt.Sprintf("%s/nodes/%s/config_pull.sh?token=%s", base, id, url.QueryEscape(node.Token))
		c.Header("Content-Type", "text/x-shellscript")
		c.Header("Content-Disposition", "attachment; filename=\"install.sh\"")
		syncInt := syncIntervalFromConfig(data)
		c.String(http.StatusOK, installScript(string(data), configURL, configPullBase, base, syncInt))
	})

	// 全局系统设置（传输/压缩）读写接口
	r.GET("/api/settings", authUserMiddleware(db), func(c *gin.Context) {
		c.JSON(http.StatusOK, loadSettings(db))
	})
	r.POST("/api/settings", authUserMiddleware(db), func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		var req Setting
		if err := c.BindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		maybeCheckpoint(db)
		var saved Setting
		err := db.Transaction(func(tx *gorm.DB) error {
			var s Setting
			if err := tx.First(&s).Error; err != nil {
				return err
			}
			if strings.TrimSpace(req.Transport) != "" {
				s.Transport = strings.TrimSpace(req.Transport)
			}
			if strings.TrimSpace(req.Compression) != "" {
				s.Compression = strings.TrimSpace(req.Compression)
			}
			if req.CompressionMin >= 0 {
				s.CompressionMin = req.CompressionMin
			}
			s.DebugLog = req.DebugLog
			if req.EncryptionPolicies != nil {
				s.EncryptionPolicies = req.EncryptionPolicies.normalize()
			}
			if strings.TrimSpace(req.HTTPProbeURL) != "" {
				s.HTTPProbeURL = strings.TrimSpace(req.HTTPProbeURL)
			}
			if err := tx.Save(&s).Error; err != nil {
				return err
			}
			saved = s
			return nil
		})
		if err != nil {
			if isSQLiteFull(err) {
				c.String(http.StatusInsufficientStorage, "写入失败：磁盘空间不足或 SQLite 无写权限，请清理空间或改用 MySQL。原始错误: %v", err)
				return
			}
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, saved)
	})

	addr := envOrDefault("CONTROLLER_ADDR", ":8080")
	log.Printf("controller listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("controller run failed: %v", err)
	}
}

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
			Name:     r.Name,
			Exit:     r.Exit,
			Remote:   r.Remote,
			Priority: r.Priority,
			Path:     []string(r.Path),
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
		ID:              node.Name,
		WSListen:        defaultIfEmpty(stripPortPrefix(node.WSListen), "18080"),
		WSSListen:       stripPortPrefix(node.WSSListen),
		QUICListen:      defaultIfEmpty(stripPortPrefix(node.QUICListen), stripPortPrefix(node.WSListen)),
		QUICServerName:  defaultIfEmpty(node.QUICServerName, "arouter.529851.xyz"),
		Peers:           peers,
		Entries:         entries,
		PollPeriod:      defaultIfEmpty(node.PollPeriod, "5s"),
		InsecureSkipTLS: true,
		AuthKey:         firstNonEmpty(globalKey, node.AuthKey, randomKey()),
		MetricsListen:   defaultIfEmpty(stripPortPrefix(node.MetricsListen), "19090"),
		RerouteAttempts: defaultInt(node.RerouteAttempts, 3),
		UDPSessionTTL:   defaultIfEmpty(node.UDPSessionTTL, "60s"),
		MTLSCert:        defaultIfEmpty(node.MTLSCert, "/opt/arouter/certs/arouter.crt"),
		MTLSKey:         defaultIfEmpty(node.MTLSKey, "/opt/arouter/certs/arouter.key"),
		MTLSCA:          node.MTLSCA,
		ControllerURL:   defaultIfEmpty(node.ControllerURL, controllerBase),
		Routes:          routes,
		Compression:     defaultIfEmpty(settings.Compression, "gzip"),
		CompressionMin:  defaultInt(settings.CompressionMin, node.CompressionMin),
		Transport:       defaultIfEmpty(settings.Transport, "quic"),
		DebugLog:        settings.DebugLog,
		TokenPath:       "/opt/arouter/.token",
		OS:              node.OSName,
		Arch:            node.Arch,
		HTTPProbeURL:    settings.HTTPProbeURL,
		Encryption:      settings.EncryptionPolicies,
		MaxMuxStreams:   node.MaxMuxStreams,
		MuxMaxAge:       node.MuxMaxAge,
		MuxMaxIdle:      node.MuxMaxIdle,
		MemLimit:        memLimit,
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

type IfAddr struct {
	Iface string `json:"iface"`
	Addr  string `json:"addr"`
}

func canonicalVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if v == "" {
		return v
	}
	return "v" + v
}

func listPublicIfAddrs() []IfAddr {
	ifaces, _ := net.Interfaces()
	var res []IfAddr
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || isPrivateOrLinkLocal(ip) {
				continue
			}
			res = append(res, IfAddr{Iface: iface.Name, Addr: ip.String()})
		}
	}
	return res
}

func isPrivateOrLinkLocal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 10 || v4[0] == 127 {
			return true
		}
		if v4[0] == 192 && v4[1] == 168 {
			return true
		}
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return true
		}
		return false
	}
	// IPv6: unique local fc00::/7
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

func detectPublicIPs() (string, string) {
	client := &http.Client{Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v4 := fetchIP(ctx, client, "https://4.ipw.cn/")
	v6 := fetchIP(ctx, client, "https://6.ipw.cn/")
	return strings.TrimSpace(v4), strings.TrimSpace(v6)
}

func fetchIP(ctx context.Context, client *http.Client, url string) string {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	return string(b)
}

func installScript(configJSON string, configURL string, configPullBase string, binBase string, syncInterval string) string {
	script := `#!/usr/bin/env bash
set -euo pipefail

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
if [ "$OS" = "darwin" ]; then
  # 将默认的 /opt/arouter 路径重写为当前安装目录，便于证书/配置落在用户目录
  python3 - <<'PY'
import json, os, pathlib
cfg_path = pathlib.Path("config.json")
cfg = json.loads(cfg_path.read_text())
inst = os.environ.get("INSTALL_DIR", "/opt/arouter")
def repl(v):
    if isinstance(v, str) and v.startswith("/opt/arouter"):
        return v.replace("/opt/arouter", inst, 1)
    return v
for key in ("mtls_cert","mtls_key","mtls_ca","token_path"):
    if key in cfg:
        cfg[key] = repl(cfg[key])
cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
PY
  echo "DEBUG: config.json rewritten for darwin install dir ${INSTALL_DIR}" >&2
fi
# 展开 config.json 中的路径占位符（${HOME} 或 /opt/arouter -> INSTALL_DIR）
python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path("config.json")
cfg = json.loads(p.read_text())
home = os.environ.get("HOME","")
inst = os.environ.get("INSTALL_DIR","")
def expand(v):
    if not isinstance(v, str):
        return v
    if "${HOME}" in v and home:
        v = v.replace("${HOME}", home)
    if inst and v.startswith("/opt/arouter"):
        v = v.replace("/opt/arouter", inst, 1)
    return v
for key in ("mtls_cert","mtls_key","mtls_ca","token_path"):
    if key in cfg:
        cfg[key] = expand(cfg[key])
p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
PY
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

func mustOpenDB() *gorm.DB {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dbPath := envOrDefault("DB_PATH", "./data/arouter.db")
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
			log.Fatalf("create db dir failed: %v", err)
		}
		return openSQLiteWithPragma(dbPath)
	}
	if strings.HasPrefix(dsn, "sqlite:") {
		path := strings.TrimPrefix(dsn, "sqlite:")
		return openSQLiteWithPragma(path)
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("open mysql failed: %v", err)
	}
	return db
}

// openSQLiteWithPragma 为 sqlite 添加常用的 pragma，减少磁盘压力并提高兼容性。
func openSQLiteWithPragma(path string) *gorm.DB {
	// busy_timeout 避免瞬时锁导致失败；WAL 提高并发；同步设为 NORMAL 兼顾性能。
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("open sqlite failed: %v", err)
	}
	// 单连接即可，避免 WAL checkpoint 被阻塞
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	return db
}

// maybeCheckpoint 在 SQLite 下进行 WAL checkpoint，避免 WAL 长大导致“disk is full”。
func maybeCheckpoint(db *gorm.DB) {
	if db == nil || db.Dialector.Name() != "sqlite" {
		return
	}
	db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
}

// isSQLiteFull 检测 SQLite 的磁盘/权限问题。
func isSQLiteFull(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database or disk is full") ||
		strings.Contains(msg, "no space left on device") ||
		strings.Contains(msg, "attempt to write a readonly database")
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ensureGlobalSettings 确保全局设置存在（单行），默认从环境获取或使用内置值。
func ensureGlobalSettings(db *gorm.DB) {
	var cnt int64
	if err := db.Model(&Setting{}).Count(&cnt).Error; err != nil {
		log.Printf("count settings failed: %v", err)
		return
	}
	if cnt == 0 {
		def := Setting{
			Transport:      envOrDefault("GLOBAL_TRANSPORT", "quic"),
			Compression:    envOrDefault("GLOBAL_COMPRESSION", "none"),
			CompressionMin: 0,
			DebugLog:       false,
			HTTPProbeURL:   envOrDefault("GLOBAL_HTTP_PROBE_URL", "https://www.google.com/generate_204"),
			EncryptionPolicies: EncPolicyList{
				{ID: 1, Name: "aes128", Method: "aes-128-gcm", Key: "YWFhYWFhYWFhYWFhYWFhYQ=="},
				{ID: 2, Name: "chacha", Method: "chacha20-poly1305", Key: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="},
			},
		}
		def.EncryptionPolicies = def.EncryptionPolicies.normalize()
		if err := db.Create(&def).Error; err != nil {
			log.Printf("create default settings failed: %v", err)
		} else {
			log.Printf("created default global settings: %+v", def)
		}
	}
}

func loadSettings(db *gorm.DB) Setting {
	var s Setting
	if err := db.First(&s).Error; err != nil {
		log.Printf("load settings failed, using defaults: %v", err)
		return Setting{
			Transport:      envOrDefault("GLOBAL_TRANSPORT", "quic"),
			Compression:    envOrDefault("GLOBAL_COMPRESSION", "none"),
			CompressionMin: 0,
			DebugLog:       false,
			HTTPProbeURL:   envOrDefault("GLOBAL_HTTP_PROBE_URL", "https://www.google.com/generate_204"),
			EncryptionPolicies: EncPolicyList{
				{ID: 1, Name: "aes128", Method: "aes-128-gcm", Key: "YWFhYWFhYWFhYWFhYWFhYQ=="},
			}.normalize(),
		}
	}
	if strings.TrimSpace(s.HTTPProbeURL) == "" {
		s.HTTPProbeURL = envOrDefault("GLOBAL_HTTP_PROBE_URL", "https://www.google.com/generate_204")
	}
	if len(s.EncryptionPolicies) == 0 {
		s.EncryptionPolicies = EncPolicyList{
			{ID: 1, Name: "aes128", Method: "aes-128-gcm", Key: "YWFhYWFhYWFhYWFhYWFhYQ=="},
		}.normalize()
	}
	s.EncryptionPolicies = s.EncryptionPolicies.normalize()
	return s
}

func generateToken() string {
	b := make([]byte, 16)
	_, _ = time.Now().UTC().MarshalBinary()
	for i := range b {
		b[i] = byte(65 + i)
	}
	return fmt.Sprintf("tok-%d", time.Now().UnixNano())
}

func ensureNodeToken(db *gorm.DB, n *Node) {
	if n.Token == "" {
		n.Token = generateToken()
		db.Model(&Node{}).Where("id = ?", n.ID).Update("token", n.Token)
	}
}

func ensureAdminExists(db *gorm.DB, username, password string) {
	var cnt int64
	db.Model(&User{}).Count(&cnt)
	if cnt == 0 && username != "" && password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		db.Create(&User{Username: username, PasswordHash: string(hash), IsAdmin: true})
	}
}

func issueJWT(u User) (string, error) {
	claims := UserClaims{UserID: u.ID, IsAdmin: u.IsAdmin}
	b, _ := json.Marshal(claims)
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write(b)
	sig := mac.Sum(nil)
	return fmt.Sprintf("%s.%x", b, sig), nil
}

func parseJWT(token string) (*UserClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token")
	}
	b := []byte(parts[0])
	sig, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write(b)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return nil, fmt.Errorf("invalid signature")
	}
	var claims UserClaims
	if err := json.Unmarshal(b, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func authUserMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		claims, err := parseJWT(token)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var user User
		if err := db.First(&user, claims.UserID).Error; err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("user", user)
		c.Next()
	}
}

func requireAdmin(c *gin.Context) {
	uVal, ok := c.Get("user")
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	u := uVal.(User)
	if !u.IsAdmin {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
}

func getBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func applyMetricsPayload(db *gorm.DB, node *Node, payload struct {
	From    string                     `json:"from"`
	Metrics map[string]LinkMetricsJSON `json:"metrics"`
	ReturnStats []ReturnStatJSON       `json:"return_stats"`
	Status  struct {
		CPUUsage    float64  `json:"cpu_usage"`
		MemUsed     uint64   `json:"mem_used_bytes"`
		MemTotal    uint64   `json:"mem_total_bytes"`
		UptimeSec   uint64   `json:"uptime_sec"`
		NetInBytes  uint64   `json:"net_in_bytes"`
		NetOutBytes uint64   `json:"net_out_bytes"`
		Version     string   `json:"version"`
		Transport   string   `json:"transport"`
		Compression string   `json:"compression"`
		OS          string   `json:"os"`
		Arch        string   `json:"arch"`
		PublicIPs   []string `json:"public_ips"`
	} `json:"status"`
}) {
	for to, m := range payload.Metrics {
		db.Model(&LinkMetric{}).Where("from_node = ? AND to_node = ?", payload.From, to).
			Assign(map[string]any{"rtt_ms": m.RTTms, "loss": m.Loss, "updated_at": time.Now()}).
			FirstOrCreate(&LinkMetric{
				From: payload.From, To: to, RTTMs: m.RTTms, Loss: m.Loss, UpdatedAt: time.Now(),
			})
	}
	for _, rs := range payload.ReturnStats {
		if rs.Route == "" {
			rs.Route = "auto"
		}
		if rs.Entry == "" {
			rs.Entry = payload.From
		}
		if rs.Exit == "" || rs.Entry == "" {
			continue
		}
		status := ReturnRouteStatus{
			Node:       payload.From,
			Route:      rs.Route,
			Entry:      rs.Entry,
			Exit:       rs.Exit,
			Auto:       rs.Auto,
			Pending:    rs.Pending,
			ReadyTotal: rs.ReadyTotal,
			ReadyAt:    rs.ReadyAt,
			FailTotal:  rs.FailTotal,
			FailAt:     rs.FailAt,
			FailReason: rs.FailReason,
		}
		db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "node"}, {Name: "route"}, {Name: "entry"}, {Name: "exit"}, {Name: "auto"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"pending":     status.Pending,
				"ready_total": status.ReadyTotal,
				"ready_at":    status.ReadyAt,
				"fail_total":  status.FailTotal,
				"fail_at":     status.FailAt,
				"fail_reason": status.FailReason,
				"updated_at":  time.Now(),
			}),
		}).Create(&status)
	}
	updates := map[string]any{
		"last_cpu":      payload.Status.CPUUsage,
		"mem_used":      payload.Status.MemUsed,
		"mem_total":     payload.Status.MemTotal,
		"uptime_sec":    payload.Status.UptimeSec,
		"net_in_bytes":  payload.Status.NetInBytes,
		"net_out_bytes": payload.Status.NetOutBytes,
		"node_version":  payload.Status.Version,
		"last_seen_at":  time.Now(),
		"transport":     firstNonEmpty(payload.Status.Transport, node.Transport),
		"compression":   firstNonEmpty(payload.Status.Compression, node.Compression),
		"os_name":       payload.Status.OS,
		"arch":          payload.Status.Arch,
	}
	// 合并已有公网IP + 新上报，不覆盖手动填写
	var existing Node
	_ = db.First(&existing, node.ID).Error
	merged := make([]string, 0)
	seen := map[string]struct{}{}
	for _, ip := range existing.PublicIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		merged = append(merged, ip)
	}
	for _, ip := range payload.Status.PublicIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		merged = append(merged, ip)
	}
	if len(merged) > 0 {
		updates["public_ips"] = StringList(merged)
	}
	db.Model(&Node{}).Where("id = ?", node.ID).Updates(updates)
}

func findNodeByToken(db *gorm.DB, token string) (*Node, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	var n Node
	if err := db.Where("token = ?", token).First(&n).Error; err != nil {
		return nil, err
	}
	return &n, nil
}

// wsHub 维护节点 WS 连接，供控制器主动下发指令。
type wsHub struct {
	mu    sync.Mutex
	conns map[string]*wscompat.Conn
}

func newWSHub() *wsHub {
	return &wsHub{conns: make(map[string]*wscompat.Conn)}
}

func (h *wsHub) register(node string, c *wscompat.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, ok := h.conns[node]; ok && old != c {
		old.Close()
	}
	h.conns[node] = c
}

func (h *wsHub) unregister(node string, c *wscompat.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur, ok := h.conns[node]; ok && cur == c {
		delete(h.conns, node)
	}
}

func (h *wsHub) sendCommand(node string, cmd interface{}) error {
	h.mu.Lock()
	c := h.conns[node]
	h.mu.Unlock()
	if c == nil {
		return fmt.Errorf("node %s offline", node)
	}
	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, wscompat.MessageText, data); err != nil {
		return err
	}
	return nil
}

func newDiagRun(nodes []string) *diagRun {
	runID := fmt.Sprintf("diag-%d", time.Now().UnixNano())
	run := &diagRun{
		RunID:     runID,
		CreatedAt: time.Now(),
		Nodes:     nodes,
		Reports:   make(map[string]DiagReport),
	}
	diagMu.Lock()
	diagRuns[runID] = run
	diagRunOrder = append(diagRunOrder, runID)
	if len(diagRunOrder) > 20 {
		old := diagRunOrder[0]
		delete(diagRuns, old)
		diagRunOrder = diagRunOrder[1:]
	}
	diagMu.Unlock()
	return run
}

func ensureDiagRun(runID string, nodes []string) {
	if runID == "" {
		return
	}
	diagMu.Lock()
	run := diagRuns[runID]
	if run == nil {
		run = &diagRun{
			RunID:     runID,
			CreatedAt: time.Now(),
			Nodes:     append([]string(nil), nodes...),
			Reports:   make(map[string]DiagReport),
		}
		diagRuns[runID] = run
		diagRunOrder = append(diagRunOrder, runID)
	} else if len(run.Nodes) == 0 && len(nodes) > 0 {
		run.Nodes = append([]string(nil), nodes...)
	}
	diagMu.Unlock()
}

func storeDiagReport(runID string, report DiagReport) {
	if runID == "" || report.Node == "" {
		return
	}
	diagMu.Lock()
	run := diagRuns[runID]
	if run == nil {
		run = &diagRun{
			RunID:     runID,
			CreatedAt: time.Now(),
			Reports:   make(map[string]DiagReport),
		}
		diagRuns[runID] = run
		diagRunOrder = append(diagRunOrder, runID)
	}
	if prev, ok := run.Reports[report.Node]; ok {
		if report.At.After(prev.At) {
			prev.At = report.At
		}
		if report.Limit > 0 {
			prev.Limit = report.Limit
		}
		if report.Filter != "" {
			prev.Filter = report.Filter
		}
		seen := make(map[string]struct{}, len(prev.Lines))
		for _, line := range prev.Lines {
			seen[line] = struct{}{}
		}
		for _, line := range report.Lines {
			if _, ok := seen[line]; ok {
				continue
			}
			prev.Lines = append(prev.Lines, line)
			seen[line] = struct{}{}
		}
		if len(prev.Lines) > 2000 {
			prev.Lines = prev.Lines[len(prev.Lines)-2000:]
		}
		run.Reports[report.Node] = prev
	} else {
		run.Reports[report.Node] = report
	}
	diagMu.Unlock()
}

func getDiagRun(runID string) *diagRun {
	diagMu.Lock()
	defer diagMu.Unlock()
	if runID == "" && len(diagRunOrder) > 0 {
		runID = diagRunOrder[len(diagRunOrder)-1]
	}
	if runID == "" {
		return nil
	}
	run := diagRuns[runID]
	if run == nil {
		return nil
	}
	clone := &diagRun{
		RunID:     run.RunID,
		CreatedAt: run.CreatedAt,
		Nodes:     append([]string(nil), run.Nodes...),
		Reports:   make(map[string]DiagReport, len(run.Reports)),
	}
	for k, v := range run.Reports {
		clone.Reports[k] = v
	}
	return clone
}

func newDiagTraceRun() *diagTraceRun {
	runID := fmt.Sprintf("trace-%d", time.Now().UnixNano())
	run := &diagTraceRun{
		RunID:     runID,
		CreatedAt: time.Now(),
		Events:    make([]DiagTraceEvent, 0),
	}
	diagTraceMu.Lock()
	diagTraceRuns[runID] = run
	diagTraceMu.Unlock()
	return run
}

func storeDiagTraceEvent(ev DiagTraceEvent) {
	if ev.RunID == "" {
		return
	}
	diagTraceMu.Lock()
	run := diagTraceRuns[ev.RunID]
	if run == nil {
		run = &diagTraceRun{RunID: ev.RunID, CreatedAt: time.Now()}
		diagTraceRuns[ev.RunID] = run
	}
	run.Events = append(run.Events, ev)
	if len(run.Events) > 2000 {
		run.Events = run.Events[len(run.Events)-2000:]
	}
	diagTraceMu.Unlock()
}

func getDiagTraceRun(runID string) *diagTraceRun {
	diagTraceMu.Lock()
	defer diagTraceMu.Unlock()
	if runID == "" {
		return nil
	}
	run := diagTraceRuns[runID]
	if run == nil {
		return nil
	}
	clone := &diagTraceRun{
		RunID:     run.RunID,
		CreatedAt: run.CreatedAt,
		Events:    append([]DiagTraceEvent(nil), run.Events...),
	}
	return clone
}

func newEndpointCheckRun(nodes []string) *endpointCheckRun {
	runID := fmt.Sprintf("ep-%d", time.Now().UnixNano())
	run := &endpointCheckRun{
		RunID:     runID,
		CreatedAt: time.Now(),
		Nodes:     append([]string(nil), nodes...),
		Results:   make([]EndpointCheckResult, 0),
	}
	endpointCheckMu.Lock()
	endpointCheckRuns[runID] = run
	endpointCheckMu.Unlock()
	return run
}

func storeEndpointCheckResults(runID string, results []EndpointCheckResult) {
	if runID == "" {
		return
	}
	endpointCheckMu.Lock()
	run := endpointCheckRuns[runID]
	if run == nil {
		run = &endpointCheckRun{RunID: runID, CreatedAt: time.Now()}
		endpointCheckRuns[runID] = run
	}
	if len(results) > 0 {
		run.Results = append(run.Results, results...)
	}
	endpointCheckMu.Unlock()
}

func getEndpointCheckRun(runID string) *endpointCheckRun {
	endpointCheckMu.Lock()
	defer endpointCheckMu.Unlock()
	if runID == "" {
		return nil
	}
	run := endpointCheckRuns[runID]
	if run == nil {
		return nil
	}
	clone := &endpointCheckRun{
		RunID:     run.RunID,
		CreatedAt: run.CreatedAt,
		Nodes:     append([]string(nil), run.Nodes...),
		Results:   append([]EndpointCheckResult(nil), run.Results...),
	}
	return clone
}

// ensureColumns 兜底补齐旧库缺失的字段，避免“no such column”。
func ensureColumns(db *gorm.DB) {
	type col struct {
		model interface{}
		name  string
		table string
		ctype string
	}
	cols := []col{
		{&Node{}, "quic_listen", "nodes", "TEXT"},
		{&Node{}, "transport", "nodes", "TEXT"},
		{&Node{}, "compression", "nodes", "TEXT"},
		{&Node{}, "compression_min", "nodes", "INTEGER"},
		{&Node{}, "max_mux_streams", "nodes", "INTEGER"},
		{&Node{}, "mux_max_age", "nodes", "TEXT"},
		{&Node{}, "mux_max_idle", "nodes", "TEXT"},
		{&Node{}, "mem_limit", "nodes", "TEXT"},
		{&Node{}, "quic_server_name", "nodes", "TEXT"},
		{&Node{}, "udp_session_ttl", "nodes", "TEXT"},
		{&Node{}, "controller_url", "nodes", "TEXT"},
		{&Node{}, "reroute_attempts", "nodes", "INTEGER"},
		{&Node{}, "insecure_skip_tls", "nodes", "BOOLEAN"},
		{&Node{}, "mtls_cert", "nodes", "TEXT"},
		{&Node{}, "mtls_key", "nodes", "TEXT"},
		{&Node{}, "mtls_ca", "nodes", "TEXT"},
		{&Node{}, "last_cpu", "nodes", "DOUBLE"},
		{&Node{}, "mem_used", "nodes", "BIGINT"},
		{&Node{}, "mem_total", "nodes", "BIGINT"},
		{&Node{}, "uptime_sec", "nodes", "BIGINT"},
		{&Node{}, "net_in_bytes", "nodes", "BIGINT"},
		{&Node{}, "net_out_bytes", "nodes", "BIGINT"},
		{&Node{}, "node_version", "nodes", "TEXT"},
		{&Node{}, "last_seen_at", "nodes", "DATETIME"},
		{&Node{}, "token", "nodes", "TEXT"},
		{&Node{}, "public_ips", "nodes", "TEXT"},
		{&User{}, "username", "users", "TEXT"},
		{&User{}, "password_hash", "users", "TEXT"},
		{&User{}, "is_admin", "users", "BOOLEAN"},
		{&Setting{}, "debug_log", "settings", "BOOLEAN"},
		{&Setting{}, "http_probe_url", "settings", "TEXT"},
		{&Setting{}, "encryption_policies", "settings", "TEXT"},
		{&RoutePlan{}, "return_path", "route_plans", "TEXT"},
		{&ReturnRouteStatus{}, "ready_at", "return_route_statuses", "BIGINT"},
		{&ReturnRouteStatus{}, "fail_total", "return_route_statuses", "BIGINT"},
		{&ReturnRouteStatus{}, "fail_at", "return_route_statuses", "BIGINT"},
		{&ReturnRouteStatus{}, "fail_reason", "return_route_statuses", "TEXT"},
		{&Peer{}, "entry_ip", "peers", "TEXT"},
		{&Peer{}, "exit_ip", "peers", "TEXT"},
	}
	for _, c := range cols {
		if !db.Migrator().HasColumn(c.model, c.name) {
			if err := db.Migrator().AddColumn(c.model, c.name); err != nil {
				log.Printf("add column %s via migrator failed: %v, trying raw alter", c.name, err)
				if err2 := addColumnRaw(db, c.table, c.name, c.ctype); err2 != nil {
					log.Printf("add column %s via raw alter failed: %v", c.name, err2)
				} else {
					log.Printf("added missing column %s via raw alter", c.name)
				}
			} else {
				log.Printf("added missing column %s", c.name)
			}
		}
	}
}

func addColumnRaw(db *gorm.DB, table, column, ctype string) error {
	dialect := strings.ToLower(db.Dialector.Name())
	switch dialect {
	case "sqlite":
		return db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, ctype)).Error
	case "mysql":
		mysqlType := ctype
		if strings.EqualFold(ctype, "BOOLEAN") {
			mysqlType = "TINYINT(1)"
		} else if strings.EqualFold(ctype, "TEXT") {
			mysqlType = "VARCHAR(255)"
		}
		return db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, mysqlType)).Error
	default:
		return fmt.Errorf("unsupported dialect %s", dialect)
	}
}

// Utility: allow simple JSON API as well
func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); strings.TrimSpace(v) != "" {
		return v
	}
	return def
}
