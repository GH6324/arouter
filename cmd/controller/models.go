package main

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
	GeoIP           string      `json:"geo_ip"`
	GeoLat          float64     `json:"geo_lat"`
	GeoLng          float64     `json:"geo_lng"`
	GeoCity         string      `json:"geo_city"`
	GeoRegion       string      `json:"geo_region"`
	GeoCountry      string      `json:"geo_country"`
	GeoOrg          string      `json:"geo_org"`
	GeoUpdatedAt    int64       `json:"geo_updated_at"`
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

type TimeSyncStep struct {
	Command string `json:"command"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

type TimeSyncResult struct {
	RunID    string         `json:"run_id"`
	Node     string         `json:"node"`
	Timezone string         `json:"timezone"`
	Success  bool           `json:"success"`
	Steps    []TimeSyncStep `json:"steps"`
}

type timeSyncRun struct {
	RunID     string
	CreatedAt time.Time
	Nodes     []string
	Results   []TimeSyncResult
}

var (
	endpointCheckMu   sync.Mutex
	endpointCheckRuns = make(map[string]*endpointCheckRun)
)

var (
	timeSyncMu   sync.Mutex
	timeSyncRuns = make(map[string]*timeSyncRun)
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

type NodeUninstallStatus struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Node      string    `gorm:"uniqueIndex" json:"node"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason"`
}

type Entry struct {
	ID     uint   `gorm:"primaryKey" json:"id"`
	NodeID uint   `json:"-"`
	Listen string `json:"listen"`
	Proto  string `json:"proto"` // tcp/udp/both
	Exit   string `json:"exit"`
	Remote string `json:"remote"`
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
	ID         uint       `gorm:"primaryKey" json:"id"`
	NodeID     uint       `json:"-"`
	Name       string     `json:"name"`
	Exit       string     `json:"exit"`
	Remote     string     `json:"remote"`
	Priority   int        `json:"priority"`
	Path       StringList `json:"path"`
	ReturnPath StringList `json:"return_path"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
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
	MaxMuxStreams      int           `json:"max_mux_streams"`
	DebugLog           bool          `json:"debug_log"`
	HTTPProbeURL       string        `json:"http_probe_url"`
	ReturnAckTimeout   string        `json:"return_ack_timeout"`
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
	ID               string            `json:"id"`
	WSListen         string            `json:"ws_listen"`
	QUICListen       string            `json:"quic_listen"`
	WSSListen        string            `json:"wss_listen"`
	QUICServerName   string            `json:"quic_server_name"`
	Peers            map[string]string `json:"peers"`
	Entries          []EntryConfig     `json:"entries"`
	PollPeriod       string            `json:"poll_period"`
	InsecureSkipTLS  bool              `json:"insecure_skip_tls"`
	AuthKey          string            `json:"auth_key"`
	MetricsListen    string            `json:"metrics_listen"`
	RerouteAttempts  int               `json:"reroute_attempts"`
	UDPSessionTTL    string            `json:"udp_session_ttl"`
	MTLSCert         string            `json:"mtls_cert"`
	MTLSKey          string            `json:"mtls_key"`
	MTLSCA           string            `json:"mtls_ca"`
	ControllerURL    string            `json:"controller_url"`
	Routes           []RouteConfig     `json:"routes,omitempty"`
	Compression      string            `json:"compression,omitempty"`
	CompressionMin   int               `json:"compression_min_bytes,omitempty"`
	Transport        string            `json:"transport,omitempty"`
	DebugLog         bool              `json:"debug_log,omitempty"`
	TokenPath        string            `json:"token_path,omitempty"`
	OS               string            `json:"os,omitempty"`
	Arch             string            `json:"arch,omitempty"`
	HTTPProbeURL     string            `json:"http_probe_url,omitempty"`
	ReturnAckTimeout string            `json:"return_ack_timeout,omitempty"`
	Encryption       []EncPolicy       `json:"encryption_policies,omitempty"`
	MaxMuxStreams    int               `json:"max_mux_streams,omitempty"`
	MuxMaxAge        string            `json:"mux_max_age,omitempty"`
	MuxMaxIdle       string            `json:"mux_max_idle,omitempty"`
	MemLimit         string            `json:"mem_limit,omitempty"`
}

type RouteConfig struct {
	Name       string   `json:"name"`
	Exit       string   `json:"exit"`
	Remote     string   `json:"remote,omitempty"`
	Priority   int      `json:"priority"`
	Path       []string `json:"path"`
	ReturnPath []string `json:"return_path,omitempty"`
}

type EntryConfig struct {
	Listen string `json:"listen"`
	Proto  string `json:"proto"`
	Exit   string `json:"exit"`
	Remote string `json:"remote"`
}

type IfAddr struct {
	Iface string `json:"iface"`
	Addr  string `json:"addr"`
}
