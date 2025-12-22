package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	wscompat "arouter/internal/wscompat"

	http2 "alicode.mukj.cn/yjkj.ink/work/http"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/chacha20poly1305"
)

var buildVersion = "dev"
var wsSessionCache = tls.NewLRUClientSessionCache(128)
var debugLogEnabled atomic.Bool
var logFilter = &levelWriter{out: os.Stderr, debug: &debugLogEnabled}
var httpTimeoutClient = &http.Client{Timeout: 10 * time.Second}
var defaultMemLimit = "256MiB"
var configPathValue string
var tokenPathValue string

const (
	colorRed   = "\033[31m"
	colorReset = "\033[0m"
)

func logDebug(format string, args ...interface{}) {
	if debugLogEnabled.Load() {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func logWarn(format string, args ...interface{}) {
	log.Printf("[WARN] "+format, args...)
}

func logError(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

// logTest 用红色高亮测试链路相关日志，便于快速识别。
func logTest(format string, args ...interface{}) {
	msg := fmt.Sprintf("[TEST] "+format, args...)
	log.Printf("%s%s%s", colorRed, msg, colorReset)
}

type levelWriter struct {
	out     io.Writer
	debug   *atomic.Bool
	mu      sync.Mutex
	tailMu  sync.Mutex
	tail    []string
	tailMax int
}

func (w *levelWriter) Write(p []byte) (n int, err error) {
	w.appendTail(p)
	if w.debug != nil && w.debug.Load() {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.out.Write(p)
	}
	// 默认仅透传 WARN/ERROR/FATAL 等重要日志
	if bytes.Contains(p, []byte("[WARN]")) || bytes.Contains(p, []byte("[ERROR]")) || bytes.Contains(p, []byte("FATA")) {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.out.Write(p)
	}
	// 非调试模式下静默吞掉信息级日志
	return len(p), nil
}

func (w *levelWriter) appendTail(p []byte) {
	if len(p) == 0 {
		return
	}
	max := w.tailMax
	if max <= 0 {
		max = 2000
	}
	s := strings.TrimRight(string(p), "\n")
	if s == "" {
		return
	}
	lines := strings.Split(s, "\n")
	w.tailMu.Lock()
	for _, line := range lines {
		if line == "" {
			continue
		}
		w.tail = append(w.tail, line)
		if len(w.tail) > max {
			w.tail = w.tail[len(w.tail)-max:]
		}
	}
	w.tailMu.Unlock()
}

func (w *levelWriter) Tail(limit int, contains string) []string {
	if limit <= 0 {
		limit = 200
	}
	w.tailMu.Lock()
	defer w.tailMu.Unlock()
	if len(w.tail) == 0 {
		return nil
	}
	filter := strings.TrimSpace(contains)
	out := make([]string, 0, limit)
	if filter == "" {
		start := len(w.tail) - limit
		if start < 0 {
			start = 0
		}
		out = append(out, w.tail[start:]...)
		return out
	}
	for i := len(w.tail) - 1; i >= 0 && len(out) < limit; i-- {
		if strings.Contains(w.tail[i], filter) {
			out = append(out, w.tail[i])
		}
	}
	// reverse to keep chronological order
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (w *levelWriter) ClearTail() {
	w.tailMu.Lock()
	w.tail = nil
	w.tailMu.Unlock()
}

// 该版本实现了基础的 WSS 数据平面、JSON 配置加载、动态选路和简单的 RTT 探测。
// 多跳通过 WebSocket 级联，出口节点将流量转发到 RemoteAddr。

type (
	NodeID   string
	Protocol string
)

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// EntryPort maps a local port to a destination node and final remote address.
type EntryPort struct {
	ListenAddr string   // local address e.g. ":10080"
	Proto      Protocol // tcp or udp
	ExitNode   NodeID   // target node that knows how to reach RemoteAddr
	RemoteAddr string   // remote IP:port to dial at the exit
}

// LinkMetrics describes current link health.
type LinkMetrics struct {
	RTT       time.Duration
	LossRatio float64 // 0..1
	UpdatedAt time.Time
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

type failMarker struct {
	failTime  int64
	failCount int64
}

func (m *failMarker) Time() time.Time {
	if m == nil {
		return time.Time{}
	}
	return time.Unix(atomic.LoadInt64(&m.failTime), 0)
}

func (m *failMarker) Count() int64 {
	if m == nil {
		return 0
	}
	return atomic.LoadInt64(&m.failCount)
}

func (m *failMarker) Mark() {
	if m == nil {
		return
	}
	atomic.AddInt64(&m.failCount, 1)
	atomic.StoreInt64(&m.failTime, time.Now().Unix())
}

func (m *failMarker) Reset() {
	if m == nil {
		return
	}
	atomic.StoreInt64(&m.failCount, 0)
}

// Topology keeps weighted edges in-memory.
type Topology struct {
	mu    sync.RWMutex
	edges map[NodeID]map[NodeID]LinkMetrics
	fails map[NodeID]map[NodeID]*failMarker
}

func NewTopology() *Topology {
	return &Topology{
		edges: make(map[NodeID]map[NodeID]LinkMetrics),
		fails: make(map[NodeID]map[NodeID]*failMarker),
	}
}

func (t *Topology) Set(from, to NodeID, m LinkMetrics) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.edges[from] == nil {
		t.edges[from] = make(map[NodeID]LinkMetrics)
	}
	t.edges[from][to] = m
}

// UpdateLink updates link metrics with an EWMA loss estimator:
// sample=0 for success, sample=1 for failure.
// If rtt > 0, RTT is updated; otherwise RTT is kept.
func (t *Topology) UpdateLink(from, to NodeID, rtt time.Duration, success bool, alpha float64) {
	if t == nil {
		return
	}
	if alpha <= 0 || alpha > 1 {
		alpha = 0.2
	}
	sample := 1.0
	if success {
		sample = 0
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.edges[from] == nil {
		t.edges[from] = make(map[NodeID]LinkMetrics)
	}
	cur := t.edges[from][to]
	if rtt > 0 {
		cur.RTT = rtt
	}
	if cur.UpdatedAt.IsZero() {
		cur.LossRatio = sample
	} else {
		cur.LossRatio = clamp01(alpha*sample + (1-alpha)*cur.LossRatio)
	}
	cur.UpdatedAt = time.Now()
	t.edges[from][to] = cur
}

func (t *Topology) Snapshot() map[NodeID]map[NodeID]LinkMetrics {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[NodeID]map[NodeID]LinkMetrics, len(t.edges))
	for from, row := range t.edges {
		copyRow := make(map[NodeID]LinkMetrics, len(row))
		for to, m := range row {
			copyRow[to] = m
		}
		out[from] = copyRow
	}
	return out
}

type LinkFailure struct {
	Count int64
	Time  time.Time
}

func (t *Topology) FailureSnapshot() map[NodeID]map[NodeID]LinkFailure {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make(map[NodeID]map[NodeID]LinkFailure, len(t.fails))
	for from, row := range t.fails {
		copyRow := make(map[NodeID]LinkFailure, len(row))
		for to, m := range row {
			copyRow[to] = LinkFailure{
				Count: m.Count(),
				Time:  m.Time(),
			}
		}
		out[from] = copyRow
	}
	return out
}

func (t *Topology) MarkFail(from, to NodeID) {
	t.mu.Lock()
	row := t.fails[from]
	if row == nil {
		row = make(map[NodeID]*failMarker)
		t.fails[from] = row
	}
	m := row[to]
	if m == nil {
		m = &failMarker{}
		row[to] = m
	}
	t.mu.Unlock()
	m.Mark()
}

func (t *Topology) ResetFail(from, to NodeID) {
	t.mu.RLock()
	row := t.fails[from]
	m := (*failMarker)(nil)
	if row != nil {
		m = row[to]
	}
	t.mu.RUnlock()
	if m != nil {
		m.Reset()
	}
}

// Metrics 以原子计数记录流量与会话情况，暴露 /metrics 供采集。
type Metrics struct {
	tcpSessions             int64
	udpSessions             int64
	bytesUp                 int64
	bytesDown               int64
	returnPending           int64
	returnReadyTotal        int64
	returnReadyLast         int64
	returnFailTotal         int64
	returnFailLast          int64
	returnMu                sync.Mutex
	returnPendingByLabel    map[string]int64
	returnReadyByLabel      map[string]int64
	returnReadyAtByLabel    map[string]int64
	returnFailByLabel       map[string]int64
	returnFailAtByLabel     map[string]int64
	returnFailReasonByLabel map[string]string
	Self                    NodeID
	Topology                *Topology
	MuxPool                 interface {
		PoolSnapshot() map[NodeID]MuxPoolStats
	}
}

type ReturnStat struct {
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

func (m *Metrics) ReturnStatsSnapshot() []ReturnStat {
	m.returnMu.Lock()
	defer m.returnMu.Unlock()
	keys := make(map[string]struct{})
	for k := range m.returnPendingByLabel {
		keys[k] = struct{}{}
	}
	for k := range m.returnReadyByLabel {
		keys[k] = struct{}{}
	}
	for k := range m.returnFailByLabel {
		keys[k] = struct{}{}
	}
	out := make([]ReturnStat, 0, len(keys))
	for k := range keys {
		entry, exit, route, auto := splitReturnLabel(k)
		out = append(out, ReturnStat{
			Entry:      entry,
			Exit:       exit,
			Route:      route,
			Auto:       auto,
			Pending:    m.returnPendingByLabel[k],
			ReadyTotal: m.returnReadyByLabel[k],
			ReadyAt:    m.returnReadyAtByLabel[k],
			FailTotal:  m.returnFailByLabel[k],
			FailAt:     m.returnFailAtByLabel[k],
			FailReason: m.returnFailReasonByLabel[k],
		})
	}
	return out
}

func (m *Metrics) IncTCP()           { atomic.AddInt64(&m.tcpSessions, 1) }
func (m *Metrics) IncUDP()           { atomic.AddInt64(&m.udpSessions, 1) }
func (m *Metrics) AddUp(n int64)     { atomic.AddInt64(&m.bytesUp, n) }
func (m *Metrics) AddDown(n int64)   { atomic.AddInt64(&m.bytesDown, n) }
func (m *Metrics) IncReturnPending() { atomic.AddInt64(&m.returnPending, 1) }
func (m *Metrics) DecReturnPending() { atomic.AddInt64(&m.returnPending, -1) }
func (m *Metrics) MarkReturnReady() {
	atomic.AddInt64(&m.returnReadyTotal, 1)
	atomic.StoreInt64(&m.returnReadyLast, time.Now().Unix())
}
func (m *Metrics) MarkReturnFail() {
	atomic.AddInt64(&m.returnFailTotal, 1)
	atomic.StoreInt64(&m.returnFailLast, time.Now().Unix())
}
func (m *Metrics) IncReturnPendingLabels(entry, exit, route string, auto bool) {
	m.IncReturnPending()
	key := returnLabelKey(entry, exit, route, auto)
	m.returnMu.Lock()
	if m.returnPendingByLabel == nil {
		m.returnPendingByLabel = make(map[string]int64)
	}
	m.returnPendingByLabel[key]++
	m.returnMu.Unlock()
}
func (m *Metrics) DecReturnPendingLabels(entry, exit, route string, auto bool) {
	m.DecReturnPending()
	key := returnLabelKey(entry, exit, route, auto)
	m.returnMu.Lock()
	if m.returnPendingByLabel != nil {
		if v := m.returnPendingByLabel[key] - 1; v > 0 {
			m.returnPendingByLabel[key] = v
		} else {
			delete(m.returnPendingByLabel, key)
		}
	}
	m.returnMu.Unlock()
}
func (m *Metrics) MarkReturnReadyLabels(entry, exit, route string, auto bool) {
	m.MarkReturnReady()
	key := returnLabelKey(entry, exit, route, auto)
	m.returnMu.Lock()
	if m.returnReadyByLabel == nil {
		m.returnReadyByLabel = make(map[string]int64)
	}
	if m.returnReadyAtByLabel == nil {
		m.returnReadyAtByLabel = make(map[string]int64)
	}
	m.returnReadyByLabel[key]++
	m.returnReadyAtByLabel[key] = time.Now().Unix()
	if m.returnFailAtByLabel != nil {
		delete(m.returnFailAtByLabel, key)
	}
	if m.returnFailReasonByLabel != nil {
		delete(m.returnFailReasonByLabel, key)
	}
	m.returnMu.Unlock()
}
func (m *Metrics) MarkReturnFailLabels(entry, exit, route string, auto bool) {
	m.MarkReturnFail()
	key := returnLabelKey(entry, exit, route, auto)
	m.returnMu.Lock()
	if m.returnFailByLabel == nil {
		m.returnFailByLabel = make(map[string]int64)
	}
	if m.returnFailAtByLabel == nil {
		m.returnFailAtByLabel = make(map[string]int64)
	}
	m.returnFailByLabel[key]++
	m.returnFailAtByLabel[key] = time.Now().Unix()
	m.returnMu.Unlock()
}
func (m *Metrics) SetReturnFailReason(entry, exit, route string, auto bool, reason string) {
	key := returnLabelKey(entry, exit, route, auto)
	m.returnMu.Lock()
	if m.returnFailReasonByLabel == nil {
		m.returnFailReasonByLabel = make(map[string]string)
	}
	m.returnFailReasonByLabel[key] = reason
	m.returnMu.Unlock()
}

func returnLabelKey(entry, exit, route string, auto bool) string {
	autoLabel := "false"
	if auto {
		autoLabel = "true"
	}
	return entry + "|" + exit + "|" + route + "|" + autoLabel
}

func splitReturnLabel(k string) (string, string, string, bool) {
	parts := strings.SplitN(k, "|", 4)
	if len(parts) < 4 {
		return k, "", "", false
	}
	return parts[0], parts[1], parts[2], parts[3] == "true"
}

type MuxPoolStats struct {
	Total      int
	Active     int
	Draining   int
	MinRTTEWMA time.Duration
	MaxRTTEWMA time.Duration
	AvgRTTEWMA time.Duration
	LastPing   time.Time
	LastFail   time.Time
	TotalFails int
}

// NodeStatus 描述节点自身运行状态，用于上报给控制器。
type NodeStatus struct {
	CPUUsage    float64  `json:"cpu_usage"`       // 0-100
	MemUsed     uint64   `json:"mem_used_bytes"`  // 已用内存
	MemTotal    uint64   `json:"mem_total_bytes"` // 总内存
	UptimeSec   uint64   `json:"uptime_sec"`
	NetInBytes  uint64   `json:"net_in_bytes"`
	NetOutBytes uint64   `json:"net_out_bytes"`
	Version     string   `json:"version"`
	Transport   string   `json:"transport"`
	Compression string   `json:"compression"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	PublicIPs   []string `json:"public_ips"`
}

func (m *Metrics) Serve(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "tcp_sessions_total %d\n", atomic.LoadInt64(&m.tcpSessions))
		fmt.Fprintf(w, "udp_sessions_total %d\n", atomic.LoadInt64(&m.udpSessions))
		fmt.Fprintf(w, "bytes_up_total %d\n", atomic.LoadInt64(&m.bytesUp))
		fmt.Fprintf(w, "bytes_down_total %d\n", atomic.LoadInt64(&m.bytesDown))
		fmt.Fprintf(w, "return_sessions_pending %d\n", atomic.LoadInt64(&m.returnPending))
		fmt.Fprintf(w, "return_path_ready_total %d\n", atomic.LoadInt64(&m.returnReadyTotal))
		fmt.Fprintf(w, "return_path_fail_total %d\n", atomic.LoadInt64(&m.returnFailTotal))
		if last := atomic.LoadInt64(&m.returnReadyLast); last > 0 {
			fmt.Fprintf(w, "return_path_ready_last_seconds %d\n", last)
		}
		if last := atomic.LoadInt64(&m.returnFailLast); last > 0 {
			fmt.Fprintf(w, "return_path_fail_last_seconds %d\n", last)
		}
		m.returnMu.Lock()
		for k, v := range m.returnPendingByLabel {
			entry, exit, route, auto := splitReturnLabel(k)
			fmt.Fprintf(w, "return_sessions_pending{entry=%q,exit=%q,route=%q,auto=%t} %d\n", entry, exit, route, auto, v)
		}
		for k, v := range m.returnReadyByLabel {
			entry, exit, route, auto := splitReturnLabel(k)
			fmt.Fprintf(w, "return_path_ready_total{entry=%q,exit=%q,route=%q,auto=%t} %d\n", entry, exit, route, auto, v)
		}
		for k, v := range m.returnFailByLabel {
			entry, exit, route, auto := splitReturnLabel(k)
			fmt.Fprintf(w, "return_path_fail_total{entry=%q,exit=%q,route=%q,auto=%t} %d\n", entry, exit, route, auto, v)
		}
		m.returnMu.Unlock()

		if m.Topology != nil {
			graph := m.Topology.Snapshot()
			fails := m.Topology.FailureSnapshot()
			writeRow := func(from NodeID, row map[NodeID]LinkMetrics) {
				for to, lm := range row {
					fmt.Fprintf(w, "link_rtt_ms{from=%q,to=%q} %d\n", string(from), string(to), lm.RTT.Milliseconds())
					fmt.Fprintf(w, "link_loss_ratio{from=%q,to=%q} %.6f\n", string(from), string(to), clamp01(lm.LossRatio))
					fmt.Fprintf(w, "link_updated_at_seconds{from=%q,to=%q} %d\n", string(from), string(to), lm.UpdatedAt.Unix())
					if fr := fails[from]; fr != nil {
						if lf, ok := fr[to]; ok {
							fmt.Fprintf(w, "link_fail_count{from=%q,to=%q} %d\n", string(from), string(to), lf.Count)
							fmt.Fprintf(w, "link_last_fail_seconds{from=%q,to=%q} %d\n", string(from), string(to), lf.Time.Unix())
						}
					}
				}
			}

			if m.Self != "" {
				if row := graph[m.Self]; row != nil {
					writeRow(m.Self, row)
				}
			} else {
				for from, row := range graph {
					writeRow(from, row)
				}
			}
		}

		if m.MuxPool != nil {
			snap := m.MuxPool.PoolSnapshot()
			for peer, st := range snap {
				fmt.Fprintf(w, "mux_pool_total{peer=%q} %d\n", string(peer), st.Total)
				fmt.Fprintf(w, "mux_pool_active{peer=%q} %d\n", string(peer), st.Active)
				fmt.Fprintf(w, "mux_pool_draining{peer=%q} %d\n", string(peer), st.Draining)
				fmt.Fprintf(w, "mux_pool_rtt_ewma_min_ms{peer=%q} %d\n", string(peer), st.MinRTTEWMA.Milliseconds())
				fmt.Fprintf(w, "mux_pool_rtt_ewma_max_ms{peer=%q} %d\n", string(peer), st.MaxRTTEWMA.Milliseconds())
				fmt.Fprintf(w, "mux_pool_rtt_ewma_avg_ms{peer=%q} %d\n", string(peer), st.AvgRTTEWMA.Milliseconds())
				fmt.Fprintf(w, "mux_pool_last_ping_seconds{peer=%q} %d\n", string(peer), st.LastPing.Unix())
				fmt.Fprintf(w, "mux_pool_last_fail_seconds{peer=%q} %d\n", string(peer), st.LastFail.Unix())
				fmt.Fprintf(w, "mux_pool_fail_total{peer=%q} %d\n", string(peer), st.TotalFails)
			}
		}
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server stopped: %v", err)
		}
	}()
	return srv
}

// Router picks a path using the latest metrics.
type Router struct {
	Topology      *Topology
	FailThreshold int64
	FailTimeout   time.Duration
	FailPenalty   time.Duration
}

func (r *Router) BestPath(src, dst NodeID) ([]NodeID, error) {
	graph := r.Topology.Snapshot()
	fails := r.Topology.FailureSnapshot()
	dist := make(map[NodeID]float64)
	prev := make(map[NodeID]NodeID)
	unseen := make(map[NodeID]bool)

	for from := range graph {
		unseen[from] = true
		dist[from] = 1e18
		for to := range graph[from] {
			unseen[to] = true
			if _, ok := dist[to]; !ok {
				dist[to] = 1e18
			}
		}
	}
	if len(unseen) == 0 {
		return nil, errors.New("empty topology")
	}
	if _, ok := dist[src]; !ok {
		return nil, fmt.Errorf("source %s not present", src)
	}
	dist[src] = 0

	weight := func(m LinkMetrics) float64 {
		rtt := float64(m.RTT.Milliseconds())
		if rtt <= 0 {
			rtt = 1
		}
		loss := m.LossRatio
		return rtt * (1 + loss*2) // penalize loss heavier than latency
	}

	for len(unseen) > 0 {
		var u NodeID
		best := 1e18
		for n := range unseen {
			if dist[n] < best {
				best = dist[n]
				u = n
			}
		}
		delete(unseen, u)
		for v, metrics := range graph[u] {
			alt := dist[u] + weight(metrics) + r.failPenalty(fails, u, v)
			if alt < dist[v] {
				dist[v] = alt
				prev[v] = u
			}
		}
	}

	// reconstruct
	path := []NodeID{dst}
	for at := dst; at != src; {
		p, ok := prev[at]
		if !ok {
			return nil, fmt.Errorf("no route %s -> %s", src, dst)
		}
		path = append([]NodeID{p}, path...)
		at = p
	}
	return path, nil
}

func (r *Router) failPenalty(fails map[NodeID]map[NodeID]LinkFailure, from, to NodeID) float64 {
	if r == nil {
		return 0
	}
	row := fails[from]
	if row == nil {
		return 0
	}
	f := row[to]
	if f.Count == 0 || f.Time.IsZero() {
		return 0
	}

	failTimeout := r.FailTimeout
	if failTimeout <= 0 {
		failTimeout = 30 * time.Second
	}
	if time.Since(f.Time) > failTimeout {
		return 0
	}

	threshold := r.FailThreshold
	if threshold <= 0 {
		threshold = 3
	}
	if f.Count >= threshold {
		return 1e18
	}

	penalty := r.FailPenalty
	if penalty <= 0 {
		penalty = 250 * time.Millisecond
	}

	// multiply penalty by fail count with cap.
	c := f.Count
	if c > 10 {
		c = 10
	}
	return float64((penalty * time.Duration(c)).Milliseconds())
}

func fmtVal(v float64) string {
	if math.IsInf(v, 1) {
		return "inf"
	}
	return fmt.Sprintf("%.2f", v)
}

type cpuSnapshot struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
	total                                                 uint64
}

var (
	prevCPUSnap cpuSnapshot
	hasCPUSnap  bool
)

func readCPUSnapshot() (cpuSnapshot, error) {
	if runtime.GOOS == "darwin" {
		return readCPUSnapshotDarwin()
	}
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSnapshot{}, err
	}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var snap cpuSnapshot
		parse := func(idx int) uint64 {
			if idx >= len(fields) {
				return 0
			}
			v, _ := strconv.ParseUint(fields[idx], 10, 64)
			return v
		}
		snap.user = parse(1)
		snap.nice = parse(2)
		snap.system = parse(3)
		snap.idle = parse(4)
		snap.iowait = parse(5)
		snap.irq = parse(6)
		snap.softirq = parse(7)
		snap.steal = parse(8)
		snap.total = snap.user + snap.nice + snap.system + snap.idle + snap.iowait + snap.irq + snap.softirq + snap.steal
		return snap, nil
	}
	return cpuSnapshot{}, fmt.Errorf("cpu line not found in /proc/stat")
}

// readCPUSnapshotDarwin 通过 sysctl kern.cp_time 获取 CPU 时间片。
func readCPUSnapshotDarwin() (cpuSnapshot, error) {
	out, err := exec.Command("sysctl", "-n", "kern.cp_time").Output()
	if err != nil {
		return cpuSnapshot{}, err
	}
	fields := strings.Fields(string(bytes.TrimSpace(out)))
	if len(fields) < 5 {
		return cpuSnapshot{}, fmt.Errorf("unexpected kern.cp_time: %s", string(out))
	}
	parse := func(idx int) uint64 {
		if idx >= len(fields) {
			return 0
		}
		v, _ := strconv.ParseUint(fields[idx], 10, 64)
		return v
	}
	var snap cpuSnapshot
	snap.user = parse(0)
	snap.nice = parse(1)
	snap.system = parse(2)
	// macOS 第4个是 idle，第5个是 intr
	snap.idle = parse(3)
	snap.irq = parse(4)
	snap.total = snap.user + snap.nice + snap.system + snap.idle + snap.irq
	return snap, nil
}

// readCPUPercentDarwin 优先解析 top 的 CPU usage 行，失败则用 ps 汇总/核数。
func readCPUPercentDarwin() (float64, error) {
	out, err := exec.Command("top", "-l", "1", "-n", "0").Output()
	if err == nil {
		re := regexp.MustCompile(`CPU usage:\s*([\d\.]+)% user,\s*([\d\.]+)% sys`)
		if m := re.FindStringSubmatch(string(out)); len(m) == 3 {
			u, _ := strconv.ParseFloat(m[1], 64)
			s, _ := strconv.ParseFloat(m[2], 64)
			return u + s, nil
		}
	}
	// fallback: ps 汇总再按核数归一化
	psOut, err2 := exec.Command("ps", "-A", "-o", "%cpu").Output()
	if err2 != nil {
		return 0, err2
	}
	lines := strings.Split(string(psOut), "\n")
	var sum float64
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "%CPU") {
			continue
		}
		if v, err := strconv.ParseFloat(l, 64); err == nil {
			sum += v
		}
	}
	cpus := float64(runtime.NumCPU())
	if cpus > 0 {
		sum = sum / cpus
	}
	if sum > 100 {
		sum = 100
	}
	return sum, nil
}

func readMem() (used, total uint64, err error) {
	if runtime.GOOS == "darwin" {
		return readMemDarwin()
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	var memTotal, memAvail uint64
	for _, l := range lines {
		if strings.HasPrefix(l, "MemTotal:") {
			fmt.Sscanf(l, "MemTotal: %d kB", &memTotal)
		} else if strings.HasPrefix(l, "MemAvailable:") {
			fmt.Sscanf(l, "MemAvailable: %d kB", &memAvail)
		}
	}
	total = memTotal * 1024
	if memAvail > 0 {
		used = (memTotal - memAvail) * 1024
	}
	return
}

func readUptime() (uint64, error) {
	if runtime.GOOS == "darwin" {
		return readUptimeDarwin()
	}
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	var up float64
	if _, err := fmt.Sscanf(string(bytes.TrimSpace(data)), "%f", &up); err != nil {
		return 0, err
	}
	return uint64(up), nil
}

func readNet() (rx, tx uint64, err error) {
	if runtime.GOOS == "darwin" {
		return readNetDarwin()
	}
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		if !strings.Contains(l, ":") {
			continue
		}
		parts := strings.Split(strings.TrimSpace(l), ":")
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += rxBytes
		tx += txBytes
	}
	return
}

func readMemDarwin() (used, total uint64, err error) {
	// total from hw.memsize
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err == nil {
		outStr := strings.TrimSpace(string(out))
		total, _ = strconv.ParseUint(outStr, 10, 64)
	}
	pageSize := uint64(4096)
	cmd := exec.Command("vm_stat")
	vmOut, vmErr := cmd.Output()
	if vmErr != nil {
		return used, total, vmErr
	}
	lines := strings.Split(string(vmOut), "\n")
	reNum := regexp.MustCompile(`([0-9]+)`)
	freePages := uint64(0)
	inactivePages := uint64(0)
	specPages := uint64(0)
	for _, l := range lines {
		if strings.Contains(l, "page size of") {
			if matches := reNum.FindStringSubmatch(l); len(matches) > 1 {
				if ps, err := strconv.ParseUint(matches[1], 10, 64); err == nil {
					pageSize = ps
				}
			}
		}
		if strings.HasPrefix(strings.TrimSpace(l), "Pages free") {
			if matches := reNum.FindStringSubmatch(l); len(matches) > 1 {
				freePages, _ = strconv.ParseUint(matches[1], 10, 64)
			}
		}
		if strings.HasPrefix(strings.TrimSpace(l), "Pages inactive") {
			if matches := reNum.FindStringSubmatch(l); len(matches) > 1 {
				inactivePages, _ = strconv.ParseUint(matches[1], 10, 64)
			}
		}
		if strings.HasPrefix(strings.TrimSpace(l), "Pages speculative") {
			if matches := reNum.FindStringSubmatch(l); len(matches) > 1 {
				specPages, _ = strconv.ParseUint(matches[1], 10, 64)
			}
		}
	}
	freeBytes := (freePages + inactivePages + specPages) * pageSize
	if total > freeBytes {
		used = total - freeBytes
	}
	return used, total, nil
}

func readUptimeDarwin() (uint64, error) {
	out, err := exec.Command("sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return 0, err
	}
	// format: { sec = 1700000000, usec = 0 } ...
	re := regexp.MustCompile(`sec\s*=\s*([0-9]+)`)
	m := re.FindStringSubmatch(string(out))
	if len(m) < 2 {
		return 0, fmt.Errorf("boottime parse failed")
	}
	sec, _ := strconv.ParseUint(m[1], 10, 64)
	if sec == 0 {
		return 0, fmt.Errorf("boottime zero")
	}
	now := uint64(time.Now().Unix())
	if now > sec {
		return now - sec, nil
	}
	return 0, fmt.Errorf("invalid boottime")
}

func readNetDarwin() (rx, tx uint64, err error) {
	out, err := exec.Command("netstat", "-ibn").Output()
	if err != nil {
		return rx, tx, err
	}
	lines := strings.Split(string(out), "\n")
	seen := make(map[string]bool)
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 12 || fields[0] == "Name" {
			continue
		}
		iface := fields[0]
		if strings.HasPrefix(iface, "lo") {
			continue
		}
		key := iface
		if seen[key] {
			continue
		}
		seen[key] = true
		rxBytes, _ := strconv.ParseUint(fields[10], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[11], 10, 64)
		rx += rxBytes
		tx += txBytes
	}
	return
}

func detectOSInfo() (string, string) {
	arch := runtime.GOARCH
	if runtime.GOOS == "darwin" {
		nameOut, _ := exec.Command("sw_vers", "-productName").Output()
		verOut, _ := exec.Command("sw_vers", "-productVersion").Output()
		name := strings.TrimSpace(string(nameOut))
		ver := strings.TrimSpace(string(verOut))
		if name == "" {
			name = "macos"
		}
		if ver != "" {
			name = name + " " + ver
		}
		return name, arch
	}
	// try /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		var name, version string
		for _, l := range lines {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				name = strings.Trim(l[len("PRETTY_NAME="):], `"`)
			} else if strings.HasPrefix(l, "NAME=") && name == "" {
				name = strings.Trim(l[len("NAME="):], `"`)
			} else if strings.HasPrefix(l, "VERSION_ID=") {
				version = strings.Trim(l[len("VERSION_ID="):], `"`)
			}
		}
		if name != "" && version != "" {
			return name + " " + version, arch
		}
		if name != "" {
			return name, arch
		}
	}
	return runtime.GOOS, arch
}

func autoMaxMuxStreams() int {
	// Conservative defaults: enough parallelism for multi-connection apps (e.g. iperf3 control+data),
	// but avoid too many long-lived WS conns to a single peer.
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	if n > 4 {
		n = 4
	}
	if n < 2 {
		n = 2
	}
	return n
}

func gatherPublicIPs() []string {
	seen := make(map[string]struct{})
	for _, ip := range publicIPsFromInterfaces() {
		seen[ip] = struct{}{}
	}
	for _, ip := range []string{fetchPublicIPFromIPSB("tcp4"), fetchPublicIPFromIPSB("tcp6")} {
		if ip == "" {
			continue
		}
		seen[ip] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func publicIPsFromInterfaces() []string {
	ifaces, _ := net.Interfaces()
	var res []string
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
			res = append(res, ip.String())
		}
	}
	return res
}

func fetchPublicIPFromIPSB(network string) string {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Timeout: 4 * time.Second, Transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://ip.sb", nil)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	ipStr := strings.TrimSpace(string(b))
	ip := net.ParseIP(ipStr)
	if ip == nil || isPrivateOrLinkLocal(ip) {
		return ""
	}
	return ip.String()
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
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

func gatherNodeStatus() NodeStatus {
	status := NodeStatus{Version: buildVersion}
	status.OS, status.Arch = detectOSInfo()
	status.PublicIPs = gatherPublicIPs()

	if snap, err := readCPUSnapshot(); err == nil {
		if hasCPUSnap {
			idleDiff := float64(snap.idle - prevCPUSnap.idle)
			totalDiff := float64(snap.total - prevCPUSnap.total)
			if totalDiff > 0 {
				status.CPUUsage = (1 - idleDiff/totalDiff) * 100
			}
		}
		prevCPUSnap = snap
		hasCPUSnap = true
	} else if runtime.GOOS == "darwin" {
		// fallback: direct macOS CPU%
		if p, err := readCPUPercentDarwin(); err == nil {
			status.CPUUsage = p
		}
	}
	if used, total, err := readMem(); err == nil {
		status.MemUsed = used
		status.MemTotal = total
	}
	if up, err := readUptime(); err == nil {
		status.UptimeSec = up
	}
	if rx, tx, err := readNet(); err == nil {
		status.NetInBytes = rx
		status.NetOutBytes = tx
	}
	return status
}

func defaultIfEmpty(val, def string) string {
	if strings.TrimSpace(val) == "" {
		return def
	}
	return val
}

// ensureListenAddr ensures port-only values are prefixed with ":" for net.Listen.
func ensureListenAddr(addr string) string {
	a := strings.TrimSpace(addr)
	if a == "" {
		return ""
	}
	if strings.Contains(a, ":") {
		return a
	}
	return ":" + a
}

func (n *Node) recordMetric(peer NodeID, m LinkMetrics) {
	if n.ControllerURL == "" {
		return
	}
	n.metricsMu.Lock()
	defer n.metricsMu.Unlock()
	if n.lastMetrics == nil {
		n.lastMetrics = make(map[NodeID]LinkMetrics)
	}
	n.lastMetrics[peer] = m
}

func (n *Node) pushAndPullLoop(ctx context.Context) {
	pushInterval := n.PollPeriod
	if pushInterval <= 0 {
		pushInterval = time.Minute
	}
	pullInterval := n.TopologyPull
	if pullInterval <= 0 {
		pullInterval = pushInterval
	}
	pushTicker := time.NewTicker(pushInterval)
	pullTicker := time.NewTicker(pullInterval)
	defer pushTicker.Stop()
	defer pullTicker.Stop()
	n.pushMetrics(ctx)
	n.pullTopology(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-pushTicker.C:
			n.pushMetrics(ctx)
		case <-pullTicker.C:
			n.pullTopology(ctx)
		}
	}
}

func (n *Node) pushMetrics(ctx context.Context) bool {
	// 优先通过 WS 推送，失败时回退 HTTP
	n.metricsMu.Lock()
	snapshot := make(map[NodeID]LinkMetrics, len(n.lastMetrics))
	for k, v := range n.lastMetrics {
		snapshot[k] = v
	}
	n.metricsMu.Unlock()
	if n.Router != nil && n.Router.Topology != nil {
		if row := n.Router.Topology.Snapshot()[n.ID]; row != nil {
			for to, m := range row {
				snapshot[to] = m
			}
		}
	}
	payload := struct {
		From        NodeID                     `json:"from"`
		Metrics     map[NodeID]LinkMetricsJSON `json:"metrics"`
		Status      NodeStatus                 `json:"status"`
		ReturnStats []ReturnStat               `json:"return_stats,omitempty"`
	}{From: n.ID, Metrics: make(map[NodeID]LinkMetricsJSON, len(snapshot)), Status: gatherNodeStatus()}
	payload.Status.Transport = n.TransportMode
	payload.Status.Compression = n.Compression
	for k, v := range snapshot {
		payload.Metrics[k] = LinkMetricsJSON{RTTms: v.RTT.Milliseconds(), Loss: v.LossRatio, UpdatedAt: v.UpdatedAt}
	}
	if n.Metrics != nil {
		payload.ReturnStats = n.Metrics.ReturnStatsSnapshot()
	}
	if n.pushMetricsWS(ctx, payload) {
		return true
	}
	data, _ := json.Marshal(payload)
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/metrics"
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(reqCtx, "POST", url, strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	if len(n.AuthKey) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(n.AuthKey))
	}
	if tok := n.loadToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpTimeoutClient.Do(req)
	if err != nil {
		log.Printf("push metrics failed: %v", err)
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if n.DebugLog {
		log.Printf("[metrics debug] payload=%s status=%s body=%s", string(data), resp.Status, string(body))
	}
	if resp.StatusCode >= 300 {
		log.Printf("push metrics non-2xx: %s body=%s", resp.Status, string(body))
	}
	return resp.StatusCode < 300
}

// pushMetricsWS 通过 WS 推送，成功返回 true。
func (n *Node) pushMetricsWS(ctx context.Context, payload interface{}) bool {
	return n.pushWSMessage(ctx, "metrics", payload)
}

func (n *Node) pushWSMessage(ctx context.Context, msgType string, payload interface{}) bool {
	conn := n.wsConnSafe()
	if conn == nil {
		return false
	}
	data, err := json.Marshal(struct {
		Type string      `json:"type"`
		Data interface{} `json:"data"`
	}{
		Type: msgType,
		Data: payload,
	})
	if err != nil {
		return false
	}
	wsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := conn.Write(wsCtx, wscompat.MessageText, data); err != nil {
		logWarn("[controller ws] write %s failed: %v", msgType, err)
		n.setWSConn(nil)
		return false
	}
	return true
}

func (n *Node) reportDiag(ev DiagEvent) {
	if ev.Node == "" {
		ev.Node = string(n.ID)
	}
	if ev.At == 0 {
		ev.At = time.Now().UnixMilli()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = n.pushWSMessage(ctx, "diag_event", ev)
}

func (n *Node) pullTopologyLoop(ctx context.Context) {
	interval := n.TopologyPull
	if interval <= 0 {
		interval = n.PollPeriod
		if interval <= 0 {
			interval = time.Minute
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	n.pullTopology(ctx) // initial pull
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.pullTopology(ctx)
		}
	}
}

func (n *Node) pullRoutesLoop(ctx context.Context) {
	interval := n.RoutePull
	if interval <= 0 {
		interval = n.TopologyPull
	}
	if interval <= 0 {
		interval = n.PollPeriod
	}
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	n.pullRoutes(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.pullRoutes(ctx)
		}
	}
}

// controllerWSLoop 建立到控制器的 WS 连接，用于实时推送指标。
func (n *Node) controllerWSLoop(ctx context.Context) {
	if n.ControllerURL == "" {
		return
	}
	wsURL := toWSURL(strings.TrimRight(n.ControllerURL, "/") + "/api/ws")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		logWarn("[controller ws] dialing %s", wsURL)
		tok := n.loadToken()
		header := http.Header{}
		if tok != "" {
			header.Set("Authorization", "Bearer "+tok)
		}
		serverName := n.ServerName
		if u, err := url.Parse(wsURL); err == nil {
			host := u.Hostname()
			if host != "" && net.ParseIP(host) == nil {
				serverName = host
			}
		}
		conn, resp, err := wscompat.Dial(ctx, wsURL, &wscompat.DialOptions{
			HTTPHeader:      header,
			TLSClientConfig: cloneTLSWithServerName(n.TLSConfig, serverName),
		})
		if err != nil {
			if resp != nil {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
				_ = resp.Body.Close()
				logWarn("[controller ws] dial failed: %v (status=%s body=%s)", err, resp.Status, strings.TrimSpace(string(body)))
			} else {
				logWarn("[controller ws] dial failed: %v", err)
			}
			if hint := wsHealthHint(err, resp); hint != "" {
				logWarn("[controller ws] health: %s", hint)
			}
			time.Sleep(3 * time.Second)
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(75 * time.Second))
		conn.SetPongHandler(func(string) error {
			return conn.SetReadDeadline(time.Now().Add(75 * time.Second))
		})
		n.setWSConn(conn)
		log.Printf("[controller ws] connected")
		go n.checkAndUpdateFromController(ctx, false)
		done := make(chan struct{})
		pingTicker := time.NewTicker(20 * time.Second)
		defer pingTicker.Stop()
		go func() {
			defer close(done)
			for {
				_, data, err := conn.Read(ctx)
				if err != nil {
					logWarn("[controller ws] read failed: %v", err)
					if hint := wsHealthHint(err, nil); hint != "" {
						logWarn("[controller ws] health: %s", hint)
					}
					return
				}
				n.handleWSMessage(ctx, data)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				conn.Close()
				return
			case <-pingTicker.C:
				pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				_ = conn.Ping(pingCtx)
				cancel()
			case <-done:
				conn.Close()
				n.setWSConn(nil)
				logWarn("[controller ws] disconnected, reconnecting...")
				time.Sleep(2 * time.Second)
				goto reconnect
			}
		}
	reconnect:
	}
}

func (n *Node) setWSConn(c *wscompat.Conn) {
	n.wsMu.Lock()
	defer n.wsMu.Unlock()
	if n.wsConn != nil && n.wsConn != c {
		n.wsConn.Close()
	}
	n.wsConn = c
}

func (n *Node) wsConnSafe() *wscompat.Conn {
	n.wsMu.Lock()
	defer n.wsMu.Unlock()
	return n.wsConn
}

func (n *Node) handleWSMessage(ctx context.Context, data []byte) {
	var msg struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	switch msg.Type {
	case "probe":
		var req struct {
			Target string `json:"target"`
		}
		if err := json.Unmarshal(msg.Data, &req); err != nil || strings.TrimSpace(req.Target) == "" {
			return
		}
		go n.runProbeAndReport(ctx, req.Target)
	case "route_test":
		var req struct {
			Route  string   `json:"route"`
			Path   []string `json:"path"`
			Target string   `json:"target"`
		}
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return
		}
		if len(req.Path) == 0 {
			return
		}
		ids := make([]NodeID, 0, len(req.Path))
		for _, p := range req.Path {
			ids = append(ids, NodeID(p))
		}
		// 确保路径以自身开头
		if len(ids) == 0 {
			return
		}
		if ids[0] != n.ID {
			ids = append([]NodeID{n.ID}, ids...)
		}
		target := strings.TrimSpace(req.Target)
		if target == "" {
			target = n.HTTPProbeURL
		}
		r := ManualRoute{Name: req.Route, Path: ids, Priority: 1}
		log.Printf("[controller ws] recv route_test route=%s path=%v target=%s", r.Name, r.Path, target)
		go n.runRouteTest(ctx, r, target)
	case "route_diag":
		var req struct {
			RunID      string   `json:"run_id"`
			Route      string   `json:"route"`
			Path       []string `json:"path"`
			ReturnPath []string `json:"return_path"`
			Target     string   `json:"target"`
		}
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return
		}
		if len(req.Path) == 0 {
			return
		}
		ids := make([]NodeID, 0, len(req.Path))
		for _, p := range req.Path {
			ids = append(ids, NodeID(p))
		}
		if len(ids) == 0 {
			return
		}
		if ids[0] != n.ID {
			ids = append([]NodeID{n.ID}, ids...)
		}
		var rPath []NodeID
		for _, p := range req.ReturnPath {
			rPath = append(rPath, NodeID(p))
		}
		target := strings.TrimSpace(req.Target)
		if target == "" {
			target = n.HTTPProbeURL
		}
		routeName := strings.TrimSpace(req.Route)
		log.Printf("[controller ws] recv route_diag route=%s path=%v return=%v target=%s run=%s", routeName, ids, rPath, target, req.RunID)
		go n.runRouteDiag(ctx, req.RunID, routeName, ids, rPath, target)
	case "endpoint_check":
		var req struct {
			RunID string `json:"run_id"`
		}
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return
		}
		go n.runEndpointCheck(ctx, req.RunID)
	case "time_sync":
		var req struct {
			RunID    string `json:"run_id"`
			Timezone string `json:"timezone"`
		}
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return
		}
		go n.runTimeSync(ctx, req.RunID, req.Timezone)
	case "force_update":
		go n.checkAndUpdateFromController(ctx, true)
	case "uninstall":
		go n.runUninstall(ctx)
	case "diag_collect":
		var req struct {
			RunID    string `json:"run_id"`
			Limit    int    `json:"limit"`
			Contains string `json:"contains"`
			Clear    bool   `json:"clear_before"`
			DelayMs  int    `json:"delay_ms"`
		}
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return
		}
		if req.Limit <= 0 {
			req.Limit = 200
		}
		if req.Clear {
			logFilter.ClearTail()
		}
		if req.DelayMs > 0 {
			timer := time.NewTimer(time.Duration(req.DelayMs) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		lines := logFilter.Tail(req.Limit, req.Contains)
		payload := struct {
			RunID  string   `json:"run_id"`
			Node   string   `json:"node"`
			At     int64    `json:"at"`
			Lines  []string `json:"lines"`
			Limit  int      `json:"limit"`
			Filter string   `json:"filter"`
		}{
			RunID:  req.RunID,
			Node:   string(n.ID),
			At:     time.Now().UnixMilli(),
			Lines:  lines,
			Limit:  req.Limit,
			Filter: req.Contains,
		}
		go n.pushWSMessage(ctx, "diag_report", payload)
	default:
	}
}

func (n *Node) runUninstall(ctx context.Context) {
	status := "success"
	var errs []string
	installDir := detectInstallDir(n)

	errs = append(errs, uninstallServicePre()...)
	errs = append(errs, cleanupNodeFiles(n, installDir)...)
	if len(errs) > 0 {
		status = "failed"
	}
	reason := strings.Join(errs, "; ")
	_ = n.pushWSMessage(ctx, "uninstall_result", map[string]any{
		"status": status,
		"reason": reason,
	})
	time.Sleep(300 * time.Millisecond)
	_ = uninstallServiceStop()
	os.Exit(0)
}

func detectInstallDir(n *Node) string {
	if tokenPathValue != "" {
		if abs, err := filepath.Abs(tokenPathValue); err == nil {
			return filepath.Dir(abs)
		}
	}
	if n != nil && n.TokenPath != "" {
		return filepath.Dir(n.TokenPath)
	}
	if configPathValue != "" {
		if abs, err := filepath.Abs(configPathValue); err == nil {
			return filepath.Dir(abs)
		}
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		return filepath.Dir(exe)
	}
	return ""
}

func cleanupNodeFiles(n *Node, installDir string) []string {
	var errs []string
	removeFile := func(p string) {
		if p == "" {
			return
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err.Error())
		}
	}
	if configPathValue != "" {
		if abs, err := filepath.Abs(configPathValue); err == nil {
			removeFile(abs)
		}
	}
	if tokenPathValue != "" {
		if abs, err := filepath.Abs(tokenPathValue); err == nil {
			removeFile(abs)
		}
	}
	if n != nil {
		removeFile(n.TokenPath)
		if installDir != "" {
			if strings.HasPrefix(n.CertPath, installDir) {
				removeFile(n.CertPath)
			}
			if strings.HasPrefix(n.KeyPath, installDir) {
				removeFile(n.KeyPath)
			}
		}
	}
	if installDir != "" && installDir != "/" && installDir != "." {
		if err := os.RemoveAll(installDir); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

func uninstallServicePre() []string {
	var errs []string
	if runtime.GOOS == "darwin" {
		if err := os.Remove("/Library/LaunchDaemons/com.arouter.node.plist"); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err.Error())
		}
		return errs
	}
	if !commandExists("systemctl") {
		return errs
	}
	_ = exec.Command("systemctl", "disable", "arouter").Run()
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if err := os.Remove("/etc/systemd/system/arouter.service"); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err.Error())
	}
	return errs
}

func uninstallServiceStop() error {
	if runtime.GOOS == "darwin" {
		if commandExists("launchctl") {
			_ = exec.Command("launchctl", "remove", "com.arouter.node").Run()
		}
		return nil
	}
	if !commandExists("systemctl") {
		return nil
	}
	_ = exec.Command("systemctl", "stop", "arouter").Run()
	return nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func toWSURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return raw
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return raw
	}
	return u.String()
}

func targetToAddr(target string) string {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	host := u.Hostname()
	if host == "" {
		return raw
	}
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return raw
		}
	}
	return net.JoinHostPort(host, port)
}

func wsHealthHint(err error, resp *http.Response) string {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return "token 无效或缺失，检查节点 token 与控制器是否一致"
		case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			return "控制器返回重定向，WS 不跟随跳转，请使用最终地址（http/https）"
		case http.StatusOK:
			return "服务返回 200 但未升级 WS，可能是反代未开启 Upgrade/Connection 或路径不对"
		case http.StatusBadRequest:
			return "控制器认为请求非法，可能是反代未升级 WS 或路径错误"
		}
	}
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unexpected EOF"):
		return "连接被对端提前关闭，可能是端口/协议不匹配或反代未升级 WS"
	case strings.Contains(msg, "i/o timeout"):
		return "读超时，可能是反代/防火墙空闲超时或未回 Pong"
	case strings.Contains(msg, "connection refused"):
		return "连接被拒绝，确认控制器监听地址/端口是否可达"
	case strings.Contains(msg, "tls"):
		return "TLS 握手失败，检查是否应使用 ws/wss 以及证书配置"
	}
	return ""
}

func (n *Node) controllerHTTPClient(rawURL string) *http.Client {
	client := fastWSClient(n.TLSConfig)
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		return client
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if u, err := url.Parse(rawURL); err == nil {
		host := u.Hostname()
		if host != "" && net.ParseIP(host) == nil {
			tr.TLSClientConfig.ServerName = host
		}
	}
	return client
}

func (n *Node) checkAndUpdateFromController(ctx context.Context, forced bool) {
	if n.ControllerURL == "" {
		return
	}
	n.updateMu.Lock()
	if n.updating {
		n.updateMu.Unlock()
		return
	}
	n.updating = true
	n.updateMu.Unlock()
	defer func() {
		n.updateMu.Lock()
		n.updating = false
		n.updateMu.Unlock()
	}()

	base := strings.TrimRight(n.ControllerURL, "/")
	versionURL := base + "/api/version"
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(reqCtx, "GET", versionURL, nil)
	client := n.controllerHTTPClient(versionURL)
	client.Timeout = 8 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		logWarn("[update] fetch controller version failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		logWarn("[update] fetch controller version failed: %s %s", resp.Status, strings.TrimSpace(string(body)))
		return
	}
	var payload struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		logWarn("[update] parse controller version failed: %v", err)
		return
	}
	controllerVersion := strings.TrimSpace(payload.Version)
	if controllerVersion == "" {
		_ = n.sendUpdateStatus(ctx, "failed", "", "controller version empty", forced)
		return
	}
	normalizedController := normalizeVersion(controllerVersion)
	normalizedLocal := normalizeVersion(buildVersion)
	if normalizedController == normalizedLocal && !forced {
		_ = n.sendUpdateStatus(ctx, "skipped", controllerVersion, "already latest", forced)
		return
	}

	log.Printf("[update] controller version %s detected, updating from %s", controllerVersion, buildVersion)
	_ = n.sendUpdateStatus(ctx, "in_progress", controllerVersion, "", forced)
	realExe, backupPath, err := n.updateBinaryFromController(ctx, controllerVersion)
	if err != nil {
		logWarn("[update] update failed: %v", err)
		_ = n.sendUpdateStatus(ctx, "failed", controllerVersion, err.Error(), forced)
		return
	}
	_ = n.sendUpdateStatus(ctx, "success", controllerVersion, "", forced)
	log.Printf("[update] update complete, restarting")
	if err := restartSelfWithPath(realExe); err != nil {
		if rollbackErr := rollbackBinary(realExe, backupPath); rollbackErr != nil {
			logWarn("[update] rollback failed after restart error: %v", rollbackErr)
		}
		logWarn("[update] restart failed: %v", err)
		_ = n.sendUpdateStatus(ctx, "failed", controllerVersion, err.Error(), forced)
	}
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

func canonicalVersion(v string) string {
	base := normalizeVersion(v)
	if base == "" {
		return v
	}
	return "v" + base
}

func (n *Node) updateBinaryFromController(ctx context.Context, targetVersion string) (string, string, error) {
	base := strings.TrimRight(n.ControllerURL, "/")
	downloadURL := fmt.Sprintf("%s/downloads/arouter?os=%s&arch=%s", base, runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		return "", "", fmt.Errorf("self-update not supported on windows")
	}
	reqCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(reqCtx, "GET", downloadURL, nil)
	client := n.controllerHTTPClient(downloadURL)
	client.Timeout = 60 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", "", fmt.Errorf("download failed: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}
	expectedHash := strings.TrimSpace(resp.Header.Get("X-Checksum-SHA256"))
	if expectedHash == "" {
		return "", "", fmt.Errorf("missing checksum header from controller")
	}
	targetExe, err := resolveUpdateTargetPath()
	if err != nil {
		return "", "", err
	}
	perm := os.FileMode(0o755)
	if info, err := os.Stat(targetExe); err == nil {
		perm = info.Mode().Perm()
	}
	tmpPath, sum, err := downloadToTemp(resp.Body, filepath.Dir(targetExe), perm)
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(sum, expectedHash) {
		_ = os.Remove(tmpPath)
		return "", "", fmt.Errorf("checksum mismatch: expected %s got %s", expectedHash, sum)
	}
	backupPath, err := swapBinary(targetExe, tmpPath)
	if err != nil {
		return "", "", err
	}
	cleanupBackupChain(targetExe)
	log.Printf("[update] binary replaced with controller version %s", targetVersion)
	return targetExe, backupPath, nil
}

func resolveUpdateTargetPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	target := exePath
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		target = resolved
	}
	target = stripBakPath(target)
	if exists, _ := fileExists(target); exists {
		return target, nil
	}
	if arg0 := strings.TrimSpace(os.Args[0]); arg0 != "" {
		if abs, err := filepath.Abs(arg0); err == nil {
			abs = stripBakPath(abs)
			if exists, _ := fileExists(abs); exists {
				return abs, nil
			}
		}
	}
	return target, nil
}

func stripBakPath(p string) string {
	for strings.HasSuffix(p, ".bak") {
		p = strings.TrimSuffix(p, ".bak")
	}
	return p
}

func cleanupBackupChain(base string) {
	base = stripBakPath(base)
	path := base + ".bak"
	removed := 0
	for i := 0; i < 10; i++ {
		if exists, _ := fileExists(path); !exists {
			break
		}
		_ = os.Remove(path)
		removed++
		path += ".bak"
	}
	if removed > 0 {
		log.Printf("[update] cleaned %d backup binaries", removed)
	}
}

func fileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		return !info.IsDir(), nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func downloadToTemp(r io.Reader, dir string, perm os.FileMode) (string, string, error) {
	tmp, err := os.CreateTemp(dir, ".arouter-update-*")
	if err != nil {
		return "", "", err
	}
	tmpName := tmp.Name()
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hasher), r); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", "", err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		_ = os.Remove(tmpName)
		return "", "", err
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	return tmpName, sum, nil
}

func swapBinary(targetExe, tmpPath string) (string, error) {
	var backupPath string
	if exists, err := fileExists(targetExe); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	} else if exists {
		backupPath = targetExe + ".bak"
		_ = os.Remove(backupPath)
		if err := os.Rename(targetExe, backupPath); err != nil {
			_ = os.Remove(tmpPath)
			return "", err
		}
	}
	if err := os.Rename(tmpPath, targetExe); err != nil {
		if backupPath != "" {
			_ = os.Rename(backupPath, targetExe)
		}
		return "", err
	}
	return backupPath, nil
}

func rollbackBinary(realExe, backupPath string) error {
	if backupPath == "" {
		return nil
	}
	if _, err := os.Stat(backupPath); err != nil {
		return err
	}
	_ = os.Remove(realExe)
	return os.Rename(backupPath, realExe)
}

func (n *Node) sendUpdateStatus(ctx context.Context, status, version, reason string, forced bool) error {
	conn := n.wsConnSafe()
	if conn == nil {
		return fmt.Errorf("ws not connected")
	}
	payload := struct {
		Type string `json:"type"`
		Data struct {
			Status  string `json:"status"`
			Version string `json:"version"`
			Reason  string `json:"reason"`
			Forced  bool   `json:"forced"`
		} `json:"data"`
	}{
		Type: "update_status",
	}
	payload.Data.Status = status
	payload.Data.Version = version
	payload.Data.Reason = reason
	payload.Data.Forced = forced
	data, _ := json.Marshal(payload)
	if werr := conn.Write(ctx, wscompat.MessageText, data); werr != nil {
		return werr
	}
	return nil
}

func restartSelfWithPath(path string) error {
	exePath := strings.TrimSpace(path)
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return err
		}
	}
	args := append([]string{exePath}, os.Args[1:]...)
	if runtime.GOOS == "windows" {
		cmd := exec.Command(exePath, os.Args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Start(); err != nil {
			return err
		}
		os.Exit(0)
		return nil
	}
	return syscall.Exec(exePath, args, os.Environ())
}

// dialWSWithTLS builds dial options respecting SNI/domain and allowing IP override via NetDialContext.
func dialWSWithTLS(ctx context.Context, targetURL string, hostForSNI string, tlsConf *tls.Config) (*wscompat.Conn, *http.Response, error) {
	dialOpts := &wscompat.DialOptions{
		HTTPClient: fastWSClient(tlsConf),
	}
	if hostForSNI != "" && tlsConf != nil {
		tc := tlsConf.Clone()
		tc.ServerName = hostForSNI
		tc.InsecureSkipVerify = tc.InsecureSkipVerify
		dialOpts.TLSClientConfig = tc
	}
	return wscompat.Dial(ctx, targetURL, dialOpts)
}

func (n *Node) runProbeAndReport(ctx context.Context, target string) {
	metrics, err := n.Prober.Probe(ctx, n.ID, NodeID(target))
	payload := struct {
		From    string                     `json:"from"`
		Metrics map[string]LinkMetricsJSON `json:"metrics"`
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
	}{
		From:    string(n.ID),
		Metrics: make(map[string]LinkMetricsJSON),
	}
	if err == nil {
		payload.Metrics[target] = LinkMetricsJSON{
			RTTms:     metrics.RTT.Milliseconds(),
			Loss:      metrics.LossRatio,
			UpdatedAt: time.Now(),
		}
	} else {
		payload.Metrics[target] = LinkMetricsJSON{
			RTTms:     0,
			Loss:      1,
			UpdatedAt: time.Now(),
		}
	}
	// 立即通过 WS 推送
	if n.pushMetricsWS(ctx, payload) {
		return
	}
	// WS 失败则回退 HTTP 推送
	n.metricsMu.Lock()
	n.lastMetrics[NodeID(target)] = metrics
	n.metricsMu.Unlock()
	n.pushMetrics(ctx)
}

func (n *Node) runRouteTest(ctx context.Context, r ManualRoute, target string) {
	ws, ok := n.Transport.(*WSSTransport)
	if !ok {
		log.Printf("[route_test %s] transport not ws", r.Name)
		return
	}
	if target == "" {
		target = n.HTTPProbeURL
	}
	timeout := 20 * time.Second
	logTest("route_test %s start path=%v target=%s timeout=%s", r.Name, r.Path, target, timeout)
	dur, err := ws.ProbeHTTP(ctx, r.Path, target, timeout)
	if dur > timeout {
		dur = timeout
	}
	success := err == nil
	if err != nil {
		logTest("route_test %s failed: %v", r.Name, err)
	} else {
		logTest("route_test %s success rtt=%s", r.Name, dur)
	}
	if e := n.sendRouteTestResult(ctx, r, target, dur, success, err); e != nil {
		logTest("route_test %s send ws result failed: %v", r.Name, e)
	}
	if e := n.reportProbe(ctx, r, dur, success, err); e != nil {
		logTest("route_test %s http report failed: %v", r.Name, e)
	}
}

func (n *Node) runRouteDiag(ctx context.Context, runID string, routeName string, path []NodeID, returnPath []NodeID, target string) {
	ws, ok := n.Transport.(*WSSTransport)
	if !ok {
		log.Printf("[route_diag %s] transport not ws", routeName)
		n.reportDiag(DiagEvent{
			RunID:  runID,
			Route:  routeName,
			Node:   string(n.ID),
			Stage:  "error",
			Detail: "transport not ws",
			At:     time.Now().UnixMilli(),
		})
		return
	}
	if target == "" {
		target = n.HTTPProbeURL
	}
	n.reportDiag(DiagEvent{
		RunID:  runID,
		Route:  routeName,
		Node:   string(n.ID),
		Stage:  "diag_start",
		Detail: fmt.Sprintf("target=%s", target),
		At:     time.Now().UnixMilli(),
	})
	n.reportDiag(DiagEvent{
		RunID:  runID,
		Route:  routeName,
		Node:   string(n.ID),
		Stage:  "return_path",
		Detail: fmt.Sprintf("%v", returnPath),
		At:     time.Now().UnixMilli(),
	})
	if ws != nil {
		n.reportDiag(DiagEvent{
			RunID:  runID,
			Route:  routeName,
			Node:   string(n.ID),
			Stage:  "links_inbound",
			Detail: formatNodeList(ws.inboundPeers()),
			At:     time.Now().UnixMilli(),
		})
		n.reportDiag(DiagEvent{
			RunID:  runID,
			Route:  routeName,
			Node:   string(n.ID),
			Stage:  "links_outbound",
			Detail: formatOutboundStats(ws.PoolSnapshot()),
			At:     time.Now().UnixMilli(),
		})
	}
	timeout := 20 * time.Second
	dur, err := ws.ProbeHTTPDiag(ctx, path, target, timeout, runID, routeName)
	if err != nil {
		n.reportDiag(DiagEvent{
			RunID:  runID,
			Route:  routeName,
			Node:   string(n.ID),
			Stage:  "probe_fail",
			Detail: err.Error(),
			At:     time.Now().UnixMilli(),
		})
	} else {
		n.reportDiag(DiagEvent{
			RunID:  runID,
			Route:  routeName,
			Node:   string(n.ID),
			Stage:  "probe_ok",
			Detail: fmt.Sprintf("rtt=%s", dur),
			At:     time.Now().UnixMilli(),
		})
	}
	if len(returnPath) >= 2 {
		addr := targetToAddr(target)
		if addr == "" {
			n.reportDiag(DiagEvent{
				RunID:  runID,
				Route:  routeName,
				Node:   string(n.ID),
				Stage:  "return_skip",
				Detail: "invalid target addr",
				At:     time.Now().UnixMilli(),
			})
			return
		}
		n.reportDiag(DiagEvent{
			RunID:  runID,
			Route:  routeName,
			Node:   string(n.ID),
			Stage:  "return_start",
			Detail: fmt.Sprintf("addr=%s", addr),
			At:     time.Now().UnixMilli(),
		})
		diagCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		err = ws.DiagReturnPath(diagCtx, path, returnPath, addr, routeName, runID)
		cancel()
		if err != nil {
			n.reportDiag(DiagEvent{
				RunID:  runID,
				Route:  routeName,
				Node:   string(n.ID),
				Stage:  "return_fail",
				Detail: err.Error(),
				At:     time.Now().UnixMilli(),
			})
		} else {
			n.reportDiag(DiagEvent{
				RunID:  runID,
				Route:  routeName,
				Node:   string(n.ID),
				Stage:  "return_ok",
				Detail: "return path established",
				At:     time.Now().UnixMilli(),
			})
		}
	}
}

func (n *Node) runEndpointCheck(ctx context.Context, runID string) {
	if runID == "" {
		return
	}
	endpoints := n.PeerEndpoints
	if ws, ok := n.Transport.(*WSSTransport); ok {
		endpoints = ws.Endpoints
	}
	results := make([]EndpointCheckResult, 0)
	if len(endpoints) == 0 {
		_ = n.pushWSMessage(ctx, "endpoint_check_result", map[string]any{
			"run_id":  runID,
			"node":    string(n.ID),
			"results": results,
		})
		return
	}
	for peer, ep := range endpoints {
		epStr := strings.TrimSpace(ep)
		if epStr == "" {
			continue
		}
		start := time.Now()
		checkCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		status, err := dialWSCheck(checkCtx, epStr, n.TLSConfig, n.ServerName)
		cancel()
		res := EndpointCheckResult{
			Node:     string(n.ID),
			Peer:     string(peer),
			Endpoint: epStr,
			RTTMs:    time.Since(start).Milliseconds(),
			Status:   status,
		}
		if err != nil {
			res.OK = false
			res.Error = err.Error()
		} else {
			res.OK = true
		}
		results = append(results, res)
	}
	_ = n.pushWSMessage(ctx, "endpoint_check_result", map[string]any{
		"run_id":  runID,
		"node":    string(n.ID),
		"results": results,
	})
}

func (n *Node) runTimeSync(ctx context.Context, runID string, tz string) {
	if runID == "" {
		return
	}
	if strings.TrimSpace(tz) == "" {
		tz = "Asia/Shanghai"
	}
	steps := make([]TimeSyncStep, 0)
	addStep := func(step TimeSyncStep) {
		steps = append(steps, step)
	}
	if os.Geteuid() != 0 {
		addStep(TimeSyncStep{Command: "check root", OK: false, Error: "not running as root"})
		_ = n.pushWSMessage(ctx, "time_sync_result", TimeSyncResult{
			RunID:    runID,
			Node:     string(n.ID),
			Timezone: tz,
			Success:  false,
			Steps:    steps,
		})
		return
	}
	runCmd := func(timeout time.Duration, name string, args ...string) TimeSyncStep {
		step := TimeSyncStep{Command: strings.Join(append([]string{name}, args...), " ")}
		cmdCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		out, err := exec.CommandContext(cmdCtx, name, args...).CombinedOutput()
		if len(out) > 0 {
			step.Output = strings.TrimSpace(string(out))
		}
		if err != nil {
			step.OK = false
			if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
				step.Error = "timeout"
			} else {
				step.Error = err.Error()
			}
			return step
		}
		step.OK = true
		return step
	}
	runSkip := func(cmd, reason string) {
		addStep(TimeSyncStep{Command: cmd, OK: false, Skipped: true, Error: reason})
	}

	if _, err := exec.LookPath("timedatectl"); err == nil {
		addStep(runCmd(10*time.Second, "timedatectl", "set-timezone", tz))
		addStep(runCmd(10*time.Second, "timedatectl", "set-ntp", "true"))
	} else {
		runSkip("timedatectl", "skipped: timedatectl not found")
	}

	if _, err := exec.LookPath("chronyc"); err != nil {
		if _, err := exec.LookPath("apt-get"); err == nil {
			addStep(runCmd(120*time.Second, "apt-get", "update"))
			addStep(runCmd(120*time.Second, "apt-get", "install", "-y", "chrony"))
		} else {
			runSkip("apt-get install chrony", "skipped: apt-get not found")
		}
	}

	if _, err := exec.LookPath("systemctl"); err == nil {
		addStep(runCmd(20*time.Second, "systemctl", "enable", "--now", "chrony"))
	} else {
		runSkip("systemctl enable --now chrony", "skipped: systemctl not found")
	}

	if _, err := exec.LookPath("chronyc"); err == nil {
		addStep(runCmd(10*time.Second, "chronyc", "sources", "-v"))
		addStep(runCmd(10*time.Second, "chronyc", "tracking"))
	} else {
		runSkip("chronyc", "skipped: chronyc not found")
	}

	success := true
	for _, st := range steps {
		if st.Error != "" && !st.Skipped {
			success = false
			break
		}
	}
	_ = n.pushWSMessage(ctx, "time_sync_result", TimeSyncResult{
		RunID:    runID,
		Node:     string(n.ID),
		Timezone: tz,
		Success:  success,
		Steps:    steps,
	})
}

type topologyPayload struct {
	Edges map[NodeID]map[NodeID]LinkMetricsJSON `json:"edges"`
}

type LinkMetricsJSON struct {
	RTTms     int64     `json:"rtt_ms"`
	Loss      float64   `json:"loss"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (n *Node) sendRouteTestResult(ctx context.Context, r ManualRoute, target string, dur time.Duration, success bool, err error) error {
	conn := n.wsConnSafe()
	if conn == nil {
		return fmt.Errorf("ws not connected")
	}
	payload := struct {
		Type string `json:"type"`
		Data struct {
			Route   string   `json:"route"`
			Path    []string `json:"path"`
			Target  string   `json:"target"`
			RTTMs   int64    `json:"rtt_ms"`
			Success bool     `json:"success"`
			Error   string   `json:"error"`
		} `json:"data"`
	}{
		Type: "route_test_result",
	}
	payload.Data.Route = r.Name
	payload.Data.Path = nodeIDsToStrings(r.Path)
	payload.Data.Target = target
	payload.Data.RTTMs = dur.Milliseconds()
	payload.Data.Success = success
	if err != nil {
		payload.Data.Error = err.Error()
	}
	data, _ := json.Marshal(payload)
	if werr := conn.Write(ctx, wscompat.MessageText, data); werr != nil {
		return werr
	}
	logTest("route_test %s ws result sent target=%s rtt=%dms success=%v", r.Name, target, payload.Data.RTTMs, success)
	return nil
}

type certPayload struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (n *Node) pullTopology(ctx context.Context) {
	if n.ControllerURL == "" {
		return
	}
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/topology"
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(reqCtx, "GET", url, nil)
	if tok := n.loadToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpTimeoutClient.Do(req)
	if err != nil {
		log.Printf("pull topology failed: %v", err)
		return
	}
	defer resp.Body.Close()
	var payload topologyPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		log.Printf("decode topology failed: %v", err)
		return
	}
	for from, row := range payload.Edges {
		for to, jm := range row {
			m := LinkMetrics{
				RTT:       time.Duration(jm.RTTms) * time.Millisecond,
				LossRatio: jm.Loss,
				UpdatedAt: jm.UpdatedAt,
			}
			n.Router.Topology.Set(from, to, m)
			if from == n.ID {
				n.recordMetric(to, m)
			}
		}
	}
}

func (n *Node) fetchCertLoop(ctx context.Context) {
	if n.ControllerURL == "" || n.CertPath == "" || n.KeyPath == "" {
		return
	}
	interval := n.TopologyPull
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	n.fetchCert(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.fetchCert(ctx)
		}
	}
}

func (n *Node) fetchCert(ctx context.Context) {
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/certs"
	log.Printf("[config] fetching cert from %s", url)
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(reqCtx, "GET", url, nil)
	if tok := n.loadToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpTimeoutClient.Do(req)
	if err != nil {
		log.Printf("[config] fetch cert failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[config] fetch cert non-2xx: %s body=%s", resp.Status, string(body))
		return
	}
	var payload certPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		log.Printf("[config] decode cert payload failed: %v", err)
		return
	}
	if payload.Cert == "" || payload.Key == "" {
		log.Printf("[config] cert payload empty")
		return
	}
	ensureDir := func(path string) error {
		dir := filepath.Dir(path)
		if dir == "" || dir == "." {
			return nil
		}
		return os.MkdirAll(dir, 0700)
	}
	if err := ensureDir(n.CertPath); err != nil {
		log.Printf("[config] ensure cert dir failed: %v", err)
		return
	}
	if err := ensureDir(n.KeyPath); err != nil {
		log.Printf("[config] ensure key dir failed: %v", err)
		return
	}
	if err := os.WriteFile(n.CertPath, []byte(payload.Cert), 0600); err != nil {
		log.Printf("[config] write cert failed: %v", err)
		return
	}
	if err := os.WriteFile(n.KeyPath, []byte(payload.Key), 0600); err != nil {
		log.Printf("[config] write key failed: %v", err)
		return
	}
	log.Printf("[config] updated cert/key from controller -> cert=%s key=%s", n.CertPath, n.KeyPath)
}

type routesPayload struct {
	Routes []routePlanConfig `json:"routes"`
}

func (n *Node) pullRoutes(ctx context.Context) {
	if n.ControllerURL == "" {
		return
	}
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/node-routes/" + url.PathEscape(string(n.ID))
	log.Printf("[config] fetching routes from %s", url)
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(reqCtx, "GET", url, nil)
	if tok := n.loadToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpTimeoutClient.Do(req)
	if err != nil {
		log.Printf("[config] pull routes failed: %v", err)
		return
	}
	defer resp.Body.Close()
	var payload routesPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		log.Printf("[config] decode routes failed: %v", err)
		return
	}
	n.updateManualRoutes(buildManualRouteMap(n.ID, payload.Routes))
}

// Prober measures RTT/loss between peers.
type Prober interface {
	Probe(ctx context.Context, local, remote NodeID) (LinkMetrics, error)
}

// WSProber 通过简单的 WebSocket 握手 + Ping 估计 RTT。
type WSProber struct {
	Endpoints  map[NodeID]string
	TLSConfig  *tls.Config
	Timeout    time.Duration
	Transport  string
	ServerName string
}

func (p *WSProber) Probe(ctx context.Context, _, remote NodeID) (LinkMetrics, error) {
	url, ok := p.Endpoints[remote]
	if !ok {
		return LinkMetrics{}, fmt.Errorf("endpoint for %s not found", remote)
	}
	tr := strings.ToLower(p.Transport)
	if strings.HasPrefix(url, "quic://") || tr == "quic" {
		addr := strings.TrimPrefix(url, "quic://")
		if !strings.Contains(addr, ":") {
			return LinkMetrics{}, fmt.Errorf("invalid quic addr %s", addr)
		}
		to := p.Timeout
		if to == 0 {
			to = 8 * time.Second
		}
		ctxDial, cancel := context.WithTimeout(ctx, to)
		defer cancel()
		tlsConf := cloneTLSWithServerName(p.TLSConfig, p.ServerName)
		start := time.Now()
		conn, err := quic.DialAddr(ctxDial, addr, tlsConf, nil)
		if err != nil {
			return LinkMetrics{}, fmt.Errorf("quic probe %s failed: %w", addr, err)
		}
		conn.CloseWithError(0, "probe done")
		return LinkMetrics{
			RTT:       time.Since(start),
			LossRatio: 0,
			UpdatedAt: time.Now(),
		}, nil
	}

	url = normalizeWSEndpoint(probeURL(url))
	to := p.Timeout
	if to == 0 {
		to = 3 * time.Second
	}
	ctxPing, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	startDial := time.Now()
	var c *wscompat.Conn
	var err error
	dialOpts := &wscompat.DialOptions{
		HTTPClient:      fastWSClient(p.TLSConfig),
		TLSClientConfig: cloneTLSWithServerName(p.TLSConfig, p.ServerName),
	}
	c, resp, err := wscompat.Dial(ctxPing, url, dialOpts)
	if err != nil && resp == nil && shouldFallbackToWS(err) && strings.HasPrefix(url, "wss://") {
		wsURL := "ws://" + strings.TrimPrefix(url, "wss://")
		logDebug("[probe] fallback to ws for %s due to tls error: %v", url, err)
		c, resp, err = wscompat.Dial(ctxPing, wsURL, &wscompat.DialOptions{
			HTTPClient: fastWSClient(nil),
		})
		if err == nil {
			url = wsURL
		}
	}
	if err != nil {
		if resp != nil {
			return LinkMetrics{}, fmt.Errorf("dial probe %s failed: status=%s err=%w", url, resp.Status, err)
		}
		return LinkMetrics{}, fmt.Errorf("dial probe %s failed: %w", url, err)
	}
	defer c.Close()
	dialCost := time.Since(startDial)

	// 连接成功后，通过 Ping/Pong 测算更精确的 RTT，失败则回退到握手耗时。
	pingCtx, cancelPing := context.WithTimeout(ctx, 2*time.Second)
	startPing := time.Now()
	if err := c.Ping(pingCtx); err == nil {
		cancelPing()
		return LinkMetrics{
			RTT:       time.Since(startPing),
			LossRatio: 0,
			UpdatedAt: time.Now(),
		}, nil
	}
	cancelPing()
	logDebug("[probe] ping failed on %s, fallback dial RTT: %v", url, dialCost)

	return LinkMetrics{
		RTT:       dialCost,
		LossRatio: 0,
		UpdatedAt: time.Now(),
	}, nil
}

// Transport encapsulates WSS data plane.
type Transport interface {
	Forward(ctx context.Context, src NodeID, path []NodeID, returnPath []NodeID, proto Protocol, downstream net.Conn, remoteAddr string, routeName string) error
	ReconnectTCP(ctx context.Context, src NodeID, proto Protocol, downstream net.Conn, remoteAddr string, computePath func(try int) ([]NodeID, error), attempts int) error
	Serve(ctx context.Context) error
}

// ControlHeader 描述剩余路径和最终出口。
type ControlHeader struct {
	Path        []NodeID `json:"path"`
	FullPath    []NodeID `json:"full_path,omitempty"`
	RemoteAddr  string   `json:"remote"`
	Proto       Protocol `json:"proto"`
	Compression string   `json:"compress,omitempty"`
	CompressMin int      `json:"compress_min,omitempty"`
	EncID       int      `json:"enc_id,omitempty"`
	Session     string   `json:"session,omitempty"`
	ReturnPath  []NodeID `json:"return_path,omitempty"`
	Return      bool     `json:"return,omitempty"`
	RouteName   string   `json:"route,omitempty"`
	EntryNode   NodeID   `json:"entry,omitempty"`
	ClientAddr  string   `json:"client,omitempty"`
	DiagRunID   string   `json:"diag_run_id,omitempty"`
	DiagRoute   string   `json:"diag_route,omitempty"`
}

type DiagEvent struct {
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

type EndpointCheckResult struct {
	Node     string `json:"node"`
	Peer     string `json:"peer"`
	Endpoint string `json:"endpoint"`
	OK       bool   `json:"ok"`
	RTTMs    int64  `json:"rtt_ms"`
	Status   string `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
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

type ctrlType uint8

const (
	ctrlHeader      ctrlType = 1
	ctrlAck         ctrlType = 2
	ctrlError       ctrlType = 3
	ctrlUDP         ctrlType = 4
	ctrlProbe       ctrlType = 5
	ctrlReturnReady ctrlType = 6
	ctrlReturnFail  ctrlType = 7
	ctrlReturnAck   ctrlType = 8
)

func marshalCtrl(t ctrlType, payload []byte) []byte {
	return append([]byte{byte(t)}, payload...)
}

func parseCtrl(payload []byte) (ctrlType, []byte, error) {
	if len(payload) == 0 {
		return 0, nil, fmt.Errorf("empty ctrl payload")
	}
	return ctrlType(payload[0]), payload[1:], nil
}

// UDPDatagram 用于跨 WS 传输单个 UDP 包。
type UDPDatagram struct {
	Src     string `json:"src"`
	Payload []byte `json:"payload"`
}

// EncryptionPolicy 描述可配置的加密策略（由控制器下发）。
type EncryptionPolicy struct {
	ID     int    `json:"id"`
	Name   string `json:"name,omitempty"`
	Method string `json:"method"` // aes-128-gcm | aes-256-gcm | chacha20-poly1305
	Key    string `json:"key"`    // base64 或 hex
	Enable bool   `json:"enable"`
}

// dummyAddr 用于 muxConnAdapter 本地/远端地址占位。
type dummyAddr string

func (d dummyAddr) Network() string { return "mux" }
func (d dummyAddr) String() string  { return string(d) }

func probeURL(endpoint string) string {
	if endpoint == "" {
		return endpoint
	}
	if strings.Contains(endpoint, "/probe") {
		return endpoint
	}
	if strings.HasSuffix(endpoint, "/mesh") {
		return strings.TrimSuffix(endpoint, "/mesh") + "/probe"
	}
	return strings.TrimRight(endpoint, "/") + "/probe"
}

func normalizeWSEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	host := u.Host
	if strings.Contains(host, ":") && !strings.Contains(host, "[") {
		h, p, err := net.SplitHostPort(host)
		if err == nil {
			// 仅 IPv6 需要加 []，IPv4 保持原样
			if ip := net.ParseIP(h); ip != nil && strings.Contains(h, ":") {
				u.Host = fmt.Sprintf("[%s]:%s", h, p)
				return u.String()
			}
			u.Host = net.JoinHostPort(h, p)
			return u.String()
		}
	}
	return u.String()
}

func shouldFallbackToWS(err error) bool {
	if err == nil {
		return false
	}
	var hdrErr *tls.RecordHeaderError
	if errors.As(err, &hdrErr) {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "first record does not look like a TLS handshake") {
		return true
	}
	if strings.Contains(msg, "unexpected EOF") {
		return true
	}
	return false
}

// dialWSWithFallback 优先按 URL 拨号，如果是 wss:// 且握手失败（无 HTTP 状态），则降级为 ws://。
func dialWSWithFallback(ctx context.Context, url string, tlsConf *tls.Config, serverName string) (*wscompat.Conn, *http.Response, error) {
	opts := &wscompat.DialOptions{
		HTTPClient:      fastWSClient(tlsConf),
		TLSClientConfig: cloneTLSWithServerName(tlsConf, serverName),
	}
	conn, resp, err := wscompat.Dial(ctx, url, opts)
	if err != nil && resp != nil {
		return conn, resp, fmt.Errorf("%w (status=%s)", err, resp.Status)
	}
	if err == nil || resp != nil || !strings.HasPrefix(url, "wss://") {
		return conn, resp, err
	}
	if !shouldFallbackToWS(err) {
		return conn, resp, err
	}
	wsURL := "ws://" + strings.TrimPrefix(url, "wss://")
	logDebug("[ws dial] fallback to ws for %s due to tls error: %v", url, err)
	conn, resp, err = wscompat.Dial(ctx, wsURL, &wscompat.DialOptions{
		HTTPClient: fastWSClient(nil),
	})
	return conn, resp, err
}

func dialWSCheck(ctx context.Context, url string, tlsConf *tls.Config, serverName string) (string, error) {
	opts := &wscompat.DialOptions{
		HTTPClient:      fastWSClient(tlsConf),
		TLSClientConfig: cloneTLSWithServerName(tlsConf, serverName),
	}
	conn, resp, err := wscompat.Dial(ctx, url, opts)
	if conn != nil {
		conn.Close()
	}
	status := ""
	if resp != nil {
		status = resp.Status
	}
	return status, err
}

func normalizePeerEndpoint(raw string, mode string) string {
	m := strings.ToLower(mode)
	if strings.HasPrefix(raw, "ws://") || strings.HasPrefix(raw, "wss://") || strings.HasPrefix(raw, "quic://") {
		if m != "quic" && strings.HasPrefix(raw, "ws") && !strings.HasSuffix(raw, "/mesh") {
			return strings.TrimRight(raw, "/") + "/mesh"
		}
		return raw
	}
	// host:port
	if m == "quic" {
		return "quic://" + raw
	}
	if m == "wss" {
		return "wss://" + strings.TrimRight(raw, "/") + "/mesh"
	}
	return "ws://" + strings.TrimRight(raw, "/") + "/mesh"
}

func fastWSClient(baseTLS *tls.Config) *http.Client {
	tlsConf := cloneTLSWithServerName(baseTLS, "")
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	}
	tlsConf.ClientSessionCache = wsSessionCache
	tr := &http.Transport{
		Proxy:               nil, // skip env proxy lookup to reduce dial latency
		TLSClientConfig:     tlsConf,
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false, // 避免 ALPN 协商 h2 导致 websocket 拒绝
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{Transport: tr, Timeout: 6 * time.Second}
}

func configDigest(cfg nodeConfig) string {
	b, _ := json.Marshal(cfg)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AckStatus 记录确认链，Confirmed 是已成功下游建立的节点列表（自下而上聚合）。
type AckStatus struct {
	Confirmed []NodeID `json:"confirmed"`
	Note      string   `json:"note,omitempty"`
}

// ControlEnvelope 用于在数据桥接前传递控制信息（首帧 header、ack、错误）。
type ControlEnvelope struct {
	Type        string           `json:"type"` // header | ack | error | probe_http | probe_result | udp
	Session     string           `json:"session"`
	Header      *ControlHeader   `json:"header,omitempty"`
	Ack         *AckStatus       `json:"ack,omitempty"`
	Error       string           `json:"error,omitempty"`
	Datagram    *UDPDatagram     `json:"datagram,omitempty"` // Type=udp
	Probe       *HTTPProbe       `json:"probe,omitempty"`
	ProbeResult *HTTPProbeResult `json:"probe_result,omitempty"`
	Signature   string           `json:"sig,omitempty"`
	Version     int              `json:"ver,omitempty"`
	Timestamp   int64            `json:"ts,omitempty"` // unix milli
}

type HTTPProbe struct {
	Path   []NodeID `json:"path"`
	Target string   `json:"target"`
}

type HTTPProbeResult struct {
	Success bool   `json:"success"`
	Status  int    `json:"status"`
	Error   string `json:"error,omitempty"`
}

type pooledWS struct {
	conn      *wscompat.Conn
	mux       *MuxManager
	createdAt time.Time
	lastUsed  time.Time
	active    int
	draining  bool
	serveOn   bool
	pinned    bool
	rttEWMA   time.Duration
	lastRTT   time.Duration
	lastPing  time.Time
	failCount int
	lastFail  time.Time
}

type returnSession struct {
	downstream  net.Conn
	forwardRaw  net.Conn
	compression string
	compressMin int
	encID       int
	createdAt   time.Time
	routeName   string
	entryNode   NodeID
	exitNode    NodeID
	auto        bool
}

// WSSTransport 通过 WebSocket 级联转发，可同时监听 WS 与 WSS。
type WSSTransport struct {
	Self                   NodeID
	ListenAddr             string
	TLSListenAddr          string
	CertFile               string
	KeyFile                string
	Endpoints              map[NodeID]string // peer -> ws(s)://host:port/mesh
	TLSConfig              *tls.Config
	ServerName             string
	IdleTimeout            time.Duration
	AuthKey                []byte
	NodeToken              string
	Metrics                *Metrics
	Topology               *Topology
	Compression            string
	CompressMin            int
	EncPolicies            []EncryptionPolicy
	poolMu                 sync.Mutex
	pool                   map[NodeID][]*pooledWS
	maxConnAge             time.Duration
	maxIdle                time.Duration
	maxStreams             int
	disablePool            bool
	muxPingInterval        time.Duration
	muxPingTimeout         time.Duration
	muxCleanupInterval     time.Duration
	muxRTTAlpha            float64
	linkLossAlpha          float64
	muxDefaultQueue        int
	muxStreamQueue         int
	muxBlockOnBackpressure bool
	inboundMu              sync.Mutex
	inboundMux             map[NodeID]*MuxManager
	returnAckMu            sync.Mutex
	returnAckWait          map[string]chan struct{}
	returnAckInfo          map[string]returnAckInfo
	diagReport             func(DiagEvent)
	returnMu               sync.Mutex
	returnSessions         map[string]*returnSession
	returnReadyMu          sync.Mutex
	returnReady            map[string]time.Time
	returnAckTimeout       time.Duration
	diagReturnMu           sync.Mutex
	diagReturnWait         map[string]chan struct{}
	diagReturnFailWait     map[string]chan error
	relayMu                sync.Mutex
	relayPeers             map[string]*MuxStream
	preconnectMu           sync.Mutex
	preconnectPeers        map[NodeID]struct{}
	preconnectInterval     time.Duration
}

func (t *WSSTransport) PoolSnapshot() map[NodeID]MuxPoolStats {
	if t == nil {
		return nil
	}
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	if t.pool == nil {
		return nil
	}

	out := make(map[NodeID]MuxPoolStats, len(t.pool))
	for peer, list := range t.pool {
		var st MuxPoolStats
		st.Total = len(list)
		var sum time.Duration
		var sumCount int64
		for _, p := range list {
			st.Active += p.active
			if p.draining {
				st.Draining++
			}
			st.TotalFails += p.failCount
			if p.lastPing.After(st.LastPing) {
				st.LastPing = p.lastPing
			}
			if p.lastFail.After(st.LastFail) {
				st.LastFail = p.lastFail
			}
			if p.rttEWMA > 0 {
				if st.MinRTTEWMA == 0 || p.rttEWMA < st.MinRTTEWMA {
					st.MinRTTEWMA = p.rttEWMA
				}
				if p.rttEWMA > st.MaxRTTEWMA {
					st.MaxRTTEWMA = p.rttEWMA
				}
				sum += p.rttEWMA
				sumCount++
			}
		}
		if sumCount > 0 {
			st.AvgRTTEWMA = time.Duration(int64(sum) / sumCount)
		}
		out[peer] = st
	}
	return out
}

func (t *WSSTransport) Serve(ctx context.Context) error {
	go t.cleanupMuxPool(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/mesh", func(w http.ResponseWriter, r *http.Request) {
		c, err := wscompat.Accept(w, r, &wscompat.AcceptOptions{})
		if err != nil {
			log.Printf("accept ws failed: %v", err)
			return
		}
		go t.handleConn(ctx, c)
	})
	// Probe endpoint: accept WS and just respond to pings, then close.
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		c, err := wscompat.Accept(w, r, &wscompat.AcceptOptions{})
		if err != nil {
			log.Printf("accept ws probe failed: %v", err)
			return
		}
		go func() {
			defer c.Close()
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}()
	})

	srv := &http.Server{
		Addr:         t.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	stopServer := func(s *http.Server) {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.Shutdown(shutdownCtx)
	}
	errCh := make(chan error, 2)
	started := 0
	if strings.TrimSpace(t.ListenAddr) != "" {
		started++
		go stopServer(srv)
		go func() {
			log.Printf("WS transport listening on %s", t.ListenAddr)
			errCh <- srv.ListenAndServe()
		}()
	}
	if strings.TrimSpace(t.TLSListenAddr) != "" && t.CertFile != "" && t.KeyFile != "" {
		tlsSrv := &http.Server{
			Addr:         t.TLSListenAddr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			TLSConfig:    t.TLSConfig,
		}
		started++
		go stopServer(tlsSrv)
		go func() {
			log.Printf("WSS transport listening on %s", t.TLSListenAddr)
			errCh <- tlsSrv.ListenAndServeTLS(t.CertFile, t.KeyFile)
		}()
	}
	if started == 0 {
		return fmt.Errorf("no listen address for WS/WSS")
	}
	for i := 0; i < started; i++ {
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}

func (t *WSSTransport) cleanupMuxPool(ctx context.Context) {
	interval := t.muxCleanupInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.poolMu.Lock()
			if t.pool == nil {
				t.poolMu.Unlock()
				continue
			}
			now := time.Now()
			for next, list := range t.pool {
				newList := list[:0]
				for _, p := range list {
					select {
					case <-p.mux.Done():
						p.conn.Close()
						continue
					default:
					}
					expired := t.isExpired(p, now)
					if expired && p.active == 0 && !p.pinned {
						p.conn.Close()
						continue
					}
					if expired && !p.draining && !p.pinned {
						p.draining = true
					}
					// if repeated failures and idle, drop it.
					if p.failCount >= 3 && p.active == 0 && now.Sub(p.lastFail) < 2*time.Minute && !p.pinned {
						p.conn.Close()
						continue
					}
					newList = append(newList, p)
				}
				if len(newList) == 0 {
					delete(t.pool, next)
				} else {
					t.pool[next] = newList
				}
			}
			t.poolMu.Unlock()
		}
	}
}

func (t *WSSTransport) StartPreconnect(ctx context.Context, peers []NodeID, interval time.Duration) {
	if t == nil || len(peers) == 0 || t.disablePool {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	set := make(map[NodeID]struct{}, len(peers))
	for _, p := range peers {
		if p != "" {
			set[p] = struct{}{}
		}
	}
	if len(set) == 0 {
		return
	}
	t.preconnectMu.Lock()
	t.preconnectPeers = set
	t.preconnectInterval = interval
	t.preconnectMu.Unlock()
	go t.preconnectLoop(ctx)
}

func (t *WSSTransport) preconnectLoop(ctx context.Context) {
	t.preconnectMu.Lock()
	interval := t.preconnectInterval
	peers := make([]NodeID, 0, len(t.preconnectPeers))
	for p := range t.preconnectPeers {
		peers = append(peers, p)
	}
	t.preconnectMu.Unlock()
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		for _, peer := range peers {
			t.ensurePreconnect(ctx, peer)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (t *WSSTransport) ensurePreconnect(ctx context.Context, peer NodeID) {
	if t == nil || peer == "" || t.disablePool {
		return
	}
	targetURL, ok := t.Endpoints[peer]
	if !ok || targetURL == "" {
		return
	}
	targetURL = normalizeWSEndpoint(targetURL)
	if t.markPinnedIfExists(peer) {
		return
	}
	ctxDial, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, mux, pw, err := t.getOrDialMux(ctxDial, peer, targetURL)
	if err != nil || mux == nil {
		logWarn("[preconnect] dial to %s failed: %v", peer, err)
		return
	}
	if pw != nil {
		t.poolMu.Lock()
		pw.pinned = true
		t.poolMu.Unlock()
	}
	stream := mux.OpenStream()
	defer stream.Close(context.Background())
	header := ControlHeader{
		Path:       []NodeID{peer},
		FullPath:   []NodeID{t.Self, peer},
		Proto:      Protocol("preconnect"),
		Session:    newSessionID(),
		EntryNode:  t.Self,
		RemoteAddr: "preconnect",
	}
	payload, _ := json.Marshal(header)
	if err := stream.WriteFlags(ctxDial, flagCTRL, marshalCtrl(ctrlHeader, payload)); err != nil {
		logWarn("[preconnect] send header to %s failed: %v", peer, err)
		t.releasePooled(peer, pw)
		return
	}
	ch := mux.subscribe(stream.ID())
	select {
	case f, ok := <-ch:
		if ok && f.flags&(flagFIN|flagRST) != 0 {
		}
	case <-time.After(2 * time.Second):
	}
	t.releasePooled(peer, pw)
}

func (t *WSSTransport) markPinnedIfExists(peer NodeID) bool {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	list := t.pool[peer]
	for _, p := range list {
		if p == nil {
			continue
		}
		select {
		case <-p.mux.Done():
			continue
		default:
		}
		p.pinned = true
		return true
	}
	return false
}

func (t *WSSTransport) handleConn(ctx context.Context, c *wscompat.Conn) {
	defer c.Close()
	if t.IdleTimeout > 0 {
		c.SetReadLimit(64 << 20)
	}
	mux := NewMuxManagerWithConfigStart(NewMuxConn(c), MuxConfig{
		DefaultQueue:        t.muxDefaultQueue,
		StreamQueue:         t.muxStreamQueue,
		BlockOnBackpressure: t.muxBlockOnBackpressure,
	}, 1) // responder uses odd stream IDs
	t.muxServe(ctx, mux)
}

func (t *WSSTransport) handleHTTPProbe(ctx context.Context, c *wscompat.Conn, env ControlEnvelope) {
	_ = c.Close()
}

func (t *WSSTransport) getOrDial(ctx context.Context, next NodeID, url string) (*wscompat.Conn, error) {
	conn, _, err := dialWSWithFallback(ctx, url, t.TLSConfig, t.ServerName)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (t *WSSTransport) startMuxServeClient(mux *MuxManager) {
	if mux == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-mux.Done()
		cancel()
	}()
	go t.muxServe(ctx, mux)
}

func (t *WSSTransport) registerInboundMux(peer NodeID, mm *MuxManager) {
	if peer == "" || mm == nil {
		return
	}
	needWatch := false
	t.inboundMu.Lock()
	if t.inboundMux == nil {
		t.inboundMux = make(map[NodeID]*MuxManager)
	}
	cur := t.inboundMux[peer]
	if cur != mm {
		t.inboundMux[peer] = mm
		needWatch = true
	}
	t.inboundMu.Unlock()
	if !needWatch {
		return
	}
	go func() {
		<-mm.Done()
		t.inboundMu.Lock()
		if t.inboundMux != nil && t.inboundMux[peer] == mm {
			delete(t.inboundMux, peer)
		}
		t.inboundMu.Unlock()
	}()
}

func (t *WSSTransport) getInboundMux(peer NodeID) *MuxManager {
	if peer == "" {
		return nil
	}
	t.inboundMu.Lock()
	defer t.inboundMu.Unlock()
	if t.inboundMux == nil {
		return nil
	}
	return t.inboundMux[peer]
}

func (t *WSSTransport) inboundPeers() []NodeID {
	t.inboundMu.Lock()
	defer t.inboundMu.Unlock()
	if len(t.inboundMux) == 0 {
		return nil
	}
	out := make([]NodeID, 0, len(t.inboundMux))
	for k := range t.inboundMux {
		out = append(out, k)
	}
	return out
}

func (t *WSSTransport) getOrDialMux(ctx context.Context, next NodeID, url string) (*wscompat.Conn, *MuxManager, *pooledWS, error) {
	// 无池模式：每次新建，流结束后关闭
	if t.disablePool {
		conn, _, err := dialWSWithFallback(ctx, url, t.TLSConfig, t.ServerName)
		if err != nil {
			return nil, nil, nil, err
		}
		mux := NewMuxManager(NewMuxConn(conn))
		t.startMuxServeClient(mux)
		go func() {
			<-mux.Done()
			conn.Close()
		}()
		return conn, mux, nil, nil
	}

	t.poolMu.Lock()
	if t.pool == nil {
		t.pool = make(map[NodeID][]*pooledWS)
	}
	// pick an active mux with available stream capacity
	maxStreams := t.maxStreams
	if maxStreams <= 0 {
		maxStreams = 2
	}
	candidates := t.pool[next]
	now := time.Now()
	// filter out expired or closed
	valid := make([]*pooledWS, 0, len(candidates))
	var chosen *pooledWS
	var chosenScore time.Duration
	var fallback *pooledWS // draining mux as last resort
	for _, p := range candidates {
		select {
		case <-p.mux.Done():
			p.conn.Close()
			logDebug("[mux pool %s] drop closed mux (addr=%p)", next, p)
			continue
		default:
		}
		expired := t.isExpired(p, now)
		if expired && p.active == 0 {
			p.conn.Close()
			logDebug("[mux pool %s] drop expired idle mux (addr=%p)", next, p)
			continue
		}
		if expired && !p.draining {
			p.draining = true
			logDebug("[mux pool %s] mark mux draining (addr=%p)", next, p)
		}
		if !p.draining && p.active < maxStreams {
			score := p.rttEWMA
			if score <= 0 {
				// Prefer connections with measured RTT; unmeasured ones are treated as slow.
				score = 365 * 24 * time.Hour
			}
			// Slightly penalize busy connections.
			score += time.Duration(p.active) * 5 * time.Millisecond
			if chosen == nil || score < chosenScore {
				chosen = p
				chosenScore = score
			}
		}
		if fallback == nil && p.draining && p.active < maxStreams {
			fallback = p
		}
		valid = append(valid, p)
	}
	if len(valid) == 0 {
		delete(t.pool, next)
	} else {
		t.pool[next] = valid
	}
	startServe := false
	if chosen != nil {
		chosen.active++
		chosen.lastUsed = now
		if !chosen.serveOn {
			chosen.serveOn = true
			startServe = true
		}
	}
	t.poolMu.Unlock()
	if chosen != nil {
		if startServe {
			t.startMuxServeClient(chosen.mux)
		}
		logDebug("[mux pool %s] reuse mux (addr=%p) active=%d/%d", next, chosen, chosen.active, maxStreams)
		return chosen.conn, chosen.mux, chosen, nil
	}

	conn, resp, err := dialWSWithFallback(ctx, url, t.TLSConfig, t.ServerName)
	if err != nil {
		if resp != nil {
			err = fmt.Errorf("%w (status=%s url=%s)", err, resp.Status, url)
		}
		// 如果新建失败，降级复用 draining 的连接，尽量保持可用
		if fallback != nil {
			startServe := false
			t.poolMu.Lock()
			fallback.active++
			fallback.lastUsed = time.Now()
			if !fallback.serveOn {
				fallback.serveOn = true
				startServe = true
			}
			t.poolMu.Unlock()
			if startServe {
				t.startMuxServeClient(fallback.mux)
			}
			logWarn("[mux pool %s] dial failed, fallback to draining mux (addr=%p): %v", next, fallback, err)
			return fallback.conn, fallback.mux, fallback, nil
		}
		if t.Topology != nil {
			t.Topology.UpdateLink(t.Self, next, 0, false, t.linkLossAlpha)
			t.Topology.MarkFail(t.Self, next)
		}
		return nil, nil, nil, err
	}
	mux := NewMuxManagerWithConfig(NewMuxConn(conn), MuxConfig{
		DefaultQueue:        t.muxDefaultQueue,
		StreamQueue:         t.muxStreamQueue,
		BlockOnBackpressure: t.muxBlockOnBackpressure,
	})
	pw := &pooledWS{conn: conn, mux: mux, createdAt: now, lastUsed: now, active: 1, serveOn: true}
	t.poolMu.Lock()
	t.pool[next] = append(t.pool[next], pw)
	t.poolMu.Unlock()
	logDebug("[mux pool %s] new mux dialed (addr=%p) active=1/%d", next, pw, maxStreams)
	t.startMuxServeClient(mux)
	if t.Topology != nil {
		t.Topology.ResetFail(t.Self, next)
	}
	go t.keepaliveMux(next, pw)
	go func() {
		<-mux.Done()
		t.evictPooled(next, pw)
	}()
	return conn, mux, pw, nil
}

func (t *WSSTransport) releasePooled(next NodeID, pw *pooledWS) {
	if pw == nil {
		return
	}
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	list := t.pool[next]
	now := time.Now()
	newList := list[:0]
	for _, p := range list {
		if p != pw {
			newList = append(newList, p)
			continue
		}
		if p.active > 0 {
			p.active--
		}
		p.lastUsed = now
		if (p.draining || t.isExpired(p, now)) && p.active == 0 && !p.pinned {
			p.conn.Close()
			logDebug("[mux pool %s] retire mux (addr=%p)", next, p)
			continue
		}
		logDebug("[mux pool %s] release mux (addr=%p) active=%d", next, p, p.active)
		newList = append(newList, p)
	}
	if len(newList) == 0 {
		delete(t.pool, next)
	} else {
		t.pool[next] = newList
	}
}

func (t *WSSTransport) evictPooled(next NodeID, pw *pooledWS) {
	if pw == nil {
		return
	}
	pw.conn.Close()
	logWarn("[mux pool %s] evict mux (addr=%p)", next, pw)
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	list := t.pool[next]
	newList := list[:0]
	for _, p := range list {
		if p != pw {
			newList = append(newList, p)
		}
	}
	if len(newList) == 0 {
		delete(t.pool, next)
	} else {
		t.pool[next] = newList
	}
}

func (t *WSSTransport) isExpired(p *pooledWS, now time.Time) bool {
	if p != nil && p.pinned {
		return false
	}
	maxAge := t.maxConnAge
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}
	maxIdle := t.maxIdle
	if maxIdle <= 0 {
		maxIdle = 2 * time.Minute
	}
	if now.Sub(p.createdAt) > maxAge {
		return true
	}
	if p.active == 0 && now.Sub(p.lastUsed) > maxIdle {
		return true
	}
	return false
}

func (t *WSSTransport) keepaliveMux(next NodeID, pw *pooledWS) {
	interval := t.muxPingInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	timeout := t.muxPingTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	alpha := t.muxRTTAlpha
	if alpha <= 0 || alpha > 1 {
		alpha = 0.2
	}
	lossAlpha := t.linkLossAlpha
	if lossAlpha <= 0 || lossAlpha > 1 {
		lossAlpha = 0.2
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-pw.mux.Done():
			logDebug("[mux pool %s] keepalive stop, mux closed (addr=%p)", next, pw)
			return
		case <-ticker.C:
			ctxPing, cancel := context.WithTimeout(context.Background(), timeout)
			rtt, err := pw.mux.Ping(ctxPing)
			cancel()
			if err != nil {
				logWarn("[mux pool %s] keepalive failed (addr=%p): %v", next, pw, err)
				t.poolMu.Lock()
				pw.failCount++
				pw.lastFail = time.Now()
				t.poolMu.Unlock()
				if t.Topology != nil {
					t.Topology.UpdateLink(t.Self, next, 0, false, lossAlpha)
					t.Topology.MarkFail(t.Self, next)
				}
				t.evictPooled(next, pw)
				return
			}
			var ewma time.Duration
			t.poolMu.Lock()
			pw.lastPing = time.Now()
			pw.lastRTT = rtt
			if pw.rttEWMA <= 0 {
				pw.rttEWMA = rtt
			} else {
				pw.rttEWMA = time.Duration(alpha*float64(rtt) + (1-alpha)*float64(pw.rttEWMA))
			}
			ewma = pw.rttEWMA
			t.poolMu.Unlock()
			if t.Topology != nil {
				t.Topology.UpdateLink(t.Self, next, ewma, true, lossAlpha)
				t.Topology.ResetFail(t.Self, next)
			}
			logDebug("[mux pool %s] keepalive ok (addr=%p) rtt=%v ewma=%v", next, pw, rtt, ewma)
		}
	}
}

func isLockErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "failed to acquire lock") || errors.Is(err, context.DeadlineExceeded)
}

func isFrameErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "invalid frame") || strings.Contains(msg, "unexpected EOF") || strings.Contains(msg, "corrupt input")
}

func isClosedPipeErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EPIPE) ||
		strings.Contains(err.Error(), "closed pipe") ||
		strings.Contains(err.Error(), "use of closed network connection")
}

// muxStreamConn adapts a mux stream to net.Conn-like interface for bridge without extra pipes.
func muxStreamConn(ctx context.Context, stream *MuxStream, onClose func()) net.Conn {
	ch := stream.mgr.subscribe(stream.ID())
	return &muxConnAdapter{
		ctx:     ctx,
		stream:  stream,
		ch:      ch,
		onClose: onClose,
	}
}

type muxConnAdapter struct {
	ctx         context.Context
	stream      *MuxStream
	ch          <-chan muxFrame
	buf         []byte
	closed      bool
	readClosed  bool
	writeClosed bool
	onClose     func()
}

func (m *muxConnAdapter) Read(p []byte) (int, error) {
	if m.closed || m.readClosed {
		return 0, io.EOF
	}
	for {
		if len(m.buf) > 0 {
			n := copy(p, m.buf)
			m.buf = m.buf[n:]
			return n, nil
		}
		var f muxFrame
		var ok bool
		select {
		case f, ok = <-m.ch:
			if !ok {
				m.closed = true
				return 0, io.EOF
			}
		case <-m.stream.mgr.Done():
			m.closed = true
			return 0, io.EOF
		case <-m.ctx.Done():
			m.closed = true
			return 0, io.EOF
		}
		if len(f.payload) > 0 {
			m.buf = f.payload
		}
		if f.flags&(flagFIN|flagRST|flagFINW) != 0 {
			log.Printf("[mux=%p stream=%d] upstream fin/rst flags=%d", m.stream.mgr, m.stream.ID(), f.flags)
			if len(m.buf) == 0 {
				if f.flags&flagFINW != 0 {
					m.readClosed = true
				} else {
					m.closed = true
					if m.onClose != nil {
						m.onClose()
					}
				}
				return 0, io.EOF
			}
			if f.flags&flagFINW != 0 {
				// We still return buffered payload first; EOF will be returned on next Read.
				m.readClosed = true
			}
		}
	}
}

func (m *muxConnAdapter) Write(p []byte) (int, error) {
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	if m.writeClosed {
		return 0, io.ErrClosedPipe
	}
	if err := m.stream.Write(context.Background(), p); err != nil {
		if isLockErr(err) {
			logWarn("[mux stream=%d] write blocked/lock err: %v", m.stream.ID(), err)
		}
		return 0, err
	}
	return len(p), nil
}

func (m *muxConnAdapter) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	if m.onClose != nil {
		m.onClose()
	}
	return m.stream.Close(context.Background())
}

func (m *muxConnAdapter) CloseWrite() error {
	if m.writeClosed {
		return nil
	}
	m.writeClosed = true
	return m.stream.CloseWrite(context.Background())
}

func (m *muxConnAdapter) CloseRead() error {
	m.readClosed = true
	return nil
}

func (m *muxConnAdapter) LocalAddr() net.Addr  { return dummyAddr("mux") }
func (m *muxConnAdapter) RemoteAddr() net.Addr { return dummyAddr("mux") }
func (m *muxConnAdapter) SetDeadline(t time.Time) error {
	return nil
}
func (m *muxConnAdapter) SetReadDeadline(t time.Time) error  { return nil }
func (m *muxConnAdapter) SetWriteDeadline(t time.Time) error { return nil }

// muxServe handles incoming mux frames on an accepted WS connection.
func (t *WSSTransport) muxServe(ctx context.Context, mm *MuxManager) {
	defaultCh := mm.subscribeDefault()
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-defaultCh:
			if !ok {
				return
			}
			if f.flags&flagCTRL != 0 {
				ct, payload, err := parseCtrl(f.payload)
				if err != nil {
					continue
				}
				if ct == ctrlHeader {
					var hdr ControlHeader
					if err := json.Unmarshal(payload, &hdr); err != nil {
						continue
					}
					if hdr.Proto == Protocol("probe") {
						logTest("mux stream=%d recv probe header path=%v target=%s", f.streamID, hdr.Path, hdr.RemoteAddr)
					}
					t.handleMuxHeader(ctx, mm, f.streamID, hdr)
				} else if ct == ctrlProbe {
					var hdr ControlHeader
					if err := json.Unmarshal(payload, &hdr); err != nil {
						continue
					}
					logTest("mux stream=%d recv ctrlProbe path=%v target=%s", f.streamID, hdr.Path, hdr.RemoteAddr)
					t.handleMuxHeader(ctx, mm, f.streamID, hdr)
				} else if ct == ctrlReturnReady {
					var msg returnReadyMsg
					if err := json.Unmarshal(payload, &msg); err != nil {
						continue
					}
					log.Printf("[mux stream=%d] recv return ready session=%s entry=%s exit=%s route=%s auto=%v", f.streamID, msg.Session, msg.Entry, msg.Exit, msg.Route, msg.Auto)
					t.markReturnReady(msg)
					t.markDiagReturnReady(msg.DiagRun)
					if msg.DiagRun != "" && t.diagReport != nil {
						t.diagReport(DiagEvent{
							RunID:  msg.DiagRun,
							Route:  msg.Route,
							Node:   string(t.Self),
							Stage:  "return_ready",
							Detail: fmt.Sprintf("entry=%s exit=%s auto=%v", msg.Entry, msg.Exit, msg.Auto),
							At:     time.Now().UnixMilli(),
						})
					}
					if peer := t.relayPeer(mm, f.streamID); peer != nil {
						_ = peer.WriteFlags(context.Background(), flagCTRL, marshalCtrl(ctrlReturnReady, payload))
					}
				} else if ct == ctrlReturnFail {
					var msg returnFailMsg
					if err := json.Unmarshal(payload, &msg); err != nil {
						continue
					}
					log.Printf("[mux stream=%d] recv return fail session=%s entry=%s exit=%s route=%s auto=%v err=%s", f.streamID, msg.Session, msg.Entry, msg.Exit, msg.Route, msg.Auto, msg.Error)
					t.markReturnFail(msg)
					t.markDiagReturnFail(msg.DiagRun, msg.Error)
					if msg.DiagRun != "" && t.diagReport != nil {
						t.diagReport(DiagEvent{
							RunID:  msg.DiagRun,
							Route:  msg.Route,
							Node:   string(t.Self),
							Stage:  "return_fail",
							Detail: fmt.Sprintf("entry=%s exit=%s auto=%v err=%s", msg.Entry, msg.Exit, msg.Auto, msg.Error),
							At:     time.Now().UnixMilli(),
						})
					}
					if peer := t.relayPeer(mm, f.streamID); peer != nil {
						_ = peer.WriteFlags(context.Background(), flagCTRL, marshalCtrl(ctrlReturnFail, payload))
					}
				} else if ct == ctrlReturnAck {
					var msg returnReadyMsg
					if err := json.Unmarshal(payload, &msg); err != nil {
						continue
					}
					log.Printf("[mux stream=%d] recv return ack session=%s entry=%s exit=%s route=%s auto=%v", f.streamID, msg.Session, msg.Entry, msg.Exit, msg.Route, msg.Auto)
					t.markReturnAck(msg.Session)
					t.reportDiag(ControlHeader{
						Session:   msg.Session,
						EntryNode: NodeID(msg.Entry),
						RouteName: msg.Route,
						DiagRunID: msg.DiagRun,
						DiagRoute: msg.Route,
					}, "return_ack_recv", fmt.Sprintf("entry=%s exit=%s auto=%v", msg.Entry, msg.Exit, msg.Auto))
					if peer := t.relayPeer(mm, f.streamID); peer != nil {
						t.reportDiag(ControlHeader{
							Session:   msg.Session,
							EntryNode: NodeID(msg.Entry),
							RouteName: msg.Route,
							DiagRunID: msg.DiagRun,
							DiagRoute: msg.Route,
						}, "return_ack_relay", fmt.Sprintf("entry=%s exit=%s auto=%v", msg.Entry, msg.Exit, msg.Auto))
						_ = peer.WriteFlags(context.Background(), flagCTRL, marshalCtrl(ctrlReturnAck, payload))
					}
				} else {
					log.Printf("[mux stream=%d] ignore ctrl type=%d", f.streamID, ct)
				}
			} else {
				// 数据帧可能在订阅前先到 defaultCh，推送到对应 stream channel，避免阻塞
				ch := mm.subscribe(f.streamID)
				if mm.cfg.BlockOnBackpressure {
					select {
					case ch <- f:
					case <-mm.Done():
						return
					case <-ctx.Done():
						return
					}
				} else {
					select {
					case ch <- f:
					default:
						mm.resetStream(f.streamID)
						continue
					}
				}
			}
		}
	}
}

// handleMuxHeader processes control header; bridges exit or forwards.
func (t *WSSTransport) handleMuxHeader(ctx context.Context, mm *MuxManager, streamID uint32, hdr ControlHeader) {
	if len(hdr.Path) == 0 || hdr.Path[0] != t.Self {
		log.Printf("[mux stream=%d] header path mismatch, expected start %s got %v", streamID, t.Self, hdr.Path)
		return
	}
	t.reportDiag(hdr, "recv_header", fmt.Sprintf("return=%v proto=%s", hdr.Return, hdr.Proto))
	if hdr.DiagRunID != "" {
		t.reportDiag(hdr, "links_inbound", formatNodeList(t.inboundPeers()))
		t.reportDiag(hdr, "links_outbound", formatOutboundStats(t.PoolSnapshot()))
	}
	if hdr.Return {
		log.Printf("[mux stream=%d] recv return header session=%s path=%v", streamID, hdr.Session, hdr.Path)
	} else {
		if upstream := upstreamFromHeader(hdr, t.Self); upstream != "" {
			t.registerInboundMux(upstream, mm)
		}
	}
	remaining := hdr.Path[1:]

	upStream := &MuxStream{id: streamID, m: mm.Conn(), mgr: mm}
	if len(remaining) == 0 {
		t.handleMuxHeaderEgress(ctx, mm, streamID, hdr, upStream)
		return
	}

	streamCh := mm.subscribe(streamID)
	t.handleMuxHeaderRelay(ctx, mm, streamID, hdr, upStream, streamCh, remaining)
}

func forwardUDPToStream(wsConn net.Conn, udpConn net.Conn, metrics *Metrics) {
	buf := make([]byte, 65535)
	for {
		n, err := udpConn.Read(buf)
		if n > 0 {
			wsConn.Write(buf[:n])
			if metrics != nil {
				metrics.AddDown(int64(n))
			}
		}
		if err != nil {
			return
		}
	}
}

func forwardStreamToUDP(wsConn net.Conn, udpConn net.Conn, metrics *Metrics) {
	buf := make([]byte, 65535)
	for {
		n, err := wsConn.Read(buf)
		if n > 0 {
			udpConn.Write(buf[:n])
			if metrics != nil {
				metrics.AddUp(int64(n))
			}
		}
		if err != nil {
			return
		}
	}
}

func (t *WSSTransport) handleTCPExit(ctx context.Context, session string, c *wscompat.Conn, remoteAddr string, compression string, compressMin int) error {
	out, err := net.DialTimeout("tcp", remoteAddr, 5*time.Second)
	if err != nil {
		log.Printf("[session=%s] dial remote %s failed: %v", session, remoteAddr, err)
		return err
	}
	if err := writeSignedEnvelope(ctx, c, ControlEnvelope{
		Type:    "ack",
		Session: session,
		Ack:     &AckStatus{Confirmed: []NodeID{t.Self}, Note: "exit connected"},
	}, t.AuthKey); err != nil {
		out.Close()
		return fmt.Errorf("send exit ack failed: %w", err)
	}
	conn := wscompat.NetConn(ctx, c, wscompat.MessageBinary)
	// 出口按照请求的压缩策略处理
	if err := bridgeMaybeCompressed(session, out, conn, compression, compressMin, t.Metrics, nil, remoteAddr); err != nil {
		return err
	}
	return nil
}

func (t *WSSTransport) handleUDPExit(ctx context.Context, session string, c *wscompat.Conn, remoteAddr string) error {
	conn, err := net.Dial("udp", remoteAddr)
	if err != nil {
		log.Printf("[session=%s] dial remote udp %s failed: %v", session, remoteAddr, err)
		return err
	}
	if err := writeSignedEnvelope(ctx, c, ControlEnvelope{
		Type:    "ack",
		Session: session,
		Ack:     &AckStatus{Confirmed: []NodeID{t.Self}, Note: "udp exit connected"},
	}, t.AuthKey); err != nil {
		conn.Close()
		return fmt.Errorf("send exit ack failed: %w", err)
	}

	errCh := make(chan error, 2)

	// 下游 -> 远端
	go func() {
		for {
			env, err := readVerifiedEnvelope(ctx, c, t.AuthKey)
			if err != nil {
				errCh <- err
				return
			}
			if env.Type != "udp" || env.Datagram == nil {
				errCh <- fmt.Errorf("unexpected msg type %s", env.Type)
				return
			}
			if _, err := conn.Write(env.Datagram.Payload); err != nil {
				errCh <- err
				return
			}
			if t.Metrics != nil {
				t.Metrics.AddUp(int64(len(env.Datagram.Payload)))
			}
		}
	}()

	// 远端 -> 上游
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			payload := append([]byte(nil), buf[:n]...)
			if err := writeSignedEnvelope(ctx, c, ControlEnvelope{
				Type:     "udp",
				Session:  session,
				Datagram: &UDPDatagram{Src: remoteAddr, Payload: payload},
			}, t.AuthKey); err != nil {
				errCh <- err
				return
			}
			if t.Metrics != nil {
				t.Metrics.AddDown(int64(len(payload)))
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (t *WSSTransport) relayUDP(ctx context.Context, session string, upstream, downstream *wscompat.Conn) {
	errCh := make(chan error, 2)
	forward := func(src, dst *wscompat.Conn, dir string) {
		for {
			env, err := readVerifiedEnvelope(ctx, src, t.AuthKey)
			if err != nil {
				errCh <- err
				return
			}
			if env.Type != "udp" || env.Datagram == nil {
				errCh <- fmt.Errorf("unexpected msg type %s", env.Type)
				return
			}
			if err := writeSignedEnvelope(ctx, dst, ControlEnvelope{
				Type:     "udp",
				Session:  session,
				Datagram: env.Datagram,
			}, t.AuthKey); err != nil {
				errCh <- err
				return
			}
			if t.Metrics != nil {
				if dir == "down" {
					t.Metrics.AddUp(int64(len(env.Datagram.Payload)))
				} else {
					t.Metrics.AddDown(int64(len(env.Datagram.Payload)))
				}
			}
		}
	}
	go forward(upstream, downstream, "down")
	go forward(downstream, upstream, "up")

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("[session=%s] udp relay error: %v", session, err)
		}
	}
}

func writeSignedEnvelope(ctx context.Context, c *wscompat.Conn, env ControlEnvelope, key []byte) error {
	if env.Version == 0 {
		env.Version = 1
	}
	if env.Timestamp == 0 {
		env.Timestamp = time.Now().UnixMilli()
	}
	if len(key) > 0 {
		if err := signEnvelope(&env, key); err != nil {
			return err
		}
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return c.Write(ctx, wscompat.MessageText, data)
}

func readVerifiedEnvelope(ctx context.Context, c *wscompat.Conn, key []byte) (ControlEnvelope, error) {
	var env ControlEnvelope
	_, data, err := c.Read(ctx)
	if err != nil {
		return env, err
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return env, err
	}
	if env.Version != 1 {
		return env, fmt.Errorf("unsupported version %d", env.Version)
	}
	if env.Timestamp > 0 && time.Since(time.UnixMilli(env.Timestamp)) > 5*time.Minute {
		return env, fmt.Errorf("envelope too old")
	}
	if len(key) == 0 {
		return env, nil
	}
	if err := verifyEnvelope(&env, key); err != nil {
		return env, err
	}
	return env, nil
}

func bridgeWithLogging(session string, a, b net.Conn, m *Metrics) error {
	return bridgeMaybeCompressed(session, a, b, "none", 0, m, nil, "")
}

func bridgeMaybeCompressed(session string, dst, src net.Conn, compression string, minBytes int, m *Metrics, path []NodeID, remote string) error {
	var upCounter, downCounter *int64
	if m != nil {
		upCounter = &m.bytesUp
		downCounter = &m.bytesDown
	}
	compression = strings.ToLower(compression)
	if compression == "" {
		compression = "none"
	}

	pathStr := ""
	if len(path) > 0 {
		parts := make([]string, len(path))
		for i, p := range path {
			parts[i] = string(p)
		}
		pathStr = strings.Join(parts, " -> ")
	}
	log.Printf("[flow session=%s] start bridge compression=%s min=%d from=%s to=%s remote=%s path=%s", session, compression, minBytes, safeAddr(src), safeAddr(dst), remote, pathStr)

	errCh := make(chan error, 2)
	go func() {
		if compression == "none" {
			errCh <- pipeNone(dst, src, downCounter, false)
			return
		}
		errCh <- copyWithCompression(dst, src, compression, minBytes, downCounter, false)
	}()
	go func() {
		if compression == "none" {
			errCh <- pipeNone(src, dst, upCounter, true)
			return
		}
		errCh <- copyWithCompression(src, dst, compression, minBytes, upCounter, true)
	}()
	startUp := int64(0)
	startDown := int64(0)
	if m != nil {
		startUp = atomic.LoadInt64(&m.bytesUp)
		startDown = atomic.LoadInt64(&m.bytesDown)
	}
	err1 := <-errCh
	err2 := <-errCh
	dst.Close()
	src.Close()
	err := err1
	if err == nil {
		err = err2
	}
	if err != nil && (errors.Is(err, io.EOF) || isClosedPipeErr(err) || isCanceledErr(err)) {
		err = nil
	}
	if err != nil && !isCanceledErr(err) && !errors.Is(err, io.EOF) {
		log.Printf("[session=%s] bridge error: %v", session, err)
	}
	if m != nil {
		up := atomic.LoadInt64(&m.bytesUp) - startUp
		down := atomic.LoadInt64(&m.bytesDown) - startDown
		pathStr := ""
		if len(path) > 0 {
			parts := make([]string, len(path))
			for i, p := range path {
				parts[i] = string(p)
			}
			pathStr = strings.Join(parts, " -> ")
		}
		log.Printf("[flow session=%s] in=%dB out=%dB from=%s to=%s remote=%s path=%s compression=%s", session, down, up, safeAddr(src), safeAddr(dst), remote, pathStr, compression)
	}
	return err
}

type closeReader interface {
	CloseRead() error
}

type closeWriter interface {
	CloseWrite() error
}

func pipeNone(dst, src net.Conn, counter *int64, compress bool) error {
	startMsg := fmt.Sprintf("[copy %s] compression=none src=%s dst=%s", dirLabel(compress), safeAddr(src), safeAddr(dst))
	n, err := io.Copy(&countingWriter{Writer: dst, counter: counter}, src)

	if cr, ok := src.(closeReader); ok {
		_ = cr.CloseRead()
	}
	// NOTE: Mux stream connections (wsConnAdapter) do not support TCP half-close semantics.
	// For those, we must not close the stream here because it would terminate the reverse direction
	// (e.g., iperf3 -R where client->server finishes early but server->client is still sending).
	// We only half-close when the underlying conn supports it; full close happens after both directions complete.
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	}

	if isClosedPipeErr(err) || errors.Is(err, net.ErrClosed) {
		err = io.EOF
	}
	log.Printf("%s done bytes=%d err=%v", startMsg, n, err)
	return err
}

func safeAddr(c net.Conn) string {
	if c == nil {
		return ""
	}
	if addr := c.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

func (t *WSSTransport) reportDiag(hdr ControlHeader, stage string, detail string) {
	if t == nil || t.diagReport == nil || hdr.DiagRunID == "" {
		return
	}
	ev := DiagEvent{
		RunID:   hdr.DiagRunID,
		Route:   hdr.DiagRoute,
		Node:    string(t.Self),
		Stage:   stage,
		Detail:  detail,
		Session: hdr.Session,
		At:      time.Now().UnixMilli(),
	}
	if len(hdr.FullPath) > 0 {
		ev.Path = make([]string, 0, len(hdr.FullPath))
		for _, p := range hdr.FullPath {
			ev.Path = append(ev.Path, string(p))
		}
	} else if len(hdr.Path) > 0 {
		ev.Path = make([]string, 0, len(hdr.Path))
		for _, p := range hdr.Path {
			ev.Path = append(ev.Path, string(p))
		}
	}
	if len(hdr.ReturnPath) > 0 {
		ev.ReturnPath = make([]string, 0, len(hdr.ReturnPath))
		for _, p := range hdr.ReturnPath {
			ev.ReturnPath = append(ev.ReturnPath, string(p))
		}
	}
	t.diagReport(ev)
}

func formatNodeList(nodes []NodeID) string {
	if len(nodes) == 0 {
		return "-"
	}
	items := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if n != "" {
			items = append(items, string(n))
		}
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func formatOutboundStats(stats map[NodeID]MuxPoolStats) string {
	if len(stats) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(stats))
	for node, st := range stats {
		if node == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(%d/%d)", node, st.Active, st.Total))
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
}

func upstreamFromHeader(hdr ControlHeader, self NodeID) NodeID {
	if len(hdr.FullPath) >= 2 {
		for i := 1; i < len(hdr.FullPath); i++ {
			if hdr.FullPath[i] == self {
				return hdr.FullPath[i-1]
			}
		}
	}
	if hdr.EntryNode != "" && hdr.EntryNode != self {
		return hdr.EntryNode
	}
	return ""
}

func dirLabel(compress bool) string {
	if compress {
		return "up/compress"
	}
	return "down/decompress"
}

func logCopyDone(startMsg string, counter *int64, start int64, err error) {
	delta := int64(-1)
	if counter != nil && start >= 0 {
		delta = atomic.LoadInt64(counter) - start
	}
	log.Printf("%s done delta=%d err=%v", startMsg, delta, err)
}

func copyWithCompression(dst net.Conn, src net.Conn, compression string, minBytes int, counter *int64, compress bool) error {
	var startCount int64 = -1
	if counter != nil {
		startCount = atomic.LoadInt64(counter)
	}
	startMsg := fmt.Sprintf("[copy %s] compression=%s src=%s dst=%s", dirLabel(compress), compression, safeAddr(src), safeAddr(dst))
	// none: direct copy
	if compression == "none" {
		n, err := io.Copy(&countingWriter{Writer: dst, counter: counter}, src)
		if isClosedPipeErr(err) || errors.Is(err, net.ErrClosed) {
			err = io.EOF
		}
		log.Printf("%s done bytes=%d err=%v", startMsg, n, err)
		return err
	}
	if compression != "gzip" {
		log.Printf("unsupported compression %s, fallback none", compression)
		n, err := io.Copy(&countingWriter{Writer: dst, counter: counter}, src)
		log.Printf("%s (fallback none) done bytes=%d err=%v", startMsg, n, err)
		return err
	}

	if compress {
		err := compressStream(dst, src, compression, minBytes, counter)
		if isClosedPipeErr(err) {
			err = io.EOF
		}
		logCopyDone(startMsg, counter, startCount, err)
		return err
	}
	err := decompressStream(dst, src, compression, minBytes, counter)
	if isClosedPipeErr(err) {
		err = io.EOF
	}
	logCopyDone(startMsg, counter, startCount, err)
	return err
}

func compressStream(dst net.Conn, src net.Conn, compression string, minBytes int, counter *int64) error {
	log.Printf("[compress] alg=%s min=%d src=%s dst=%s", compression, minBytes, safeAddr(src), safeAddr(dst))
	// Read optional threshold bytes
	if minBytes > 0 {
		buf := make([]byte, minBytes)
		n, err := io.ReadFull(src, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return err
		}
		if n < minBytes && (err == io.ErrUnexpectedEOF || err == io.EOF) {
			// 小流量，直接透传
			if counter != nil {
				atomic.AddInt64(counter, int64(n))
			}
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return werr
				}
			}
			log.Printf("[compress] below threshold (%dB), passthrough", n)
			if err == io.EOF {
				return nil
			}
			return err
		}
		// 达到阈值，开始压缩并写入已读缓冲
		w, closer, err := compressor(dst, compression)
		if err != nil {
			log.Printf("compression %s unavailable, fallback passthrough: %v", compression, err)
			if counter != nil {
				atomic.AddInt64(counter, int64(n))
			}
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return werr
				}
			}
			_, errCopy := io.Copy(&countingWriter{Writer: dst, counter: counter}, src)
			return errCopy
		}
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				closer.Close()
				return werr
			}
			if counter != nil {
				atomic.AddInt64(counter, int64(n))
			}
		}
		_, errCopy := io.Copy(&countingWriter{Writer: w, counter: counter}, src)
		if cerr := closer.Close(); errCopy == nil {
			errCopy = cerr
		}
		return errCopy
	}

	w, closer, err := compressor(dst, compression)
	if err != nil {
		log.Printf("compression %s unavailable, fallback passthrough: %v", compression, err)
		_, errCopy := io.Copy(&countingWriter{Writer: dst, counter: counter}, src)
		return errCopy
	}
	_, err = io.Copy(&countingWriter{Writer: w, counter: counter}, src)
	if cerr := closer.Close(); err == nil {
		err = cerr
	}
	if isClosedPipeErr(err) {
		return io.EOF
	}
	return err
}

func decompressStream(dst net.Conn, src net.Conn, compression string, minBytes int, counter *int64) error {
	log.Printf("[decompress] alg=%s src=%s dst=%s", compression, safeAddr(src), safeAddr(dst))
	br := bufio.NewReader(src)
	peek, err := br.Peek(2)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return err
	}
	if !isCompressedMagic(peek, compression) {
		n, errCopy := io.Copy(&countingWriter{Writer: dst, counter: counter}, br)
		log.Printf("[decompress passthrough] bytes=%d err=%v", n, errCopy)
		return errCopy
	}
	r, closer, derr := decompressor(br, compression)
	if derr != nil {
		// 解压器初始化失败，尝试透传
		log.Printf("[decompress] init failed, passthrough err=%v", derr)
		n, errCopy := io.Copy(&countingWriter{Writer: dst, counter: counter}, br)
		log.Printf("[decompress passthrough] bytes=%d err=%v", n, errCopy)
		return errCopy
	}
	n, errCopy := io.Copy(&countingWriter{Writer: dst, counter: counter}, r)
	if cerr := closer.Close(); errCopy == nil {
		errCopy = cerr
	}
	if isClosedPipeErr(errCopy) {
		return io.EOF
	}
	if errCopy == io.ErrUnexpectedEOF {
		// 上游提前关闭视为正常结束，避免噪声
		log.Printf("[decompress done] bytes=%d err=unexpected EOF (treated as close)", n)
		return nil
	}
	log.Printf("[decompress done] bytes=%d err=%v", n, errCopy)
	return errCopy
}

type closer interface {
	Close() error
}

// gzipFlushingWriter 在每次 Write 后调用 Flush，避免小包长时间停留在缓冲中。
type gzipFlushingWriter struct {
	zw *gzip.Writer
}

func (g *gzipFlushingWriter) Write(p []byte) (int, error) {
	n, err := g.zw.Write(p)
	// Flush 即便返回错误也要优先返回原始错误
	_ = g.zw.Flush()
	return n, err
}

func compressor(dst io.Writer, alg string) (io.Writer, closer, error) {
	switch alg {
	case "gzip":
		zw := gzip.NewWriter(dst)
		fw := &gzipFlushingWriter{zw: zw}
		return fw, zw, nil
	default:
		return nil, nil, fmt.Errorf("unknown compressor %s", alg)
	}
}

func decompressor(src io.Reader, alg string) (io.Reader, closer, error) {
	switch alg {
	case "gzip":
		r, err := gzip.NewReader(src)
		if err != nil {
			return nil, nil, err
		}
		return r, r, nil
	default:
		return nil, nil, fmt.Errorf("unknown decompressor %s", alg)
	}
}

func isCompressedMagic(peek []byte, alg string) bool {
	if len(peek) < 2 {
		return false
	}
	switch alg {
	case "gzip":
		return peek[0] == 0x1f && peek[1] == 0x8b
	default:
		return false
	}
}

func isCanceledErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return true
	}
	if strings.Contains(err.Error(), "context canceled") {
		return true
	}
	return false
}

func isConnBroken(err error) bool {
	if err == nil {
		return false
	}
	// EOF/ErrClosed 多为正常关闭，不视为致命
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "reset by peer") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "use of closed network connection") {
		return true
	}
	return false
}

func isCipherErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "cipher") || strings.Contains(msg, "invalid frame len") || strings.Contains(msg, "nonce") || strings.Contains(msg, "message authentication failed")
}

// === Encryption helpers ===

// selectPolicy 根据当前时间选择一条加密策略。
func selectPolicy(pols []EncryptionPolicy) *EncryptionPolicy {
	if len(pols) == 0 {
		return nil
	}
	idx := int(time.Now().Unix()) % len(pols)
	return &pols[idx]
}

func findPolicy(pols []EncryptionPolicy, id int) *EncryptionPolicy {
	for i := range pols {
		if pols[i].ID == id {
			return &pols[i]
		}
	}
	return nil
}

func decodeKey(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty key")
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return []byte(s), nil
}

func newAEAD(method string, key []byte) (cipher.AEAD, error) {
	switch strings.ToLower(method) {
	case "aes-128-gcm", "aes-256-gcm", "aes-gcm":
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return nil, fmt.Errorf("aes-gcm key length must be 16/24/32, got %d", len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case "chacha20-poly1305", "chacha20":
		if len(key) != chacha20poly1305.KeySize {
			return nil, fmt.Errorf("chacha20-poly1305 key must be %d bytes", chacha20poly1305.KeySize)
		}
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unknown method %s", method)
	}
}

// secureConn 在 net.Conn 上做 AEAD 分帧加解密。
type secureConn struct {
	conn      net.Conn
	aead      cipher.AEAD
	readBuf   []byte
	nonceSize int
}

func wrapSecureConn(c net.Conn, pol *EncryptionPolicy) (net.Conn, error) {
	if pol == nil || !pol.Enable {
		return c, nil
	}
	key, err := decodeKey(pol.Key)
	if err != nil {
		return nil, err
	}
	a, err := newAEAD(pol.Method, key)
	if err != nil {
		return nil, err
	}
	return &secureConn{conn: c, aead: a, nonceSize: a.NonceSize()}, nil
}

func (s *secureConn) Read(p []byte) (int, error) {
	if len(s.readBuf) == 0 {
		var lenBuf [4]byte
		if _, err := io.ReadFull(s.conn, lenBuf[:]); err != nil {
			return 0, err
		}
		frameLen := binary.BigEndian.Uint32(lenBuf[:])
		if frameLen == 0 || frameLen > 4<<20 {
			err := fmt.Errorf("invalid frame len %d", frameLen)
			_ = s.conn.Close()
			return 0, err
		}
		frame := make([]byte, frameLen)
		if _, err := io.ReadFull(s.conn, frame); err != nil {
			return 0, err
		}
		if len(frame) < s.nonceSize {
			return 0, fmt.Errorf("frame too short")
		}
		nonce := frame[:s.nonceSize]
		ct := frame[s.nonceSize:]
		pt, err := s.aead.Open(nil, nonce, ct, nil)
		if err != nil {
			_ = s.conn.Close()
			return 0, err
		}
		s.readBuf = pt
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *secureConn) Write(p []byte) (int, error) {
	nonce := make([]byte, s.nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	ct := s.aead.Seal(nil, nonce, p, nil)
	var lenBuf [4]byte
	total := len(nonce) + len(ct)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(total))
	if _, err := s.conn.Write(lenBuf[:]); err != nil {
		return 0, err
	}
	if _, err := s.conn.Write(nonce); err != nil {
		return 0, err
	}
	if _, err := s.conn.Write(ct); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *secureConn) Close() error                       { return s.conn.Close() }
func (s *secureConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *secureConn) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *secureConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *secureConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *secureConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

type countingWriter struct {
	Writer  io.Writer
	counter *int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	if w.counter != nil {
		atomic.AddInt64(w.counter, int64(len(p)))
	}
	return w.Writer.Write(p)
}

type ManualRoute struct {
	Name       string
	Priority   int
	Path       []NodeID
	Remote     string
	ReturnPath []NodeID
}

// Node wires entries, probing, routing, and transport.
type Node struct {
	ID                 NodeID
	Entries            []EntryPort
	Router             *Router
	Prober             Prober
	Transport          Transport
	Peers              []NodeID
	PollPeriod         time.Duration
	Metrics            *Metrics
	MaxReroute         int
	udpTTL             time.Duration
	ControllerURL      string
	TopologyPull       time.Duration
	RoutePull          time.Duration
	TokenPath          string
	Compression        string
	CompressionMin     int
	TransportMode      string
	HTTPProbeURL       string
	CertPath           string
	KeyPath            string
	AuthKey            []byte
	DebugLog           bool
	EncPolicies        []EncryptionPolicy
	lastMetrics        map[NodeID]LinkMetrics
	metricsMu          sync.Mutex
	routePlans         map[NodeID][]ManualRoute
	routeMu            sync.RWMutex
	TLSConfig          *tls.Config
	ServerName         string
	PeerEndpoints      map[NodeID]string
	tokenOnce          sync.Once
	tokenValue         string
	wsMu               sync.Mutex
	wsConn             *wscompat.Conn
	maxMuxStreams      int
	muxMaxAge          time.Duration
	muxMaxIdle         time.Duration
	memLimit           string
	preconnectPeers    []NodeID
	preconnectInterval time.Duration
	updateMu           sync.Mutex
	updating           bool
}

func (n *Node) Start(ctx context.Context) error {
	if n.Transport == nil || n.Router == nil || n.Prober == nil {
		return errors.New("node missing Transport/Router/Prober")
	}
	if n.PollPeriod == 0 {
		n.PollPeriod = 3 * time.Second
	}
	if n.ControllerURL != "" {
		if tok := n.loadToken(); tok == "" {
			return fmt.Errorf("controller url set but token missing; please write token to %s or set NODE_TOKEN", n.TokenPath)
		}
	}

	go n.pollMetrics(ctx)
	go n.controllerWSLoop(ctx)
	log.Printf("[topology] controller url: %s", n.ControllerURL)
	if n.ControllerURL != "" {
		go n.pushAndPullLoop(ctx)
		go n.pullRoutesLoop(ctx)
		go n.fetchCertLoop(ctx)
	}
	go n.probeRoutesLoop(ctx)
	go func() {
		if err := n.Transport.Serve(ctx); err != nil {
			log.Printf("transport server stopped: %v", err)
		}
	}()
	if ws, ok := n.Transport.(*WSSTransport); ok && len(n.preconnectPeers) > 0 {
		ws.StartPreconnect(ctx, n.preconnectPeers, n.preconnectInterval)
	}
	for _, ep := range n.Entries {
		ep := ep
		switch ep.Proto {
		case ProtocolTCP:
			go n.serveTCP(ctx, ep)
		case ProtocolUDP:
			go n.serveUDP(ctx, ep)
		case Protocol("both"):
			go n.serveTCP(ctx, EntryPort{ListenAddr: ep.ListenAddr, Proto: ProtocolTCP, ExitNode: ep.ExitNode, RemoteAddr: ep.RemoteAddr})
			go n.serveUDP(ctx, EntryPort{ListenAddr: ep.ListenAddr, Proto: ProtocolUDP, ExitNode: ep.ExitNode, RemoteAddr: ep.RemoteAddr})
		default:
			log.Printf("unknown protocol %q on %s", ep.Proto, ep.ListenAddr)
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func (n *Node) pollMetrics(ctx context.Context) {
	ticker := time.NewTicker(n.PollPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, peer := range n.Peers {
				metrics, err := n.Prober.Probe(ctx, n.ID, peer)
				if err != nil {
					log.Printf("probe %s -> %s failed: %v", n.ID, peer, err)
					continue
				}
				n.Router.Topology.Set(n.ID, peer, metrics)
				n.recordMetric(peer, metrics)
			}
		}
	}
}

func (n *Node) matchingManualRoutes(exit NodeID, remote string) []ManualRoute {
	n.routeMu.RLock()
	routes := n.routePlans[exit]
	n.routeMu.RUnlock()
	if remote == "" || len(routes) == 0 {
		return routes
	}
	filtered := make([]ManualRoute, 0, len(routes))
	for _, r := range routes {
		if r.Remote == "" || r.Remote == remote {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

type routeSelection struct {
	Path       []NodeID
	ReturnPath []NodeID
	Name       string
}

func (n *Node) routeForAttempt(exit NodeID, remote string, attempt int) (routeSelection, error) {
	routes := n.matchingManualRoutes(exit, remote)
	if attempt < len(routes) {
		r := routes[attempt]
		if len(r.Path) < 2 {
			return routeSelection{}, fmt.Errorf("manual route %q too short", r.Name)
		}
		if r.Path[0] != n.ID {
			return routeSelection{}, fmt.Errorf("manual route %q must start from %s", r.Name, n.ID)
		}
		if r.Path[len(r.Path)-1] != exit {
			return routeSelection{}, fmt.Errorf("manual route %q must end at exit %s", r.Name, exit)
		}
		log.Printf("[route] using manual route %q (priority=%d) for %s -> %s remote=%s: %v", r.Name, r.Priority, n.ID, exit, remote, r.Path)
		sel := routeSelection{Path: r.Path, ReturnPath: r.ReturnPath, Name: r.Name}
		if len(sel.ReturnPath) > 0 {
			if len(sel.ReturnPath) < 2 || sel.ReturnPath[0] != exit || sel.ReturnPath[len(sel.ReturnPath)-1] != n.ID {
				log.Printf("[route] ignore return_path for %q: expect %s -> %s, got %v", r.Name, exit, n.ID, sel.ReturnPath)
				sel.ReturnPath = nil
			}
		}
		return sel, nil
	}
	path, err := n.Router.BestPath(n.ID, exit)
	if err != nil {
		return routeSelection{}, err
	}
	return routeSelection{Path: path, Name: "auto"}, nil
}

func (n *Node) routeAttempts(exit NodeID, remote string) int {
	attempts := n.MaxReroute
	routes := n.matchingManualRoutes(exit, remote)
	if attempts < len(routes)+1 {
		attempts = len(routes) + 1
	}
	if attempts < 1 {
		attempts = 1
	}
	return attempts
}

func (n *Node) probeRoutesLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	n.runRouteProbes(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.runRouteProbes(ctx)
		}
	}
}

func (n *Node) runRouteProbes(ctx context.Context) {
	ws, ok := n.Transport.(*WSSTransport)
	if !ok {
		return
	}
	n.routeMu.RLock()
	plans := make([]ManualRoute, 0)
	for _, rs := range n.routePlans {
		plans = append(plans, rs...)
	}
	n.routeMu.RUnlock()
	for _, r := range plans {
		if len(r.Path) < 2 || r.Path[0] != n.ID {
			continue
		}
		const probeTimeout = 20 * time.Second
		dur, err := ws.ProbeHTTP(ctx, r.Path, n.HTTPProbeURL, probeTimeout)
		if dur > probeTimeout {
			dur = probeTimeout
		}
		success := err == nil
		if err != nil {
			log.Printf("[probe route %s] failed: %v", r.Name, err)
		}
		_ = n.reportProbe(ctx, r, dur, success, err)
	}
}

func (n *Node) reportProbe(ctx context.Context, r ManualRoute, dur time.Duration, success bool, err error) error {
	if n.ControllerURL == "" {
		return nil
	}
	reqBody := struct {
		Route   string   `json:"route"`
		Path    []string `json:"path"`
		RTTMs   int64    `json:"rtt_ms"`
		Success bool     `json:"success"`
		Error   string   `json:"error"`
	}{
		Route:   r.Name,
		Path:    nodeIDsToStrings(r.Path),
		RTTMs:   dur.Milliseconds(),
		Success: success,
	}
	if err != nil {
		reqBody.Error = err.Error()
	}
	data, _ := json.Marshal(reqBody)
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/probe/e2e"
	req, _ := http.NewRequestWithContext(ctxReq, "POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if len(n.AuthKey) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(n.AuthKey))
	}
	if tok := n.loadToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, errDo := http.DefaultClient.Do(req)
	if errDo != nil {
		return errDo
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		log.Printf("[probe route %s] report non-2xx: %s body=%s", r.Name, resp.Status, string(body))
	}
	return nil
}

func nodeIDsToStrings(ids []NodeID) []string {
	out := make([]string, len(ids))
	for i, v := range ids {
		out[i] = string(v)
	}
	return out
}

func (n *Node) serveTCP(ctx context.Context, ep EntryPort) {
	ln, err := net.Listen("tcp", ep.ListenAddr)
	if err != nil {
		log.Printf("tcp listen %s failed: %v", ep.ListenAddr, err)
		return
	}
	log.Printf("tcp entry listening on %s -> exit %s (%s)", ep.ListenAddr, ep.ExitNode, ep.RemoteAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept failed on %s: %v", ep.ListenAddr, err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			if n.Metrics != nil {
				n.Metrics.IncTCP()
			}
			routeSel, err := n.routeForAttempt(ep.ExitNode, ep.RemoteAddr, 0)
			if err != nil {
				log.Printf("tcp forwarding failed: %v", err)
				return
			}
			if err := n.Transport.Forward(ctx, n.ID, routeSel.Path, routeSel.ReturnPath, ep.Proto, c, ep.RemoteAddr, routeSel.Name); err != nil {
				log.Printf("tcp forwarding failed: %v", err)
			}
		}(conn)
	}
}

func (n *Node) serveUDP(ctx context.Context, ep EntryPort) {
	transport, ok := n.Transport.(*WSSTransport)
	if !ok {
		log.Printf("udp entry %s requires WSSTransport", ep.ListenAddr)
		return
	}
	pc, err := net.ListenPacket("udp", ep.ListenAddr)
	if err != nil {
		log.Printf("udp listen %s failed: %v", ep.ListenAddr, err)
		return
	}
	log.Printf("udp entry listening on %s -> exit %s (%s)", ep.ListenAddr, ep.ExitNode, ep.RemoteAddr)
	sessions := make(map[string]*udpSession)
	var mu sync.Mutex
	ttl := n.udpTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	buf := make([]byte, 64*1024)
	for {
		nBytes, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("udp read failed: %v", err)
			continue
		}
		data := append([]byte(nil), buf[:nBytes]...)
		go func(pkt []byte, clientAddr net.Addr) {
			key := clientAddr.String()
			mu.Lock()
			sess := sessions[key]
			if sess == nil {
				attempts := n.routeAttempts(ep.ExitNode, ep.RemoteAddr)
				var path []NodeID
				var sessionID string
				var wsConn *wscompat.Conn
				var err error
				for try := 0; try < attempts; try++ {
					routeSel, selErr := n.routeForAttempt(ep.ExitNode, ep.RemoteAddr, try)
					path = routeSel.Path
					err = selErr
					if err != nil {
						log.Printf("udp route selection failed (attempt %d/%d): %v", try+1, attempts, err)
						continue
					}
					wsConn, sessionID, err = transport.OpenUDPSession(ctx, path, ep.RemoteAddr, clientAddr.String())
					if err == nil {
						break
					}
					log.Printf("open udp session failed via route %d/%d: %v", try+1, attempts, err)
				}
				if err != nil {
					mu.Unlock()
					log.Printf("open udp session failed after %d attempts: %v", attempts, err)
					return
				}
				if n.Metrics != nil {
					n.Metrics.IncUDP()
				}
				sessCtx, cancel := context.WithCancel(ctx)
				sess = &udpSession{conn: wsConn, cancel: cancel, clientAddr: clientAddr, sessionID: sessionID}
				sessions[key] = sess
				go n.udpDownstreamLoop(sessCtx, pc, sess, transport.AuthKey, n.Metrics, func() {
					mu.Lock()
					delete(sessions, key)
					mu.Unlock()
				})
			}
			mu.Unlock()
			if sess == nil {
				return
			}
			if err := writeSignedEnvelope(ctx, sess.conn, ControlEnvelope{
				Type:     "udp",
				Session:  sess.sessionID,
				Datagram: &UDPDatagram{Src: clientAddr.String(), Payload: pkt},
			}, transport.AuthKey); err != nil {
				log.Printf("send udp datagram failed: %v", err)
				sess.cancel()
				mu.Lock()
				delete(sessions, key)
				mu.Unlock()
				return
			}
			if n.Metrics != nil {
				n.Metrics.AddUp(int64(len(pkt)))
			}
			// 更新最后活跃时间
			sess.touch()
		}(data, addr)

		// 定期清理过期 UDP 会话
		mu.Lock()
		now := time.Now()
		for k, s := range sessions {
			last := time.UnixMilli(s.lastActive.Load())
			if now.Sub(last) > ttl {
				s.cancel()
				delete(sessions, k)
			}
		}
		mu.Unlock()
	}
}

type udpSession struct {
	conn       *wscompat.Conn
	cancel     context.CancelFunc
	clientAddr net.Addr
	sessionID  string
	lastActive atomic.Int64
}

func (n *Node) udpDownstreamLoop(ctx context.Context, pc net.PacketConn, sess *udpSession, key []byte, metrics *Metrics, cleanup func()) {
	defer func() {
		if sess.conn != nil {
			sess.conn.Close()
		}
		cleanup()
	}()
	for {
		env, err := readVerifiedEnvelope(ctx, sess.conn, key)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				log.Printf("[session=%s] udp downstream err: %v", sess.sessionID, err)
			}
			return
		}
		if env.Type != "udp" || env.Datagram == nil {
			log.Printf("[session=%s] unexpected msg type %s", sess.sessionID, env.Type)
			continue
		}
		if _, err := pc.WriteTo(env.Datagram.Payload, sess.clientAddr); err != nil {
			log.Printf("[session=%s] udp write back failed: %v", sess.sessionID, err)
			return
		}
		if metrics != nil {
			metrics.AddDown(int64(len(env.Datagram.Payload)))
		}
		sess.touch()
	}
}

func (s *udpSession) touch() {
	s.lastActive.Store(time.Now().UnixMilli())
}

type entryConfig struct {
	Listen string `json:"listen"`
	Proto  string `json:"proto"`
	Exit   string `json:"exit"`
	Remote string `json:"remote"`
}

type routePlanConfig struct {
	Name       string   `json:"name"`
	Exit       string   `json:"exit"`
	Remote     string   `json:"remote"`
	Priority   int      `json:"priority"`
	Path       []string `json:"path"`
	ReturnPath []string `json:"return_path"`
}

type nodeConfig struct {
	ID                 string             `json:"id"`
	WSListen           string             `json:"ws_listen"`
	QUICListen         string             `json:"quic_listen"`
	WSSListen          string             `json:"wss_listen"`
	Peers              map[string]string  `json:"peers"` // node -> ws(s)://host:port/mesh
	Entries            []entryConfig      `json:"entries"`
	Routes             []routePlanConfig  `json:"routes"`
	PollPeriod         string             `json:"poll_period"`
	InsecureSkipTLS    bool               `json:"insecure_skip_tls"`
	QUICServerName     string             `json:"quic_server_name"`
	MaxIdle            string             `json:"quic_max_idle"`
	MaxDatagramSize    int                `json:"quic_max_datagram_size"`
	AuthKey            string             `json:"auth_key"`
	MetricsListen      string             `json:"metrics_listen"`
	MTLSCert           string             `json:"mtls_cert"`
	MTLSKey            string             `json:"mtls_key"`
	MTLSCA             string             `json:"mtls_ca"`
	ControllerURL      string             `json:"controller_url"`
	TopologyPull       string             `json:"topology_pull"`
	RoutePull          string             `json:"route_pull"`
	Compression        string             `json:"compression"`
	CompressionMin     int                `json:"compression_min_bytes"`
	Transport          string             `json:"transport"`
	TokenPath          string             `json:"token_path"`
	DebugLog           bool               `json:"debug_log"`
	HTTPProbeURL       string             `json:"http_probe_url"`
	EncPolicies        []EncryptionPolicy `json:"encryption_policies"`
	MemLimit           string             `json:"mem_limit"`
	PreconnectPeers    []string           `json:"preconnect_peers"`
	PreconnectInterval string             `json:"preconnect_interval"`
	ReturnAckTimeout   string             `json:"return_ack_timeout"`
	MaxMuxStreams      int                `json:"max_mux_streams"`
}

func loadConfig(path string) (nodeConfig, error) {
	var cfg nodeConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.ID == "" {
		return cfg, errors.New("id required")
	}
	if cfg.WSListen == "" && cfg.WSSListen == "" {
		return cfg, errors.New("at least one of ws_listen or wss_listen required")
	}
	if cfg.ControllerURL != "" {
		cfg.ControllerURL = strings.TrimRight(cfg.ControllerURL, "/")
	}
	if cfg.Transport == "" {
		cfg.Transport = "quic"
	}
	if strings.TrimSpace(cfg.HTTPProbeURL) == "" {
		cfg.HTTPProbeURL = "https://www.google.com/generate_204"
	}
	// 默认证书/密钥路径并按平台重写
	if cfg.MTLSCert == "" {
		cfg.MTLSCert = "/opt/arouter/certs/arouter.crt"
	}
	if cfg.MTLSKey == "" {
		cfg.MTLSKey = "/opt/arouter/certs/arouter.key"
	}
	if cfg.MTLSCA == "" {
		cfg.MTLSCA = "/opt/arouter/certs/arouter.crt"
	}
	cfg.MTLSCert = platformPath(cfg.MTLSCert)
	cfg.MTLSKey = platformPath(cfg.MTLSKey)
	cfg.MTLSCA = platformPath(cfg.MTLSCA)
	if cfg.TokenPath != "" {
		cfg.TokenPath = platformPath(cfg.TokenPath)
	}
	return cfg, nil
}

func (n *nodeConfig) fetchCert() {
	url := strings.TrimRight(n.ControllerURL, "/") + "/api/certs"
	log.Printf("[config] fetching cert from %s", url)
	token, err := os.ReadFile(n.TokenPath)
	if err != nil {
		log.Fatalf("[config] failed to read token: %v", err)
	}
	tok := strings.TrimSpace(string(token))
	fmt.Println("Authorization token", tok)
	header := &http.Header{}
	header.Set("Authorization", "Bearer "+tok)
	resp := http2.GETWithHeader(url, nil, header)
	if resp.Error() != nil {
		log.Printf("[config] fetch cert failed: %v", resp.Error())
		return
	}
	if resp.StatusCode >= 300 {
		log.Printf("[config] fetch cert non-2xx: %s body=%s", resp.StatusCode, string(resp.Byte()))
		return
	}
	var payload certPayload

	if err := resp.Resp(&payload); err != nil {
		log.Printf("[config] decode cert payload failed: %v", err)
		return
	}
	if payload.Cert == "" || payload.Key == "" {
		log.Printf("[config] cert payload empty")
		return
	}
	ensureDir := func(path string) error {
		dir := filepath.Dir(path)
		if dir == "" || dir == "." {
			return nil
		}
		return os.MkdirAll(dir, 0700)
	}
	if err := ensureDir(n.MTLSCert); err != nil {
		log.Printf("[config] ensure cert dir failed: %v", err)
		return
	}
	if err := ensureDir(n.MTLSKey); err != nil {
		log.Printf("[config] ensure key dir failed: %v", err)
		return
	}
	if err := os.WriteFile(n.MTLSCert, []byte(payload.Cert), 0600); err != nil {
		log.Printf("[config] write cert failed: %v", err)
		return
	}
	if err := os.WriteFile(n.MTLSKey, []byte(payload.Key), 0600); err != nil {
		log.Printf("[config] write key failed: %v", err)
		return
	}
	log.Printf("[config] updated cert/key from controller -> cert=%s key=%s", n.MTLSCert, n.MTLSKey)
}
func parseDurationOrDefault(raw string, def time.Duration) time.Duration {
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return def
	}
	return d
}

func applyMemLimit(raw string) {
	// 优先使用配置，其次环境变量，最后默认值
	limitStr := strings.TrimSpace(raw)
	if limitStr == "" {
		if env := os.Getenv("GOMEMLIMIT"); env != "" {
			limitStr = env
		} else {
			limitStr = defaultMemLimit
		}
	}
	if limitStr == "" {
		return
	}
	limitBytes := parseMemSize(limitStr)
	if limitBytes > 0 {
		debug.SetMemoryLimit(limitBytes)
		os.Setenv("GOMEMLIMIT", fmt.Sprintf("%d", limitBytes))
		log.Printf("[mem] apply mem limit=%s (%d bytes)", limitStr, limitBytes)
	}
}

func parseMemSize(s string) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "gib"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "gib")
	case strings.HasSuffix(s, "gb"):
		mult = 1_000_000_000
		s = strings.TrimSuffix(s, "gb")
	case strings.HasSuffix(s, "mib"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "mib")
	case strings.HasSuffix(s, "mb"):
		mult = 1_000_000
		s = strings.TrimSuffix(s, "mb")
	case strings.HasSuffix(s, "kib"):
		mult = 1 << 10
		s = strings.TrimSuffix(s, "kib")
	case strings.HasSuffix(s, "kb"):
		mult = 1_000
		s = strings.TrimSuffix(s, "kb")
	}
	val, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || val <= 0 {
		return 0
	}
	return val * mult
}

func buildManualRouteMap(self NodeID, routes []routePlanConfig) map[NodeID][]ManualRoute {
	plans := make(map[NodeID][]ManualRoute)
	for _, r := range routes {
		if len(r.Path) == 0 {
			continue
		}
		path := make([]NodeID, 0, len(r.Path))
		for _, p := range r.Path {
			path = append(path, NodeID(p))
		}
		returnPath := make([]NodeID, 0, len(r.ReturnPath))
		for _, p := range r.ReturnPath {
			returnPath = append(returnPath, NodeID(p))
		}
		if path[0] != self {
			path = append([]NodeID{self}, path...)
		}
		exit := path[len(path)-1]
		plans[exit] = append(plans[exit], ManualRoute{
			Name:       r.Name,
			Priority:   r.Priority,
			Path:       path,
			Remote:     r.Remote,
			ReturnPath: returnPath,
		})
	}
	for exit := range plans {
		sort.Slice(plans[exit], func(i, j int) bool {
			if plans[exit][i].Priority == plans[exit][j].Priority {
				return plans[exit][i].Name < plans[exit][j].Name
			}
			return plans[exit][i].Priority < plans[exit][j].Priority
		})
	}
	return plans
}

func (n *Node) updateManualRoutes(plans map[NodeID][]ManualRoute) {
	n.routeMu.Lock()
	n.routePlans = plans
	n.routeMu.Unlock()
}

func platformPath(p string) string {
	// expand ~ and ${HOME}
	if strings.HasPrefix(p, "~") {
		home, _ := os.UserHomeDir()
		if home != "" {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	if strings.HasPrefix(p, "${HOME}") {
		home, _ := os.UserHomeDir()
		if home != "" {
			p = filepath.Join(home, strings.TrimPrefix(p, "${HOME}"))
		}
	}
	if runtime.GOOS == "darwin" && strings.HasPrefix(p, "/opt/arouter") {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			return filepath.Join(home, ".arouter"+strings.TrimPrefix(p, "/opt/arouter"))
		}
	}
	return p
}

// loadToken 读取节点 token，优先环境变量 NODE_TOKEN，其次文件 TokenPath/.token。
func (n *Node) loadToken() string {
	n.tokenOnce.Do(func() {
		if tok := os.Getenv("NODE_TOKEN"); tok != "" {
			n.tokenValue = tok
			return
		}
		path := n.TokenPath
		if strings.TrimSpace(path) == "" {
			path = "/opt/arouter/.token"
		}
		data, err := os.ReadFile(path)
		if err == nil {
			n.tokenValue = strings.TrimSpace(string(data))
		} else {
			log.Printf("token file read failed (%s): %v", path, err)
		}
	})
	return n.tokenValue
}

func buildTLSConfig(cfg nodeConfig) (*tls.Config, error) {
	if cfg.MTLSCert == "" && cfg.MTLSKey == "" && cfg.MTLSCA == "" {
		return &tls.Config{InsecureSkipVerify: cfg.InsecureSkipTLS}, nil
	}
	if cfg.MTLSCert == "" || cfg.MTLSKey == "" {
		return nil, fmt.Errorf("mtls_cert and mtls_key required when mtls_ca provided")
	}
	certPath := platformPath(cfg.MTLSCert)
	keyPath := platformPath(cfg.MTLSKey)
	caPath := platformPath(cfg.MTLSCA)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: cfg.InsecureSkipTLS,
	}
	if cfg.MTLSCA != "" {
		caData, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to load mtls_ca")
		}
		tlsConf.ClientCAs = pool
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConf.RootCAs = pool
	} else {
		// 无 CA 时，将自签名证书本身加入 RootCAs 以便信任自签。
		pool := x509.NewCertPool()
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(certPEM) {
			return nil, fmt.Errorf("failed to append self-signed cert to root pool")
		}
		tlsConf.RootCAs = pool
		// 提取叶子用于 ClientAuth 验证。
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("invalid pem in self-signed cert")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			tlsConf.ClientCAs = pool
			tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConf.ServerName = cert.Subject.CommonName
		}
	}
	return tlsConf, nil
}

func cloneTLSWithServerName(base *tls.Config, serverName string) *tls.Config {
	var tlsConf *tls.Config
	if base != nil {
		tlsConf = base.Clone()
	} else {
		tlsConf = &tls.Config{}
	}
	tlsConf.InsecureSkipVerify = true
	tlsConf.ServerName = strings.TrimSpace(serverName)
	// 强制 HTTP/1.1，避免 ALPN 协商到 h2 导致 WS 握手失败
	tlsConf.NextProtos = []string{"http/1.1"}
	return tlsConf
}

func main() {
	configPath := flag.String("config", "config.json", "path to JSON config")
	tokenPath := flag.String("token", "/opt/arouter/.token", "path to node token file")
	flag.Parse()
	configPathValue = *configPath
	tokenPathValue = *tokenPath

	buildVersion = canonicalVersion(buildVersion)
	log.Printf("arouter agent version %s", buildVersion)
	log.SetOutput(logFilter)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGUSR1)

	var lastCfgDigest string

	for {
		cfg, err := loadConfig(*configPath)
		if err != nil {
			log.Fatalf("load config failed: %v", err)
		}
		applyMemLimit(cfg.MemLimit)
		debugLogEnabled.Store(cfg.DebugLog)
		// 更新过滤器开关
		logFilter.debug = &debugLogEnabled
		cfgDigest := configDigest(cfg)
		if cfgDigest == lastCfgDigest {
			log.Printf("config unchanged, skip reload")
			select {
			case <-sigCh:
				continue
			case <-time.After(5 * time.Second):
				continue
			}
		}
		lastCfgDigest = cfgDigest
		metrics := &Metrics{}
		var metricsSrv *http.Server
		if cfg.MetricsListen != "" {
			metricsSrv = metrics.Serve(cfg.MetricsListen)
			log.Printf("metrics listening on %s", cfg.MetricsListen)
		}
		topology := NewTopology()
		metrics.Topology = topology
		metrics.Self = NodeID(cfg.ID)
		router := &Router{
			Topology:      topology,
			FailThreshold: 3,
			FailTimeout:   30 * time.Second,
			FailPenalty:   250 * time.Millisecond,
		}

		{
			//构建之前要先拉取certs
			_, errStat := os.Stat(cfg.MTLSCert)
			if errStat != nil {
				fmt.Println("不存在cert文件，尝试从controller拉取")
				cfg.fetchCert()
				fmt.Println("拉取cert文件完成")
			}
		}

		fmt.Println("构建节点...")
		tlsConf, err := buildTLSConfig(cfg)
		if err != nil {
			log.Fatalf("build tls config failed: %v", err)
		}
		authKey := []byte(cfg.AuthKey)
		endpoints := make(map[NodeID]string, len(cfg.Peers))
		peerIDs := make([]NodeID, 0, len(cfg.Peers))
		defaultPort := func(listen string, fallback string) string {
			l := strings.TrimSpace(listen)
			if strings.HasPrefix(l, ":") {
				return strings.TrimPrefix(l, ":")
			}
			if strings.Contains(l, ":") {
				parts := strings.Split(l, ":")
				return parts[len(parts)-1]
			}
			if l != "" {
				return l
			}
			return fallback
		}
		mode := strings.ToLower(cfg.Transport)
		if mode == "" {
			mode = "quic"
		}
		wsPort := defaultPort(cfg.WSListen, "18080")
		wssPort := defaultPort(cfg.WSSListen, wsPort)
		quicPort := defaultPort(cfg.QUICListen, wssPort)
		port := quicPort
		if mode == "wss" {
			port = wssPort
		} else if mode == "ws" {
			port = wsPort
		}
		for id, addr := range cfg.Peers {
			raw := strings.TrimSpace(addr)
			if strings.Contains(raw, "://") {
				endpoints[NodeID(id)] = normalizePeerEndpoint(raw, mode)
			} else {
				host := raw
				peerPort := port
				if strings.Contains(host, ":") {
					if h, p, err := net.SplitHostPort(host); err == nil {
						host = h
						peerPort = p // 显式端口优先
					}
				}
				host = net.JoinHostPort(host, peerPort)
				endpoints[NodeID(id)] = normalizePeerEndpoint(host, mode)
			}
			peerIDs = append(peerIDs, NodeID(id))
		}

		entries := make([]EntryPort, 0, len(cfg.Entries))
		for _, e := range cfg.Entries {
			entries = append(entries, EntryPort{
				ListenAddr: ensureListenAddr(e.Listen),
				Proto:      Protocol(e.Proto),
				ExitNode:   NodeID(e.Exit),
				RemoteAddr: e.Remote,
			})
		}

		udpTTL := 60 * time.Second
		routePull := parseDurationOrDefault(cfg.RoutePull, 0)
		compression := strings.ToLower(cfg.Compression)
		if compression == "" {
			compression = "gzip"
		}
		var transport Transport
		cfg.WSListen = ensureListenAddr(cfg.WSListen)
		cfg.WSSListen = ensureListenAddr(cfg.WSSListen)
		cfg.QUICListen = ensureListenAddr(cfg.QUICListen)
		cfg.MetricsListen = ensureListenAddr(cfg.MetricsListen)
		muxMaxAge := 10 * time.Minute
		muxMaxIdle := 2 * time.Minute
		muxPingInterval := 30 * time.Second
		muxPingTimeout := 5 * time.Second
		muxCleanup := 30 * time.Second
		muxRTTAlpha := 0.2
		linkLossAlpha := 0.2
		maxStreams := autoMaxMuxStreams()
		if cfg.MaxMuxStreams > 0 {
			maxStreams = cfg.MaxMuxStreams
		}
		muxDefaultQueue := 256 * maxStreams
		muxStreamQueue := 64 * maxStreams
		muxBlockOnBackpressure := true
		switch mode {
		case "quic":
			transport = &QUICTransport{
				Self:            NodeID(cfg.ID),
				ListenAddr:      defaultIfEmpty(cfg.QUICListen, cfg.WSListen),
				Endpoints:       endpoints,
				TLSConfig:       tlsConf,
				ServerName:      cfg.QUICServerName,
				MaxIdleTimeout:  parseDurationOrDefault(cfg.MaxIdle, 0),
				MaxDatagramSize: cfg.MaxDatagramSize,
				AuthKey:         authKey,
				Metrics:         metrics,
				Topology:        topology,
				Compression:     compression,
				CompressMin:     cfg.CompressionMin,
				LinkLossAlpha:   linkLossAlpha,
			}
		case "wss", "ws":
			transport = &WSSTransport{
				Self:                   NodeID(cfg.ID),
				ListenAddr:             cfg.WSListen,
				TLSListenAddr:          cfg.WSSListen,
				CertFile:               platformPath(defaultIfEmpty(cfg.MTLSCert, "/opt/arouter/certs/arouter.crt")),
				KeyFile:                platformPath(defaultIfEmpty(cfg.MTLSKey, "/opt/arouter/certs/arouter.key")),
				Endpoints:              endpoints,
				TLSConfig:              tlsConf,
				ServerName:             cfg.QUICServerName,
				AuthKey:                authKey,
				Metrics:                metrics,
				Topology:               topology,
				Compression:            compression,
				CompressMin:            cfg.CompressionMin,
				EncPolicies:            cfg.EncPolicies,
				maxStreams:             maxStreams,
				disablePool:            maxStreams <= 1,
				maxConnAge:             muxMaxAge,
				maxIdle:                muxMaxIdle,
				returnAckTimeout:       parseDurationOrDefault(cfg.ReturnAckTimeout, 10*time.Second),
				muxPingInterval:        muxPingInterval,
				muxPingTimeout:         muxPingTimeout,
				muxCleanupInterval:     muxCleanup,
				muxRTTAlpha:            muxRTTAlpha,
				linkLossAlpha:          linkLossAlpha,
				muxDefaultQueue:        muxDefaultQueue,
				muxStreamQueue:         muxStreamQueue,
				muxBlockOnBackpressure: muxBlockOnBackpressure,
			}
		default:
			log.Printf("unknown transport %s, fallback to ws", mode)
			transport = &WSSTransport{
				Self:                   NodeID(cfg.ID),
				ListenAddr:             cfg.WSListen,
				TLSListenAddr:          cfg.WSSListen,
				CertFile:               platformPath(defaultIfEmpty(cfg.MTLSCert, "/opt/arouter/certs/arouter.crt")),
				KeyFile:                platformPath(defaultIfEmpty(cfg.MTLSKey, "/opt/arouter/certs/arouter.key")),
				Endpoints:              endpoints,
				TLSConfig:              tlsConf,
				ServerName:             cfg.QUICServerName,
				AuthKey:                authKey,
				Metrics:                metrics,
				Topology:               topology,
				Compression:            compression,
				CompressMin:            cfg.CompressionMin,
				EncPolicies:            cfg.EncPolicies,
				maxStreams:             maxStreams,
				disablePool:            maxStreams <= 1,
				maxConnAge:             muxMaxAge,
				maxIdle:                muxMaxIdle,
				returnAckTimeout:       parseDurationOrDefault(cfg.ReturnAckTimeout, 10*time.Second),
				muxPingInterval:        muxPingInterval,
				muxPingTimeout:         muxPingTimeout,
				muxCleanupInterval:     muxCleanup,
				muxRTTAlpha:            muxRTTAlpha,
				linkLossAlpha:          linkLossAlpha,
				muxDefaultQueue:        muxDefaultQueue,
				muxStreamQueue:         muxStreamQueue,
				muxBlockOnBackpressure: muxBlockOnBackpressure,
			}
		}
		if ws, ok := transport.(*WSSTransport); ok {
			metrics.MuxPool = ws
		}
		prober := &WSProber{
			Endpoints:  endpoints,
			TLSConfig:  tlsConf,
			Transport:  mode,
			ServerName: cfg.QUICServerName,
		}

		routePlans := buildManualRouteMap(NodeID(cfg.ID), cfg.Routes)
		var preconnectPeers []NodeID
		for _, p := range cfg.PreconnectPeers {
			if strings.TrimSpace(p) != "" {
				preconnectPeers = append(preconnectPeers, NodeID(p))
			}
		}
		if len(preconnectPeers) == 0 {
			for peer := range endpoints {
				if peer != "" {
					preconnectPeers = append(preconnectPeers, peer)
				}
			}
		}
		preconnectInterval := parseDurationOrDefault(cfg.PreconnectInterval, 30*time.Second)

		node := &Node{
			ID:                 NodeID(cfg.ID),
			Entries:            entries,
			Router:             router,
			Prober:             prober,
			Transport:          transport,
			Peers:              peerIDs,
			PollPeriod:         parseDurationOrDefault(cfg.PollPeriod, 5*time.Second),
			Metrics:            metrics,
			MaxReroute:         1,
			udpTTL:             udpTTL,
			ControllerURL:      cfg.ControllerURL,
			TopologyPull:       parseDurationOrDefault(cfg.TopologyPull, 5*time.Minute),
			RoutePull:          routePull,
			Compression:        compression,
			CompressionMin:     cfg.CompressionMin,
			TransportMode:      mode,
			HTTPProbeURL:       cfg.HTTPProbeURL,
			CertPath:           platformPath(defaultIfEmpty(cfg.MTLSCert, "/opt/arouter/certs/arouter.crt")),
			KeyPath:            platformPath(defaultIfEmpty(cfg.MTLSKey, "/opt/arouter/certs/arouter.key")),
			AuthKey:            authKey,
			routePlans:         routePlans,
			TokenPath:          platformPath(defaultIfEmpty(*tokenPath, "/opt/arouter/.token")),
			DebugLog:           cfg.DebugLog,
			EncPolicies:        cfg.EncPolicies,
			maxMuxStreams:      maxStreams,
			muxMaxAge:          muxMaxAge,
			muxMaxIdle:         muxMaxIdle,
			memLimit:           cfg.MemLimit,
			preconnectPeers:    preconnectPeers,
			preconnectInterval: preconnectInterval,
			TLSConfig:          tlsConf,
			ServerName:         cfg.QUICServerName,
			PeerEndpoints:      endpoints,
		}
		if ws, ok := transport.(*WSSTransport); ok {
			ws.diagReport = node.reportDiag
		}

		ctx, cancel := context.WithCancel(context.Background())
		nodeDone := make(chan struct{})
		go func() {
			defer close(nodeDone)
			log.Printf("starting node %s", node.ID)
			if err := node.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("node stopped: %v", err)
			}
		}()
		if metricsSrv != nil {
			go func() {
				<-ctx.Done()
				shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
				defer c()
				metricsSrv.Shutdown(shutdownCtx)
			}()
		}

		select {
		case <-sigCh:
			log.Printf("received reload signal, reloading config")
			cancel()
			<-nodeDone
			continue
		case <-nodeDone:
			return
		}
	}
}

func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("sess-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func signEnvelope(env *ControlEnvelope, key []byte) error {
	sig := env.Signature
	env.Signature = ""
	origTS := env.Timestamp
	if origTS == 0 {
		env.Timestamp = time.Now().UnixMilli()
	}
	data, err := json.Marshal(env)
	if err != nil {
		env.Signature = sig
		env.Timestamp = origTS
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	env.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

func verifyEnvelope(env *ControlEnvelope, key []byte) error {
	expected := env.Signature
	env.Signature = ""
	if env.Timestamp == 0 {
		return fmt.Errorf("missing timestamp")
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	raw, err := hex.DecodeString(expected)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	if !hmac.Equal(raw, mac.Sum(nil)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
