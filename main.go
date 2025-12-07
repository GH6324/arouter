package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"crypto/x509"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

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

// Topology keeps weighted edges in-memory.
type Topology struct {
	mu    sync.RWMutex
	edges map[NodeID]map[NodeID]LinkMetrics
}

func NewTopology() *Topology {
	return &Topology{edges: make(map[NodeID]map[NodeID]LinkMetrics)}
}

func (t *Topology) Set(from, to NodeID, m LinkMetrics) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.edges[from] == nil {
		t.edges[from] = make(map[NodeID]LinkMetrics)
	}
	t.edges[from][to] = m
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

// Metrics 以原子计数记录流量与会话情况，暴露 /metrics 供采集。
type Metrics struct {
	tcpSessions int64
	udpSessions int64
	bytesUp     int64
	bytesDown   int64
}

func (m *Metrics) IncTCP() { atomic.AddInt64(&m.tcpSessions, 1) }
func (m *Metrics) IncUDP() { atomic.AddInt64(&m.udpSessions, 1) }
func (m *Metrics) AddUp(n int64) { atomic.AddInt64(&m.bytesUp, n) }
func (m *Metrics) AddDown(n int64) { atomic.AddInt64(&m.bytesDown, n) }

func (m *Metrics) Serve(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "tcp_sessions_total %d\n", atomic.LoadInt64(&m.tcpSessions))
		fmt.Fprintf(w, "udp_sessions_total %d\n", atomic.LoadInt64(&m.udpSessions))
		fmt.Fprintf(w, "bytes_up_total %d\n", atomic.LoadInt64(&m.bytesUp))
		fmt.Fprintf(w, "bytes_down_total %d\n", atomic.LoadInt64(&m.bytesDown))
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
	Topology *Topology
}

func (r *Router) BestPath(src, dst NodeID) ([]NodeID, error) {
	graph := r.Topology.Snapshot()
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
			alt := dist[u] + weight(metrics)
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

// Prober measures RTT/loss between peers.
type Prober interface {
	Probe(ctx context.Context, local, remote NodeID) (LinkMetrics, error)
}

// WSProber 通过简单的 WebSocket 握手 + Ping 估计 RTT。
type WSProber struct {
	Endpoints map[NodeID]string
	TLSConfig *tls.Config
	Timeout   time.Duration
}

func (p *WSProber) Probe(ctx context.Context, _, remote NodeID) (LinkMetrics, error) {
	url, ok := p.Endpoints[remote]
	if !ok {
		return LinkMetrics{}, fmt.Errorf("endpoint for %s not found", remote)
	}
	to := p.Timeout
	if to == 0 {
		to = 2 * time.Second
	}
	ctxPing, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	start := time.Now()
	c, _, err := websocket.Dial(ctxPing, url, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: p.TLSConfig}},
	})
	if err != nil {
		return LinkMetrics{}, err
	}
	defer c.Close(websocket.StatusNormalClosure, "probe done")
	if err := c.Ping(ctxPing); err != nil {
		return LinkMetrics{}, err
	}
	return LinkMetrics{
		RTT:       time.Since(start),
		LossRatio: 0,
		UpdatedAt: time.Now(),
	}, nil
}

// Transport encapsulates WSS data plane.
type Transport interface {
	Forward(ctx context.Context, src NodeID, path []NodeID, proto Protocol, downstream net.Conn, remoteAddr string) error
	ReconnectTCP(ctx context.Context, src NodeID, proto Protocol, downstream net.Conn, remoteAddr string, computePath func() ([]NodeID, error), attempts int) error
	Serve(ctx context.Context) error
}

// ControlHeader 描述剩余路径和最终出口。
type ControlHeader struct {
	Path       []NodeID `json:"path"`
	RemoteAddr string   `json:"remote"`
	Proto      Protocol `json:"proto"`
}

// UDPDatagram 用于跨 WS 传输单个 UDP 包。
type UDPDatagram struct {
	Src     string `json:"src"`
	Payload []byte `json:"payload"`
}

// AckStatus 记录确认链，Confirmed 是已成功下游建立的节点列表（自下而上聚合）。
type AckStatus struct {
	Confirmed []NodeID `json:"confirmed"`
	Note      string   `json:"note,omitempty"`
}

// ControlEnvelope 用于在数据桥接前传递控制信息（首帧 header、ack、错误）。
type ControlEnvelope struct {
	Type    string         `json:"type"` // header | ack | error
	Session string         `json:"session"`
	Header  *ControlHeader `json:"header,omitempty"`
	Ack     *AckStatus     `json:"ack,omitempty"`
	Error   string         `json:"error,omitempty"`
	Datagram *UDPDatagram  `json:"datagram,omitempty"` // Type=udp
	Signature string       `json:"sig,omitempty"`
	Version   int          `json:"ver,omitempty"`
	Timestamp int64        `json:"ts,omitempty"` // unix milli
}

// WSSTransport 通过 WebSocket 级联转发。
type WSSTransport struct {
	Self        NodeID
	ListenAddr  string
	Endpoints   map[NodeID]string // peer -> ws(s)://host:port/mesh
	TLSConfig   *tls.Config
	IdleTimeout time.Duration
	AuthKey     []byte
	Metrics     *Metrics
}

func (t *WSSTransport) Forward(ctx context.Context, src NodeID, path []NodeID, proto Protocol, downstream net.Conn, remoteAddr string) error {
	if len(path) < 2 {
		return fmt.Errorf("path too short: %v", path)
	}
	next := path[1]
	targetURL, ok := t.Endpoints[next]
	if !ok {
		return fmt.Errorf("no endpoint for %s", next)
	}
	session := newSessionID()
	header := ControlHeader{
		Path:       path[1:],
		RemoteAddr: remoteAddr,
		Proto:      proto,
	}
	ctxDial, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctxDial, targetURL, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: t.TLSConfig}},
	})
	if err != nil {
		downstream.Close()
		return fmt.Errorf("dial next %s failed: %w", next, err)
	}

	if err := writeSignedEnvelope(ctxDial, c, ControlEnvelope{
		Type:    "header",
		Session: session,
		Header:  &header,
	}, t.AuthKey); err != nil {
		downstream.Close()
		return fmt.Errorf("send header failed: %w", err)
	}
	ack, err := readVerifiedEnvelope(ctxDial, c, t.AuthKey)
	if err != nil {
		downstream.Close()
		return fmt.Errorf("await ack failed: %w", err)
	}
	if ack.Type != "ack" {
		downstream.Close()
		return fmt.Errorf("expected ack, got %s: %s", ack.Type, ack.Error)
	}
	log.Printf("[session=%s] 下游 %s 确认链路，已确认: %v", session, next, ack.Ack.Confirmed)
	wsConn := websocket.NetConn(ctx, c, websocket.MessageBinary)
	go func() {
		<-ctx.Done()
		c.Close(websocket.StatusNormalClosure, "ctx canceled")
		wsConn.Close()
	}()
	return bridgeWithLogging(session, downstream, wsConn, t.Metrics)
}

// ReconnectTCP 在桥接出错时尝试重新选路重建连接。
func (t *WSSTransport) ReconnectTCP(ctx context.Context, src NodeID, proto Protocol, downstream net.Conn, remoteAddr string, computePath func() ([]NodeID, error), attempts int) error {
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		path, err := computePath()
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		err = t.Forward(ctx, src, path, proto, downstream, remoteAddr)
		if err == nil {
			return nil
		}
		log.Printf("[reconnect attempt %d/%d] failed: %v", i+1, attempts, err)
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("reconnect attempts exhausted")
}

// OpenUDPSession 建立 UDP 隧道的控制面，返回已握手的 WS 连接与会话 ID。
func (t *WSSTransport) OpenUDPSession(ctx context.Context, path []NodeID, remoteAddr string) (*websocket.Conn, string, error) {
	if len(path) < 2 {
		return nil, "", fmt.Errorf("path too short: %v", path)
	}
	next := path[1]
	targetURL, ok := t.Endpoints[next]
	if !ok {
		return nil, "", fmt.Errorf("no endpoint for %s", next)
	}
	session := newSessionID()
	header := ControlHeader{
		Path:       path[1:],
		RemoteAddr: remoteAddr,
		Proto:      ProtocolUDP,
	}
	ctxDial, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctxDial, targetURL, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: t.TLSConfig}},
	})
	if err != nil {
		return nil, "", fmt.Errorf("dial next %s failed: %w", next, err)
	}
	if err := writeSignedEnvelope(ctxDial, c, ControlEnvelope{
		Type:    "header",
		Session: session,
		Header:  &header,
	}, t.AuthKey); err != nil {
		c.Close(websocket.StatusInternalError, "send header failed")
		return nil, "", err
	}
	ack, err := readVerifiedEnvelope(ctxDial, c, t.AuthKey)
	if err != nil {
		c.Close(websocket.StatusInternalError, "await ack failed")
		return nil, "", err
	}
	if ack.Type != "ack" || ack.Ack == nil {
		c.Close(websocket.StatusInternalError, "bad ack")
		return nil, "", fmt.Errorf("expected ack, got %s: %s", ack.Type, ack.Error)
	}
	log.Printf("[session=%s] UDP 下游 %s 确认链路，已确认: %v", session, next, ack.Ack.Confirmed)
	return c, session, nil
}

func (t *WSSTransport) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mesh", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: t.TLSConfig != nil && t.TLSConfig.InsecureSkipVerify,
		})
		if err != nil {
			log.Printf("accept ws failed: %v", err)
			return
		}
		go t.handleConn(ctx, c)
	})

	srv := &http.Server{
		Addr:         t.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	log.Printf("WSS transport listening on %s", t.ListenAddr)
	// 这里使用明文 ws；如需 TLS，可在外层反代或在此处配置证书。
	return srv.ListenAndServe()
}

func (t *WSSTransport) handleConn(ctx context.Context, c *websocket.Conn) {
	defer c.Close(websocket.StatusNormalClosure, "done")
	if t.IdleTimeout > 0 {
		c.SetReadLimit(64 << 20)
	}
	env, err := readVerifiedEnvelope(ctx, c, t.AuthKey)
	if err != nil {
		log.Printf("read header failed: %v", err)
		return
	}
	if env.Type != "header" || env.Header == nil {
		log.Printf("unexpected envelope type %s", env.Type)
		return
	}
	header := *env.Header
	session := env.Session
	if len(header.Path) == 0 {
		log.Printf("empty path in header")
		return
	}
	if header.Path[0] != t.Self {
		log.Printf("path not for me: %v", header.Path)
		return
	}
	remaining := header.Path[1:]

	if len(remaining) == 0 {
		// 当前节点是出口
		switch header.Proto {
		case ProtocolTCP:
			if err := t.handleTCPExit(ctx, session, c, header.RemoteAddr); err != nil {
				writeSignedEnvelope(ctx, c, ControlEnvelope{Type: "error", Session: session, Error: err.Error()}, t.AuthKey)
				return
			}
		case ProtocolUDP:
			if err := t.handleUDPExit(ctx, session, c, header.RemoteAddr); err != nil {
				writeSignedEnvelope(ctx, c, ControlEnvelope{Type: "error", Session: session, Error: err.Error()}, t.AuthKey)
				return
			}
		default:
			log.Printf("unknown proto %q", header.Proto)
		}
		return
	}

	// 中间节点：转发到下一跳
	next := remaining[0]
	targetURL, ok := t.Endpoints[next]
	if !ok {
		log.Printf("no endpoint for next hop %s", next)
		return
	}
	ctxDial, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	nextConn, _, err := websocket.Dial(ctxDial, targetURL, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: t.TLSConfig}},
	})
	if err != nil {
		log.Printf("dial next hop %s failed: %v", next, err)
		return
	}
	if err := writeSignedEnvelope(ctxDial, nextConn, ControlEnvelope{
		Type:    "header",
		Session: session,
		Header: &ControlHeader{
			Path:       remaining,
			RemoteAddr: header.RemoteAddr,
			Proto:      header.Proto,
		},
	}, t.AuthKey); err != nil {
		log.Printf("forward header failed: %v", err)
		nextConn.Close(websocket.StatusInternalError, "header write failed")
		return
	}
	nextAck, err := readVerifiedEnvelope(ctxDial, nextConn, t.AuthKey)
	if err != nil {
		log.Printf("wait downstream ack failed: %v", err)
		return
	}
	if nextAck.Type != "ack" || nextAck.Ack == nil {
		log.Printf("downstream returned non-ack: %s %s", nextAck.Type, nextAck.Error)
		return
	}
	confirmed := append([]NodeID{t.Self}, nextAck.Ack.Confirmed...)
	if err := writeSignedEnvelope(ctx, c, ControlEnvelope{
		Type:    "ack",
		Session: session,
		Ack:     &AckStatus{Confirmed: confirmed, Note: "forwarded to " + string(next)},
	}, t.AuthKey); err != nil {
		log.Printf("send upstream ack failed: %v", err)
		return
	}

	if header.Proto == ProtocolUDP {
		t.relayUDP(ctx, session, c, nextConn)
		return
	}

	upstream := websocket.NetConn(ctx, c, websocket.MessageBinary)
	downstream := websocket.NetConn(ctx, nextConn, websocket.MessageBinary)
	if err := bridgeWithLogging(session, upstream, downstream, t.Metrics); err != nil {
		log.Printf("[session=%s] bridge failed: %v", session, err)
	}
}

func (t *WSSTransport) handleTCPExit(ctx context.Context, session string, c *websocket.Conn, remoteAddr string) error {
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
	conn := websocket.NetConn(ctx, c, websocket.MessageBinary)
	if err := bridgeWithLogging(session, conn, out, t.Metrics); err != nil {
		return err
	}
	return nil
}

func (t *WSSTransport) handleUDPExit(ctx context.Context, session string, c *websocket.Conn, remoteAddr string) error {
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

func (t *WSSTransport) relayUDP(ctx context.Context, session string, upstream, downstream *websocket.Conn) {
	errCh := make(chan error, 2)
	forward := func(src, dst *websocket.Conn, dir string) {
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

func writeSignedEnvelope(ctx context.Context, c *websocket.Conn, env ControlEnvelope, key []byte) error {
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
	return c.Write(ctx, websocket.MessageText, data)
}

func readVerifiedEnvelope(ctx context.Context, c *websocket.Conn, key []byte) (ControlEnvelope, error) {
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
	var upCounter, downCounter *int64
	if m != nil {
		upCounter = &m.bytesUp
		downCounter = &m.bytesDown
	}
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(&countingWriter{Writer: a, counter: downCounter}, b)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(&countingWriter{Writer: b, counter: upCounter}, a)
		errCh <- err
	}()
	err := <-errCh
	a.Close()
	b.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		log.Printf("[session=%s] bridge error: %v", session, err)
	}
	return err
}

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

// Node wires entries, probing, routing, and transport.
type Node struct {
	ID         NodeID
	Entries    []EntryPort
	Router     *Router
	Prober     Prober
	Transport  Transport
	Peers      []NodeID
	PollPeriod time.Duration
	Metrics    *Metrics
	MaxReroute int
	udpTTL     time.Duration
}

func (n *Node) Start(ctx context.Context) error {
	if n.Transport == nil || n.Router == nil || n.Prober == nil {
		return errors.New("node missing Transport/Router/Prober")
	}
	if n.PollPeriod == 0 {
		n.PollPeriod = 3 * time.Second
	}

	go n.pollMetrics(ctx)
	go func() {
		if err := n.Transport.Serve(ctx); err != nil {
			log.Printf("transport server stopped: %v", err)
		}
	}()
	for _, ep := range n.Entries {
		ep := ep
		switch ep.Proto {
		case ProtocolTCP:
			go n.serveTCP(ctx, ep)
		case ProtocolUDP:
			go n.serveUDP(ctx, ep)
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
			}
		}
	}
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
			if n.Metrics != nil {
				n.Metrics.IncTCP()
			}
			attempts := n.MaxReroute
			if attempts < 1 {
				attempts = 1
			}
			if err := n.Transport.ReconnectTCP(ctx, n.ID, ep.Proto, c, ep.RemoteAddr, func() ([]NodeID, error) {
				return n.Router.BestPath(n.ID, ep.ExitNode)
			}, attempts); err != nil {
				log.Printf("tcp forwarding failed after %d attempts: %v", attempts, err)
				c.Close()
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
				path, err := n.Router.BestPath(n.ID, ep.ExitNode)
				if err != nil {
					mu.Unlock()
					log.Printf("route lookup failed: %v", err)
					return
				}
				wsConn, sessionID, err := transport.OpenUDPSession(ctx, path, ep.RemoteAddr)
				if err != nil {
					mu.Unlock()
					log.Printf("open udp session failed: %v", err)
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
			if now.Sub(s.lastActive.Load()) > ttl {
				s.cancel()
				delete(sessions, k)
			}
		}
		mu.Unlock()
	}
}

type udpSession struct {
	conn       *websocket.Conn
	cancel     context.CancelFunc
	clientAddr net.Addr
	sessionID  string
	lastActive atomic.Value
}

func (n *Node) udpDownstreamLoop(ctx context.Context, pc net.PacketConn, sess *udpSession, key []byte, metrics *Metrics, cleanup func()) {
	defer func() {
		if sess.conn != nil {
			sess.conn.Close(websocket.StatusNormalClosure, "udp session closed")
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
	s.lastActive.Store(time.Now())
}

type entryConfig struct {
	Listen string `json:"listen"`
	Proto  string `json:"proto"`
	Exit   string `json:"exit"`
	Remote string `json:"remote"`
}

type nodeConfig struct {
	ID              string            `json:"id"`
	WSListen        string            `json:"ws_listen"`
	Peers           map[string]string `json:"peers"` // node -> ws(s)://host:port/mesh
	Entries         []entryConfig     `json:"entries"`
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

func loadConfig(path string) (nodeConfig, error) {
	var cfg nodeConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.ID == "" || cfg.WSListen == "" {
		return cfg, errors.New("id and ws_listen required")
	}
	return cfg, nil
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

func buildTLSConfig(cfg nodeConfig) (*tls.Config, error) {
	if cfg.MTLSCert == "" && cfg.MTLSKey == "" && cfg.MTLSCA == "" {
		return &tls.Config{InsecureSkipVerify: cfg.InsecureSkipTLS}, nil
	}
	if cfg.MTLSCert == "" || cfg.MTLSKey == "" {
		return nil, fmt.Errorf("mtls_cert and mtls_key required when mtls_ca provided")
	}
	cert, err := tls.LoadX509KeyPair(cfg.MTLSCert, cfg.MTLSKey)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: cfg.InsecureSkipTLS,
	}
	if cfg.MTLSCA != "" {
		caData, err := os.ReadFile(cfg.MTLSCA)
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
		certPEM, err := os.ReadFile(cfg.MTLSCert)
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

func main() {
	configPath := flag.String("config", "config.json", "path to JSON config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}
	metrics := &Metrics{}
	var metricsSrv *http.Server
	if cfg.MetricsListen != "" {
		metricsSrv = metrics.Serve(cfg.MetricsListen)
		log.Printf("metrics listening on %s", cfg.MetricsListen)
	}
	topology := NewTopology()
	router := &Router{Topology: topology}

	tlsConf, err := buildTLSConfig(cfg)
	if err != nil {
		log.Fatalf("build tls config failed: %v", err)
	}
	authKey := []byte(cfg.AuthKey)
	endpoints := make(map[NodeID]string, len(cfg.Peers))
	peerIDs := make([]NodeID, 0, len(cfg.Peers))
	for id, url := range cfg.Peers {
		endpoints[NodeID(id)] = url
		peerIDs = append(peerIDs, NodeID(id))
	}

	entries := make([]EntryPort, 0, len(cfg.Entries))
	for _, e := range cfg.Entries {
		entries = append(entries, EntryPort{
			ListenAddr: e.Listen,
			Proto:      Protocol(e.Proto),
			ExitNode:   NodeID(e.Exit),
			RemoteAddr: e.Remote,
		})
	}

	udpTTL := parseDurationOrDefault(cfg.UDPSessionTTL, 60*time.Second)
	transport := &WSSTransport{
		Self:       NodeID(cfg.ID),
		ListenAddr: cfg.WSListen,
		Endpoints:  endpoints,
		TLSConfig:  tlsConf,
		AuthKey:    authKey,
		Metrics:    metrics,
	}
	prober := &WSProber{
		Endpoints: endpoints,
		TLSConfig: tlsConf,
	}

	node := &Node{
		ID:         NodeID(cfg.ID),
		Entries:    entries,
		Router:     router,
		Prober:     prober,
		Transport:  transport,
		Peers:      peerIDs,
		PollPeriod: parseDurationOrDefault(cfg.PollPeriod, 5*time.Second),
		Metrics:    metrics,
		MaxReroute: cfg.RerouteAttempts,
		udpTTL:     udpTTL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Printf("starting node %s", node.ID)
	if metricsSrv != nil {
		go func() {
			<-ctx.Done()
			shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
			defer c()
			metricsSrv.Shutdown(shutdownCtx)
		}()
	}
	if err := node.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("node stopped: %v", err)
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
