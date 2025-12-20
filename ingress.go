package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	wscompat "arouter/internal/wscompat"
)

// Ingress responsibilities:
// - pick the first hop and establish the initial mux stream
// - send the control header
// - bridge local downstream <-> mux stream (optional compression/encryption)

func (t *WSSTransport) Forward(ctx context.Context, src NodeID, path []NodeID, proto Protocol, downstream net.Conn, remoteAddr string) error {
	if len(path) < 2 {
		return fmt.Errorf("path too short: %v", path)
	}
	next := path[1]
	targetURL, ok := t.Endpoints[next]
	if !ok {
		return fmt.Errorf("no endpoint for %s", next)
	}
	targetURL = normalizeWSEndpoint(targetURL)
	ctxDial, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, mux, pw, err := t.getOrDialMux(ctxDial, next, targetURL)
	if err != nil {
		if t.Topology != nil {
			t.Topology.UpdateLink(t.Self, next, 0, false, t.linkLossAlpha)
			t.Topology.MarkFail(t.Self, next)
		}
		downstream.Close()
		return fmt.Errorf("dial next %s failed: %w", next, err)
	}
	stream := mux.OpenStream()
	defer stream.Close(context.Background())
	session := fmt.Sprintf("mux-%d", stream.ID())
	pol := selectPolicy(t.EncPolicies)
	header := ControlHeader{
		Path:        path[1:],
		RemoteAddr:  remoteAddr,
		Proto:       proto,
		Compression: t.Compression,
		CompressMin: t.CompressMin,
	}
	if pol != nil {
		header.EncID = pol.ID
	}
	hdrPayload, _ := json.Marshal(header)
	if err := stream.WriteFlags(ctxDial, flagCTRL, marshalCtrl(ctrlHeader, hdrPayload)); err != nil {
		downstream.Close()
		t.releasePooled(next, pw)
		t.evictPooled(next, pw)
		if t.Topology != nil {
			t.Topology.UpdateLink(t.Self, next, 0, false, t.linkLossAlpha)
			t.Topology.MarkFail(t.Self, next)
		}
		return fmt.Errorf("send header failed: %w", err)
	}
	defer stream.Close(context.Background())
	logDebug("[mux stream=%d] sent header to %s proto=%s remote=%s path=%v", stream.ID(), next, proto, remoteAddr, header.Path)
	wsConn := muxStreamConn(ctx, stream, func() {
		logDebug("[mux stream=%d] release pooled mux %s (addr=%p)", stream.ID(), next, pw)
		t.releasePooled(next, pw)
	})
	defer t.releasePooled(next, pw)
	if pol != nil {
		logDebug("[mux stream=%d] enable encryption enc_id=%d method=%s", stream.ID(), pol.ID, pol.Method)
		secured, err := wrapSecureConn(wsConn, pol)
		if err != nil {
			downstream.Close()
			t.evictPooled(next, pw)
			if t.Topology != nil {
				t.Topology.UpdateLink(t.Self, next, 0, false, t.linkLossAlpha)
				t.Topology.MarkFail(t.Self, next)
			}
			return fmt.Errorf("enable encryption failed: %w", err)
		}
		wsConn = secured
	}
	logDebug("[session=%s] tunnel start proto=%s remote=%s path=%v compression=%s enc=%v", session, proto, remoteAddr, header.Path, header.Compression, header.EncID)
	err = bridgeMaybeCompressed(session, downstream, wsConn, header.Compression, header.CompressMin, t.Metrics, path, remoteAddr)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if err != nil {
		// Only reset on fatal protocol/cipher errors; otherwise prefer FIN close.
		if isCipherErr(err) || isFrameErr(err) {
			_ = stream.Reset(context.Background())
			logWarn("[mux stream=%d] bridge fatal (cipher/broken/frame), closing mux: %v", stream.ID(), err)
			t.evictPooled(next, pw)
		}
	}
	if err == nil {
		logDebug("[session=%s] tunnel finish proto=%s remote=%s path=%v", session, proto, remoteAddr, header.Path)
	}
	return err
}

// ReconnectTCP 在桥接出错时尝试重新选路重建连接。
func (t *WSSTransport) ReconnectTCP(ctx context.Context, src NodeID, proto Protocol, downstream net.Conn, remoteAddr string, computePath func(try int) ([]NodeID, error), attempts int) error {
	// 仅对入口->隧道、隧道->隧道做一次尝试，出口/远端断开不再重试。
	path, err := computePath(0)
	if err != nil {
		return err
	}
	return t.Forward(ctx, src, path, proto, downstream, remoteAddr)
}

// ProbeHTTP 在给定路径上发起 HTTP 探测（入口->多跳->出口->目标 URL），返回端到端耗时。
func (t *WSSTransport) ProbeHTTP(ctx context.Context, path []NodeID, target string, timeout time.Duration) (time.Duration, error) {
	if len(path) < 2 {
		return 0, fmt.Errorf("path too short: %v", path)
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	logTest("probe http start path=%v target=%s timeout=%s", path, target, timeout)
	next := path[1]
	targetURL, ok := t.Endpoints[next]
	if !ok {
		return 0, fmt.Errorf("no endpoint for %s", next)
	}
	targetURL = normalizeWSEndpoint(targetURL)
	logTest("probe http dial next=%s url=%s", next, targetURL)
	start := time.Now()
	ctxDial, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, mux, pw, err := t.getOrDialMux(ctxDial, next, targetURL)
	if err != nil {
		return 0, fmt.Errorf("dial next %s failed: %w", next, err)
	}
	defer t.releasePooled(next, pw)
	stream := mux.OpenStream()
	defer stream.Close(context.Background())
	header := ControlHeader{
		Path:       path[1:],
		RemoteAddr: target, // 复用 RemoteAddr 字段传目标 URL
		Proto:      Protocol("probe"),
	}
	hdrPayload, _ := json.Marshal(header)
	logTest("probe http send ctrl path=%v target=%s", header.Path, header.RemoteAddr)
	if err := stream.WriteFlags(ctxDial, flagCTRL, marshalCtrl(ctrlProbe, hdrPayload)); err != nil {
		return 0, fmt.Errorf("send probe failed: %w", err)
	}
	// 等待 FIN 表示完成
	ch := mux.subscribe(stream.ID())
	for f := range ch {
		if f.flags&(flagFIN|flagRST) != 0 {
			logTest("probe http recv fin flags=%d stream=%d", f.flags, stream.ID())
			break
		}
	}
	elapsed := time.Since(start)
	logTest("probe http finished path=%v target=%s rtt=%s", path, target, elapsed)
	return elapsed, nil
}

// OpenUDPSession 建立 UDP 隧道的控制面，返回已握手的 WS 连接与会话 ID。
func (t *WSSTransport) OpenUDPSession(ctx context.Context, path []NodeID, remoteAddr string) (*wscompat.Conn, string, error) {
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
		Path:        path[1:],
		RemoteAddr:  remoteAddr,
		Proto:       ProtocolUDP,
		Compression: t.Compression,
		CompressMin: t.CompressMin,
	}
	ctxDial, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := t.getOrDial(ctxDial, next, targetURL)
	if err != nil {
		return nil, "", fmt.Errorf("dial next %s failed: %w", next, err)
	}
	if err := writeSignedEnvelope(ctxDial, c, ControlEnvelope{
		Type:    "header",
		Session: session,
		Header:  &header,
	}, t.AuthKey); err != nil {
		c.Close()
		return nil, "", err
	}
	ack, err := readVerifiedEnvelope(ctxDial, c, t.AuthKey)
	if err != nil {
		c.Close()
		return nil, "", err
	}
	if ack.Type != "ack" || ack.Ack == nil {
		c.Close()
		return nil, "", fmt.Errorf("expected ack, got %s: %s", ack.Type, ack.Error)
	}
	log.Printf("[session=%s] UDP 下游 %s 确认链路，已确认: %v", session, next, ack.Ack.Confirmed)
	return c, session, nil
}
