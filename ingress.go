package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	wscompat "arouter/internal/wscompat"
)

// Ingress responsibilities:
// - pick the first hop and establish the initial mux stream
// - send the control header
// - bridge local downstream <-> mux stream (optional compression/encryption)

func (t *WSSTransport) Forward(ctx context.Context, src NodeID, path []NodeID, returnPath []NodeID, proto Protocol, downstream net.Conn, remoteAddr string, routeName string) error {
	return t.forwardWithDiag(ctx, src, path, returnPath, proto, downstream, remoteAddr, routeName, "", "")
}

func (t *WSSTransport) ForwardWithDiag(ctx context.Context, src NodeID, path []NodeID, returnPath []NodeID, proto Protocol, downstream net.Conn, remoteAddr string, routeName string, runID string, diagRoute string) error {
	return t.forwardWithDiag(ctx, src, path, returnPath, proto, downstream, remoteAddr, routeName, runID, diagRoute)
}

func (t *WSSTransport) forwardWithDiag(ctx context.Context, src NodeID, path []NodeID, returnPath []NodeID, proto Protocol, downstream net.Conn, remoteAddr string, routeName string, runID string, diagRoute string) error {
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
	session := newSessionID()
	pol := selectPolicy(t.EncPolicies)
	header := ControlHeader{
		Path:        path[1:],
		FullPath:    path,
		RemoteAddr:  remoteAddr,
		Proto:       proto,
		Compression: t.Compression,
		CompressMin: t.CompressMin,
		Session:     session,
		EntryNode:   src,
		ClientAddr:  safeAddr(downstream),
		DiagRunID:   runID,
		DiagRoute:   diagRoute,
	}
	if header.DiagRunID != "" && header.DiagRoute == "" {
		header.DiagRoute = routeName
	}
	if proto == ProtocolTCP && len(returnPath) >= 2 {
		header.ReturnPath = returnPath
	}
	if routeName != "" {
		header.RouteName = routeName
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
	logDebug("[mux stream=%d] sent header to %s proto=%s remote=%s path=%v full=%v return=%v entry=%s client=%s", stream.ID(), next, proto, remoteAddr, header.Path, header.FullPath, header.ReturnPath, header.EntryNode, header.ClientAddr)
	t.reportDiag(header, "send_header", fmt.Sprintf("next=%s proto=%s remote=%s", next, proto, remoteAddr))
	rawWS := muxStreamConn(ctx, stream, func() {
		logDebug("[mux stream=%d] release pooled mux %s (addr=%p)", stream.ID(), next, pw)
		t.releasePooled(next, pw)
	})
	wsConn := rawWS
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
	useReturn := proto == ProtocolTCP
	logDebug("[session=%s] tunnel start proto=%s remote=%s path=%v full=%v compression=%s enc=%v return=%v entry=%s client=%s", session, proto, remoteAddr, header.Path, header.FullPath, header.Compression, header.EncID, header.ReturnPath, header.EntryNode, header.ClientAddr)

	if useReturn {
		exitNode := path[len(path)-1]
		routeLabel := routeName
		if routeLabel == "" {
			routeLabel = "auto"
		}
		autoReturn := len(returnPath) == 0
		t.registerReturnSession(session, &returnSession{
			downstream:  downstream,
			compression: header.Compression,
			compressMin: header.CompressMin,
			encID:       header.EncID,
			createdAt:   time.Now(),
			routeName:   routeLabel,
			entryNode:   t.Self,
			exitNode:    exitNode,
			auto:        autoReturn,
		})
		t.attachReturnForward(session, rawWS)
		t.registerReturnReady(session)
	}
	if useReturn {
		err = bridgeReturnMode(session, downstream, wsConn, header.Compression, header.CompressMin, t.Metrics, path, remoteAddr)
	} else {
		err = bridgeMaybeCompressed(session, downstream, wsConn, header.Compression, header.CompressMin, t.Metrics, path, remoteAddr)
	}
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

func (t *WSSTransport) DiagReturnPath(ctx context.Context, path []NodeID, returnPath []NodeID, remoteAddr string, routeName string, runID string) error {
	if len(path) < 2 {
		return fmt.Errorf("path too short: %v", path)
	}
	if len(returnPath) < 2 {
		return fmt.Errorf("return path too short: %v", returnPath)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	errCh := make(chan error, 1)
	readyCh := t.registerDiagReturnWait(runID)
	failCh := t.registerDiagReturnFailWait(runID)
	if readyCh != nil {
		defer t.cancelDiagReturnWait(runID)
	}
	if failCh != nil {
		defer t.cancelDiagReturnFailWait(runID)
	}
	go func() {
		errCh <- t.ForwardWithDiag(ctx, path[0], path, returnPath, ProtocolTCP, a, remoteAddr, routeName, runID, routeName)
	}()
	timer := time.NewTimer(2 * time.Second)
	select {
	case <-ctx.Done():
		timer.Stop()
		_ = b.Close()
		return ctx.Err()
	case <-timer.C:
	}
	_ = b.Close()
	select {
	case <-readyCh:
		return nil
	case err := <-failCh:
		if err == nil {
			return fmt.Errorf("return failed")
		}
		return err
	case err := <-errCh:
		return err
	case <-time.After(3 * time.Second):
		return fmt.Errorf("return diag timeout")
	}
}

func bridgeReturnMode(session string, downstream net.Conn, wsConn net.Conn, compression string, minBytes int, m *Metrics, path []NodeID, remote string) error {
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
	log.Printf("[flow session=%s] start return-bridge compression=%s min=%d from=%s to=%s remote=%s path=%s", session, compression, minBytes, safeAddr(wsConn), safeAddr(downstream), remote, pathStr)

	errCh := make(chan error, 2)
	go func() {
		// forward path is read-closed when return path is ready; do not close downstream.
		errCh <- copyOneWayMaybeCompressed(session, wsConn, downstream, compression, minBytes, downCounter, true, false)
	}()
	go func() {
		// keep downstream writable for return stream
		errCh <- copyOneWayMaybeCompressed(session, downstream, wsConn, compression, minBytes, upCounter, false, false)
	}()
	err1 := <-errCh
	err2 := <-errCh
	_ = wsConn.Close()
	err := err1
	if err == nil {
		err = err2
	}
	if err != nil && (errors.Is(err, io.EOF) || isClosedPipeErr(err) || isCanceledErr(err)) {
		err = nil
	}
	if err != nil && !isCanceledErr(err) && !errors.Is(err, io.EOF) {
		log.Printf("[session=%s] return-bridge error: %v", session, err)
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
	return t.Forward(ctx, src, path, nil, proto, downstream, remoteAddr, "")
}

// ProbeHTTP 在给定路径上发起 HTTP 探测（入口->多跳->出口->目标 URL），返回端到端耗时。
func (t *WSSTransport) ProbeHTTP(ctx context.Context, path []NodeID, target string, timeout time.Duration) (time.Duration, error) {
	return t.probeHTTPWithDiag(ctx, path, target, timeout, "", "")
}

func (t *WSSTransport) ProbeHTTPDiag(ctx context.Context, path []NodeID, target string, timeout time.Duration, runID string, diagRoute string) (time.Duration, error) {
	return t.probeHTTPWithDiag(ctx, path, target, timeout, runID, diagRoute)
}

func (t *WSSTransport) probeHTTPWithDiag(ctx context.Context, path []NodeID, target string, timeout time.Duration, runID string, diagRoute string) (time.Duration, error) {
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
		FullPath:   path,
		RemoteAddr: target, // 复用 RemoteAddr 字段传目标 URL
		Proto:      Protocol("probe"),
		DiagRunID:  runID,
		DiagRoute:  diagRoute,
	}
	if header.DiagRunID != "" && header.DiagRoute == "" {
		header.DiagRoute = "probe"
	}
	hdrPayload, _ := json.Marshal(header)
	logTest("probe http send ctrl path=%v target=%s", header.Path, header.RemoteAddr)
	if err := stream.WriteFlags(ctxDial, flagCTRL, marshalCtrl(ctrlProbe, hdrPayload)); err != nil {
		return 0, fmt.Errorf("send probe failed: %w", err)
	}
	t.reportDiag(header, "probe_send", fmt.Sprintf("next=%s target=%s", next, target))
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
func (t *WSSTransport) OpenUDPSession(ctx context.Context, path []NodeID, remoteAddr string, clientAddr string) (*wscompat.Conn, string, error) {
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
		FullPath:    path,
		RemoteAddr:  remoteAddr,
		Proto:       ProtocolUDP,
		Compression: t.Compression,
		CompressMin: t.CompressMin,
		EntryNode:   t.Self,
		ClientAddr:  clientAddr,
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
