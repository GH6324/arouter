package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"
)

type returnReadyMsg struct {
	Session string `json:"session"`
	Entry   string `json:"entry,omitempty"`
	Exit    string `json:"exit,omitempty"`
	Route   string `json:"route,omitempty"`
	Auto    bool   `json:"auto,omitempty"`
	DiagRun string `json:"diag_run_id,omitempty"`
}

type returnFailMsg struct {
	Session string `json:"session"`
	Entry   string `json:"entry,omitempty"`
	Exit    string `json:"exit,omitempty"`
	Route   string `json:"route,omitempty"`
	Auto    bool   `json:"auto,omitempty"`
	Error   string `json:"error,omitempty"`
	DiagRun string `json:"diag_run_id,omitempty"`
}

type returnAckInfo struct {
	start  time.Time
	entry  string
	exit   string
	route  string
	auto   bool
	diagID string
}

func (t *WSSTransport) registerReturnSession(id string, sess *returnSession) {
	if id == "" || sess == nil {
		return
	}
	t.returnMu.Lock()
	if t.returnSessions == nil {
		t.returnSessions = make(map[string]*returnSession)
	}
	t.returnSessions[id] = sess
	t.returnMu.Unlock()
	if t.Metrics != nil {
		t.Metrics.IncReturnPendingLabels(string(sess.entryNode), string(sess.exitNode), sess.routeName, sess.auto)
	}

	go func() {
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		<-timer.C
		t.returnMu.Lock()
		if cur := t.returnSessions[id]; cur == sess {
			delete(t.returnSessions, id)
			if t.Metrics != nil {
				t.Metrics.DecReturnPendingLabels(string(sess.entryNode), string(sess.exitNode), sess.routeName, sess.auto)
			}
		}
		t.returnMu.Unlock()
	}()
}

func (t *WSSTransport) attachReturnForward(id string, forward net.Conn) {
	if id == "" || forward == nil {
		return
	}
	t.returnMu.Lock()
	if t.returnSessions == nil {
		t.returnMu.Unlock()
		return
	}
	if sess := t.returnSessions[id]; sess != nil {
		sess.forwardRaw = forward
	}
	t.returnMu.Unlock()
}

func (t *WSSTransport) popReturnSession(id string) (*returnSession, bool) {
	if id == "" {
		return nil, false
	}
	t.returnMu.Lock()
	defer t.returnMu.Unlock()
	if t.returnSessions == nil {
		return nil, false
	}
	sess, ok := t.returnSessions[id]
	if ok {
		delete(t.returnSessions, id)
		if t.Metrics != nil {
			t.Metrics.DecReturnPendingLabels(string(sess.entryNode), string(sess.exitNode), sess.routeName, sess.auto)
		}
	}
	return sess, ok
}

func (t *WSSTransport) getReturnSession(id string) (*returnSession, bool) {
	if id == "" {
		return nil, false
	}
	t.returnMu.Lock()
	defer t.returnMu.Unlock()
	if t.returnSessions == nil {
		return nil, false
	}
	sess, ok := t.returnSessions[id]
	return sess, ok
}

func (t *WSSTransport) registerReturnReady(id string) {
	if id == "" {
		return
	}
	t.returnReadyMu.Lock()
	if t.returnReady == nil {
		t.returnReady = make(map[string]time.Time)
	}
	t.returnReady[id] = time.Now()
	t.returnReadyMu.Unlock()
}

func (t *WSSTransport) registerReturnAckWait(id string) chan struct{} {
	if id == "" {
		return nil
	}
	t.returnAckMu.Lock()
	if t.returnAckWait == nil {
		t.returnAckWait = make(map[string]chan struct{})
	}
	ch, ok := t.returnAckWait[id]
	if !ok {
		ch = make(chan struct{})
		t.returnAckWait[id] = ch
	}
	t.returnAckMu.Unlock()
	return ch
}

func (t *WSSTransport) registerReturnAckInfo(id string, info returnAckInfo) {
	if id == "" {
		return
	}
	t.returnAckMu.Lock()
	if t.returnAckInfo == nil {
		t.returnAckInfo = make(map[string]returnAckInfo)
	}
	t.returnAckInfo[id] = info
	t.returnAckMu.Unlock()
}

func (t *WSSTransport) popReturnAckInfo(id string) (returnAckInfo, bool) {
	t.returnAckMu.Lock()
	defer t.returnAckMu.Unlock()
	if t.returnAckInfo == nil {
		return returnAckInfo{}, false
	}
	info, ok := t.returnAckInfo[id]
	if ok {
		delete(t.returnAckInfo, id)
	}
	return info, ok
}

func (t *WSSTransport) markReturnAck(id string) {
	if id == "" {
		return
	}
	t.returnAckMu.Lock()
	if t.returnAckWait == nil {
		t.returnAckMu.Unlock()
		return
	}
	if ch, ok := t.returnAckWait[id]; ok {
		delete(t.returnAckWait, id)
		close(ch)
	}
	t.returnAckMu.Unlock()
	if info, ok := t.popReturnAckInfo(id); ok {
		rtt := time.Since(info.start)
		if t.diagReport != nil && info.diagID != "" {
			t.diagReport(DiagEvent{
				RunID:  info.diagID,
				Route:  info.route,
				Node:   string(t.Self),
				Stage:  "return_ack_rtt",
				Detail: fmt.Sprintf("rtt=%s entry=%s exit=%s auto=%v", rtt, info.entry, info.exit, info.auto),
				At:     time.Now().UnixMilli(),
			})
		}
	}
	log.Printf("[session=%s] return ack received", id)
}

func (t *WSSTransport) waitReturnAck(id string, timeout time.Duration) bool {
	if id == "" {
		return false
	}
	ch := t.registerReturnAckWait(id)
	if ch == nil {
		return false
	}
	log.Printf("[session=%s] wait return ack timeout=%s", id, timeout)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		_, _ = t.popReturnAckInfo(id)
		return false
	}
}

func (t *WSSTransport) getReturnAckTimeout() time.Duration {
	if t == nil {
		return 10 * time.Second
	}
	if t.returnAckTimeout > 0 {
		return t.returnAckTimeout
	}
	return 10 * time.Second
}

func (t *WSSTransport) markReturnReady(msg returnReadyMsg) {
	if msg.Session == "" {
		return
	}
	t.returnReadyMu.Lock()
	if t.returnReady == nil {
		t.returnReady = make(map[string]time.Time)
	}
	t.returnReady[msg.Session] = time.Now()
	t.returnReadyMu.Unlock()
	if t.Metrics != nil {
		t.Metrics.MarkReturnReadyLabels(msg.Entry, msg.Exit, msg.Route, msg.Auto)
	}
	log.Printf("[session=%s] return path ready route=%s exit=%s entry=%s auto=%v", msg.Session, msg.Route, msg.Exit, msg.Entry, msg.Auto)
}

func (t *WSSTransport) registerDiagReturnWait(runID string) chan struct{} {
	if runID == "" {
		return nil
	}
	t.diagReturnMu.Lock()
	if t.diagReturnWait == nil {
		t.diagReturnWait = make(map[string]chan struct{})
	}
	ch, ok := t.diagReturnWait[runID]
	if !ok {
		ch = make(chan struct{})
		t.diagReturnWait[runID] = ch
	}
	t.diagReturnMu.Unlock()
	return ch
}

func (t *WSSTransport) markDiagReturnReady(runID string) {
	if runID == "" {
		return
	}
	t.diagReturnMu.Lock()
	if t.diagReturnWait == nil {
		t.diagReturnMu.Unlock()
		return
	}
	if ch, ok := t.diagReturnWait[runID]; ok {
		delete(t.diagReturnWait, runID)
		close(ch)
	}
	t.diagReturnMu.Unlock()
}

func (t *WSSTransport) cancelDiagReturnWait(runID string) {
	if runID == "" {
		return
	}
	t.diagReturnMu.Lock()
	if t.diagReturnWait != nil {
		if ch, ok := t.diagReturnWait[runID]; ok {
			delete(t.diagReturnWait, runID)
			close(ch)
		}
	}
	t.diagReturnMu.Unlock()
}

func (t *WSSTransport) registerDiagReturnFailWait(runID string) chan error {
	if runID == "" {
		return nil
	}
	t.diagReturnMu.Lock()
	if t.diagReturnFailWait == nil {
		t.diagReturnFailWait = make(map[string]chan error)
	}
	ch, ok := t.diagReturnFailWait[runID]
	if !ok {
		ch = make(chan error, 1)
		t.diagReturnFailWait[runID] = ch
	}
	t.diagReturnMu.Unlock()
	return ch
}

func (t *WSSTransport) markDiagReturnFail(runID string, errMsg string) {
	if runID == "" {
		return
	}
	t.diagReturnMu.Lock()
	if t.diagReturnFailWait == nil {
		t.diagReturnMu.Unlock()
		return
	}
	if ch, ok := t.diagReturnFailWait[runID]; ok {
		delete(t.diagReturnFailWait, runID)
		if errMsg == "" {
			errMsg = "return fail"
		}
		ch <- fmt.Errorf("%s", errMsg)
		close(ch)
	}
	t.diagReturnMu.Unlock()
}

func (t *WSSTransport) cancelDiagReturnFailWait(runID string) {
	if runID == "" {
		return
	}
	t.diagReturnMu.Lock()
	if t.diagReturnFailWait != nil {
		if ch, ok := t.diagReturnFailWait[runID]; ok {
			delete(t.diagReturnFailWait, runID)
			close(ch)
		}
	}
	t.diagReturnMu.Unlock()
}

func (t *WSSTransport) markReturnFail(msg returnFailMsg) {
	if msg.Session == "" {
		return
	}
	if _, ok := t.popReturnSession(msg.Session); ok {
		log.Printf("[session=%s] return path failed: %s", msg.Session, msg.Error)
	}
	if t.Metrics != nil {
		t.Metrics.MarkReturnFailLabels(msg.Entry, msg.Exit, msg.Route, msg.Auto)
		if msg.Error != "" {
			t.Metrics.SetReturnFailReason(msg.Entry, msg.Exit, msg.Route, msg.Auto, msg.Error)
		}
	}
}

func relayKey(mm *MuxManager, streamID uint32) string {
	return fmt.Sprintf("%p:%d", mm, streamID)
}

func (t *WSSTransport) registerRelayPair(up *MuxManager, upID uint32, down *MuxStream, downMux *MuxManager, downID uint32, upStream *MuxStream) {
	t.relayMu.Lock()
	if t.relayPeers == nil {
		t.relayPeers = make(map[string]*MuxStream)
	}
	t.relayPeers[relayKey(up, upID)] = down
	t.relayPeers[relayKey(downMux, downID)] = upStream
	t.relayMu.Unlock()
}

func (t *WSSTransport) unregisterRelayPair(up *MuxManager, upID uint32, downMux *MuxManager, downID uint32) {
	t.relayMu.Lock()
	if t.relayPeers != nil {
		delete(t.relayPeers, relayKey(up, upID))
		delete(t.relayPeers, relayKey(downMux, downID))
	}
	t.relayMu.Unlock()
}

func (t *WSSTransport) relayPeer(mm *MuxManager, streamID uint32) *MuxStream {
	t.relayMu.Lock()
	defer t.relayMu.Unlock()
	if t.relayPeers == nil {
		return nil
	}
	return t.relayPeers[relayKey(mm, streamID)]
}

func copyOneWayMaybeCompressed(session string, dst, src net.Conn, compression string, minBytes int, counter *int64, compress bool, closeDst bool) error {
	var startCount int64 = -1
	if counter != nil {
		startCount = atomic.LoadInt64(counter)
	}
	startMsg := fmt.Sprintf("[copy %s] compression=%s src=%s dst=%s", dirLabel(compress), compression, safeAddr(src), safeAddr(dst))
	var err error
	if compression == "" || compression == "none" {
		_, err = io.Copy(&countingWriter{Writer: dst, counter: counter}, src)
	} else {
		err = copyWithCompression(dst, src, compression, minBytes, counter, compress)
	}
	if closeDst {
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}
	if isClosedPipeErr(err) || errors.Is(err, net.ErrClosed) {
		err = io.EOF
	}
	logCopyDone(startMsg, counter, startCount, err)
	return err
}

func (t *WSSTransport) handleMuxHeaderReturnIngress(ctx context.Context, mm *MuxManager, streamID uint32, sessionID string, hdr ControlHeader, upStream *MuxStream) {
	log.Printf("[mux stream=%d] return ingress session=%s entry=%s exit=%s", streamID, sessionID, hdr.EntryNode, t.Self)
	t.reportDiag(hdr, "return_ingress", "recv return header")
	ackPayload, _ := json.Marshal(returnReadyMsg{
		Session: sessionID,
		Entry:   string(t.Self),
		Route:   hdr.RouteName,
		Auto:    false,
		DiagRun: hdr.DiagRunID,
	})
	_ = upStream.WriteFlags(context.Background(), flagCTRL, marshalCtrl(ctrlReturnAck, ackPayload))
	log.Printf("[mux stream=%d] send return ack session=%s entry=%s", streamID, sessionID, t.Self)
	t.reportDiag(hdr, "return_ack_sent", fmt.Sprintf("entry=%s exit=%s auto=%v", hdr.EntryNode, t.Self, false))
	sess, ok := t.popReturnSession(sessionID)
	if !ok || sess == nil || sess.downstream == nil {
		log.Printf("[mux stream=%d] return session %s not found", streamID, sessionID)
		_ = upStream.WriteFlags(context.Background(), flagRST, []byte("return session not found"))
		return
	}
	if sess.forwardRaw != nil {
		if cr, ok := sess.forwardRaw.(closeReader); ok {
			_ = cr.CloseRead()
		}
	}
	wsConn := muxStreamConn(ctx, upStream, func() {})
	pol := findPolicy(t.EncPolicies, hdr.EncID)
	if hdr.EncID != 0 && pol == nil {
		log.Printf("[mux stream=%d] unknown enc policy id=%d", streamID, hdr.EncID)
		_ = upStream.WriteFlags(context.Background(), flagRST, []byte("unknown enc policy"))
		return
	}
	if pol != nil {
		secured, err := wrapSecureConn(wsConn, pol)
		if err != nil {
			_ = upStream.WriteFlags(context.Background(), flagRST, []byte(err.Error()))
			return
		}
		wsConn = secured
	}

	go func() {
		defer upStream.Close(context.Background())
		err := copyOneWayMaybeCompressed(sessionID, sess.downstream, wsConn, hdr.Compression, hdr.CompressMin, nil, false, true)
		if err != nil && !errors.Is(err, io.EOF) && !isCanceledErr(err) {
			log.Printf("[session=%s] return stream failed: %v", sessionID, err)
		}
	}()
}

func (t *WSSTransport) handleReturnEgress(ctx context.Context, sessionID string, hdr ControlHeader, remote net.Conn, forwardWS net.Conn, upStream *MuxStream, auto bool) error {
	if len(hdr.ReturnPath) < 2 {
		return fmt.Errorf("return_path too short")
	}
	next := hdr.ReturnPath[1]
	targetURL, ok := t.Endpoints[next]
	if !ok {
		return fmt.Errorf("no endpoint for return hop %s", next)
	}
	targetURL = normalizeWSEndpoint(targetURL)
	ctxDial, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, nextMux, pw, err := t.getOrDialMux(ctxDial, next, targetURL)
	if err != nil || nextMux == nil {
		return fmt.Errorf("dial return hop %s failed: %w", next, err)
	}
	returnStream := nextMux.OpenStream()
	if err := t.sendReturnHeader(ctxDial, returnStream, sessionID, hdr); err != nil {
		t.releasePooled(next, pw)
		t.evictPooled(next, pw)
		return err
	}
	log.Printf("[session=%s] return stream established via %s path=%v", sessionID, next, hdr.ReturnPath)
	waitAck := hdr.DiagRunID != ""
	if waitAck {
		entry := ""
		if len(hdr.ReturnPath) > 0 {
			entry = string(hdr.ReturnPath[len(hdr.ReturnPath)-1])
		}
		routeName := hdr.RouteName
		if routeName == "" {
			routeName = "auto"
		}
		t.registerReturnAckInfo(sessionID, returnAckInfo{
			start:  time.Now(),
			entry:  entry,
			exit:   string(t.Self),
			route:  routeName,
			auto:   auto,
			diagID: hdr.DiagRunID,
		})
		go t.waitReturnAck(sessionID, t.getReturnAckTimeout())
	}
	t.sendReturnReady(upStream, sessionID, hdr, auto)

	returnWS := muxStreamConn(ctx, returnStream, func() { t.releasePooled(next, pw) })
	return t.startReturnBridge(ctx, sessionID, hdr, remote, forwardWS, returnWS, returnStream)
}

func (t *WSSTransport) handleReturnEgressOnMux(ctx context.Context, sessionID string, hdr ControlHeader, remote net.Conn, forwardWS net.Conn, upStream *MuxStream, auto bool, mm *MuxManager) error {
	if mm == nil {
		return fmt.Errorf("nil mux for return")
	}
	returnStream := mm.OpenStream()
	if err := t.sendReturnHeader(ctx, returnStream, sessionID, hdr); err != nil {
		return err
	}
	log.Printf("[session=%s] return stream established via upstream mux path=%v", sessionID, hdr.ReturnPath)
	waitAck := hdr.DiagRunID != ""
	if waitAck {
		entry := ""
		if len(hdr.ReturnPath) > 0 {
			entry = string(hdr.ReturnPath[len(hdr.ReturnPath)-1])
		}
		routeName := hdr.RouteName
		if routeName == "" {
			routeName = "auto"
		}
		t.registerReturnAckInfo(sessionID, returnAckInfo{
			start:  time.Now(),
			entry:  entry,
			exit:   string(t.Self),
			route:  routeName,
			auto:   auto,
			diagID: hdr.DiagRunID,
		})
		go t.waitReturnAck(sessionID, t.getReturnAckTimeout())
	}
	t.sendReturnReady(upStream, sessionID, hdr, auto)

	returnWS := muxStreamConn(ctx, returnStream, func() {})
	return t.startReturnBridge(ctx, sessionID, hdr, remote, forwardWS, returnWS, returnStream)
}

func (t *WSSTransport) sendReturnHeader(ctx context.Context, returnStream *MuxStream, sessionID string, hdr ControlHeader) error {
	if returnStream == nil {
		return fmt.Errorf("nil return stream")
	}
	returnHdr := ControlHeader{
		Path:        hdr.ReturnPath[1:],
		RemoteAddr:  hdr.RemoteAddr,
		Proto:       hdr.Proto,
		Compression: hdr.Compression,
		CompressMin: hdr.CompressMin,
		EncID:       hdr.EncID,
		Session:     sessionID,
		Return:      true,
		EntryNode:   hdr.EntryNode,
		ClientAddr:  hdr.ClientAddr,
		DiagRunID:   hdr.DiagRunID,
		DiagRoute:   hdr.DiagRoute,
	}
	payload, _ := json.Marshal(returnHdr)
	if err := returnStream.WriteFlags(ctx, flagCTRL, marshalCtrl(ctrlHeader, payload)); err != nil {
		return fmt.Errorf("send return header failed: %w", err)
	}
	log.Printf("[session=%s] send return header path=%v entry=%s client=%s", sessionID, returnHdr.Path, returnHdr.EntryNode, returnHdr.ClientAddr)
	t.reportDiag(hdr, "send_return_header", fmt.Sprintf("path=%v", returnHdr.Path))
	return nil
}

func (t *WSSTransport) sendReturnReady(upStream *MuxStream, sessionID string, hdr ControlHeader, auto bool) {
	if upStream == nil {
		return
	}
	routeName := hdr.RouteName
	if routeName == "" {
		routeName = "auto"
	}
	entry := ""
	if len(hdr.ReturnPath) > 0 {
		entry = string(hdr.ReturnPath[len(hdr.ReturnPath)-1])
	}
	readyPayload, _ := json.Marshal(returnReadyMsg{
		Session: sessionID,
		Entry:   entry,
		Exit:    string(t.Self),
		Route:   routeName,
		Auto:    auto,
		DiagRun: hdr.DiagRunID,
	})
	_ = upStream.WriteFlags(context.Background(), flagCTRL, marshalCtrl(ctrlReturnReady, readyPayload))
	log.Printf("[session=%s] send return ready entry=%s exit=%s route=%s auto=%v", sessionID, entry, t.Self, routeName, auto)
	t.reportDiag(hdr, "return_ready", fmt.Sprintf("entry=%s exit=%s auto=%v", entry, t.Self, auto))
}

func (t *WSSTransport) startReturnBridge(ctx context.Context, sessionID string, hdr ControlHeader, remote net.Conn, forwardWS net.Conn, returnWS net.Conn, returnStream *MuxStream) error {
	pol := findPolicy(t.EncPolicies, hdr.EncID)
	if hdr.EncID != 0 && pol == nil {
		return fmt.Errorf("unknown enc policy id=%d", hdr.EncID)
	}
	if pol != nil {
		secured, err := wrapSecureConn(returnWS, pol)
		if err != nil {
			return fmt.Errorf("wrap return stream failed: %w", err)
		}
		returnWS = secured
	}

	go func() {
		defer returnStream.Close(context.Background())
		// forward stream: entry -> exit (decompress on exit)
		_ = copyOneWayMaybeCompressed(sessionID, remote, forwardWS, hdr.Compression, hdr.CompressMin, nil, false, true)
	}()
	go func() {
		defer returnStream.Close(context.Background())
		// return stream: exit -> entry (compress on exit)
		_ = copyOneWayMaybeCompressed(sessionID, returnWS, remote, hdr.Compression, hdr.CompressMin, nil, true, true)
	}()
	return nil
}

func (t *WSSTransport) sendReturnFail(upStream *MuxStream, sessionID string, hdr ControlHeader, auto bool, err error) {
	if upStream == nil {
		return
	}
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	routeName := hdr.RouteName
	if routeName == "" {
		routeName = "auto"
	}
	entry := ""
	if len(hdr.ReturnPath) > 0 {
		entry = string(hdr.ReturnPath[len(hdr.ReturnPath)-1])
	}
	payload, _ := json.Marshal(returnFailMsg{
		Session: sessionID,
		Entry:   entry,
		Exit:    string(t.Self),
		Route:   routeName,
		Auto:    auto,
		Error:   errMsg,
		DiagRun: hdr.DiagRunID,
	})
	_ = upStream.WriteFlags(context.Background(), flagCTRL, marshalCtrl(ctrlReturnFail, payload))
	log.Printf("[session=%s] send return fail entry=%s exit=%s route=%s auto=%v err=%s", sessionID, entry, t.Self, routeName, auto, errMsg)
	t.reportDiag(hdr, "return_fail", fmt.Sprintf("entry=%s exit=%s auto=%v err=%s", entry, t.Self, auto, errMsg))
}
