package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// Egress responsibilities:
// - terminate the path (remaining hops == 0)
// - dial the target remote and bridge bytes
// - optionally decrypt the mux stream based on enc policy

func (t *WSSTransport) handleMuxHeaderEgress(ctx context.Context, mm *MuxManager, streamID uint32, hdr ControlHeader, upStream *MuxStream) {
	sessionID := fmt.Sprintf("mux-%d", streamID)

	log.Printf("[mux stream=%d] exit handle proto=%s remote=%s compress=%s enc_id=%d", streamID, hdr.Proto, hdr.RemoteAddr, hdr.Compression, hdr.EncID)
	pol := findPolicy(t.EncPolicies, hdr.EncID)
	if hdr.EncID != 0 && pol == nil {
		log.Printf("[mux stream=%d] unknown enc policy id=%d", streamID, hdr.EncID)
		_ = upStream.WriteFlags(context.Background(), flagRST, []byte("unknown enc policy"))
		return
	}

	switch hdr.Proto {
	case ProtocolTCP:
		conn, err := net.DialTimeout("tcp", hdr.RemoteAddr, 5*time.Second)
		if err != nil {
			_ = upStream.WriteFlags(context.Background(), flagRST, []byte(err.Error()))
			return
		}
		wsConn := muxStreamConn(ctx, upStream, func() { conn.Close() })
		if pol != nil {
			log.Printf("[mux stream=%d] decrypt with enc_id=%d method=%s", streamID, pol.ID, pol.Method)
			secured, err := wrapSecureConn(wsConn, pol)
			if err != nil {
				_ = upStream.WriteFlags(context.Background(), flagRST, []byte(err.Error()))
				conn.Close()
				return
			}
			wsConn = secured
		}
		go func() {
			defer upStream.Close(context.Background())
			if err := bridgeMaybeCompressed(sessionID, conn, wsConn, hdr.Compression, hdr.CompressMin, t.Metrics, nil, hdr.RemoteAddr); err != nil {
				log.Printf("[session=%s] exit bridge failed: %v", sessionID, err)
				if isCipherErr(err) || isFrameErr(err) {
					_ = upStream.Reset(context.Background())
					log.Printf("[session=%s] bridge fatal error, closing mux conn", sessionID)
					mm.Conn().Close()
				}
			}
		}()

	case ProtocolUDP:
		udpConn, err := net.Dial("udp", hdr.RemoteAddr)
		if err != nil {
			_ = upStream.WriteFlags(context.Background(), flagRST, []byte(err.Error()))
			return
		}
		wsConn := muxStreamConn(ctx, upStream, func() { udpConn.Close() })
		if pol != nil {
			log.Printf("[mux stream=%d] decrypt with enc_id=%d method=%s (udp)", streamID, pol.ID, pol.Method)
			secured, err := wrapSecureConn(wsConn, pol)
			if err != nil {
				_ = upStream.WriteFlags(context.Background(), flagRST, []byte(err.Error()))
				udpConn.Close()
				return
			}
			wsConn = secured
		}
		go forwardUDPToStream(wsConn, udpConn, t.Metrics)
		go forwardStreamToUDP(wsConn, udpConn, t.Metrics)

	case Protocol("probe"):
		ctxReq, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctxReq, "GET", hdr.RemoteAddr, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		_ = upStream.WriteFlags(context.Background(), flagFIN, nil)
	}
}
