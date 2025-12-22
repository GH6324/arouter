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
	sessionID := hdr.Session
	if sessionID == "" {
		sessionID = fmt.Sprintf("mux-%d", streamID)
	}

	if hdr.Return {
		t.handleMuxHeaderReturnIngress(ctx, mm, streamID, sessionID, hdr, upStream)
		return
	}

	log.Printf("[mux stream=%d] exit handle proto=%s remote=%s entry=%s client=%s path=%v full=%v return=%v compress=%s enc_id=%d", streamID, hdr.Proto, hdr.RemoteAddr, hdr.EntryNode, hdr.ClientAddr, hdr.Path, hdr.FullPath, hdr.ReturnPath, hdr.Compression, hdr.EncID)
	t.reportDiag(hdr, "exit_handle", fmt.Sprintf("proto=%s remote=%s", hdr.Proto, hdr.RemoteAddr))
	pol := findPolicy(t.EncPolicies, hdr.EncID)
	if hdr.EncID != 0 && pol == nil {
		log.Printf("[mux stream=%d] unknown enc policy id=%d", streamID, hdr.EncID)
		_ = upStream.WriteFlags(context.Background(), flagRST, []byte("unknown enc policy"))
		return
	}

	switch hdr.Proto {
	case Protocol("preconnect"):
		_ = upStream.WriteFlags(context.Background(), flagFIN, nil)
		return
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
		if len(hdr.ReturnPath) >= 2 {
			if hdr.ReturnPath[0] != t.Self {
				log.Printf("[session=%s] return_path must start at %s, got %v", sessionID, t.Self, hdr.ReturnPath)
			} else {
				if next := hdr.ReturnPath[1]; next != "" {
					upstream := NodeID("")
					if len(hdr.FullPath) >= 2 {
						upstream = hdr.FullPath[len(hdr.FullPath)-2]
					} else if hdr.EntryNode != "" {
						upstream = hdr.EntryNode
					}
					if upstream != "" && next == upstream {
						if err := t.handleReturnEgressOnMux(ctx, sessionID, hdr, conn, wsConn, upStream, false, mm); err == nil {
							return
						} else {
							t.sendReturnFail(upStream, sessionID, hdr, false, err)
							log.Printf("[session=%s] return_path setup failed: %v (fallback to forward path)", sessionID, err)
						}
					} else {
						if err := t.handleReturnEgress(ctx, sessionID, hdr, conn, wsConn, upStream, false); err == nil {
							return
						} else {
							t.sendReturnFail(upStream, sessionID, hdr, false, err)
							log.Printf("[session=%s] return_path setup failed: %v (fallback to forward path)", sessionID, err)
						}
					}
				}
			}
		} else if len(hdr.Path) >= 1 {
			var reverse []NodeID
			if len(hdr.FullPath) >= 2 {
				reverse = make([]NodeID, 0, len(hdr.FullPath))
				for i := len(hdr.FullPath) - 1; i >= 0; i-- {
					reverse = append(reverse, hdr.FullPath[i])
				}
			} else if hdr.EntryNode != "" {
				reverse = []NodeID{t.Self, hdr.EntryNode}
			} else {
				reverse = make([]NodeID, 0, len(hdr.Path)+1)
				reverse = append(reverse, t.Self)
				for i := len(hdr.Path) - 1; i >= 0; i-- {
					reverse = append(reverse, hdr.Path[i])
				}
			}
			hdr.ReturnPath = reverse
			log.Printf("[session=%s] auto return_path computed=%v full=%v entry=%s", sessionID, hdr.ReturnPath, hdr.FullPath, hdr.EntryNode)
			if len(hdr.ReturnPath) >= 2 {
				next := hdr.ReturnPath[1]
				upstream := NodeID("")
				if len(hdr.FullPath) >= 2 {
					upstream = hdr.FullPath[len(hdr.FullPath)-2]
				} else if hdr.EntryNode != "" {
					upstream = hdr.EntryNode
				}
				if upstream != "" && next == upstream {
					if err := t.handleReturnEgressOnMux(ctx, sessionID, hdr, conn, wsConn, upStream, true, mm); err == nil {
						return
					} else {
						t.sendReturnFail(upStream, sessionID, hdr, true, err)
						log.Printf("[session=%s] auto return_path setup failed: %v (fallback to forward path)", sessionID, err)
					}
				} else {
					if err := t.handleReturnEgress(ctx, sessionID, hdr, conn, wsConn, upStream, true); err == nil {
						return
					} else {
						t.sendReturnFail(upStream, sessionID, hdr, true, err)
						log.Printf("[session=%s] auto return_path setup failed: %v (fallback to forward path)", sessionID, err)
					}
				}
			}
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
