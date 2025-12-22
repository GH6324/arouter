package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Relay responsibilities:
// - forward control header to the next hop
// - pump data frames bidirectionally
// - propagate FINW/FIN/RST semantics without reinterpretation
// - never close the whole mux due to a single stream ending

func (t *WSSTransport) handleMuxHeaderRelay(ctx context.Context, mm *MuxManager, streamID uint32, hdr ControlHeader, upStream *MuxStream, streamCh <-chan muxFrame, remaining []NodeID) {
	next := remaining[0]
	logDebug("[mux=%p stream=%d] relay forward to %s path=%v return=%v session=%s", mm, streamID, next, remaining, hdr.Return, hdr.Session)
	t.reportDiag(hdr, "relay_next", fmt.Sprintf("next=%s return=%v", next, hdr.Return))
	var (
		nextMux *MuxManager
		pw      *pooledWS
	)
	if hdr.Return {
		if inbound := t.getInboundMux(next); inbound != nil && inbound != mm {
			select {
			case <-inbound.Done():
				logWarn("[mux=%p stream=%d] relay return inbound mux closed for %s", mm, streamID, next)
			default:
				nextMux = inbound
				logDebug("[mux=%p stream=%d] relay return using inbound mux to %s (addr=%p)", mm, streamID, next, inbound)
			}
		} else {
			logWarn("[mux=%p stream=%d] relay return inbound missing for %s", mm, streamID, next)
		}
		if nextMux == nil {
			_ = upStream.WriteFlags(context.Background(), flagRST, []byte("return hop unreachable"))
			return
		}
	}
	if nextMux == nil {
		targetURL, ok := t.Endpoints[next]
		if !ok {
			_ = upStream.WriteFlags(context.Background(), flagRST, []byte("no endpoint"))
			return
		}
		targetURL = normalizeWSEndpoint(targetURL)
		ctxDial, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var err error
		_, nextMux, pw, err = t.getOrDialMux(ctxDial, next, targetURL)
		if err != nil || nextMux == nil {
			if err != nil {
				logWarn("[mux=%p stream=%d] relay dial to %s failed: %v", mm, streamID, next, err)
			}
			_ = upStream.WriteFlags(context.Background(), flagRST, []byte("dial next failed"))
			return
		}
	}

	downStream := nextMux.OpenStream()
	hdr.Path = remaining
	payload, _ := json.Marshal(hdr)
	if err := downStream.WriteFlags(ctx, flagCTRL, marshalCtrl(ctrlHeader, payload)); err != nil {
		t.releasePooled(next, pw)
		t.evictPooled(next, pw)
		logWarn("[mux=%p stream=%d] relay header write to %s failed: %v", mm, streamID, next, err)
		return
	}
	downCh := nextMux.subscribe(downStream.ID())
	logDebug("[mux=%p stream=%d] relay start next=%s path=%v down_mux=%p down_stream=%d", mm, streamID, next, remaining, nextMux, downStream.ID())
	t.registerRelayPair(mm, streamID, downStream, nextMux, downStream.ID(), upStream)

	// We release pooled mux only after both directions finish (strict relay), or at least once (best-effort).
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { t.releasePooled(next, pw) }) }
	relayCtx, cancelRelay := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(2)

	// downstream -> upstream
	go func() {
		defer wg.Done()
		halfClosed := false
		for {
			select {
			case <-relayCtx.Done():
				return
			case f, ok := <-downCh:
				if !ok {
					if !halfClosed {
						_ = upStream.CloseWrite(context.Background())
					}
					if !halfClosed {
						cancelRelay()
					}
					return
				}
				if len(f.payload) > 0 {
					logTest("mux=%p stream=%d relay downstream payload len=%d", mm, streamID, len(f.payload))
					_ = upStream.Write(context.Background(), f.payload)
				}
				if f.flags&flagFINW != 0 {
					halfClosed = true
					_ = upStream.CloseWrite(context.Background())
					return
				}
				if f.flags&(flagFIN|flagRST) != 0 {
					closeFlags := uint8(flagFIN)
					if f.flags&flagRST != 0 {
						closeFlags = flagRST
					}
					_ = upStream.WriteFlags(context.Background(), closeFlags, f.payload)
					logTest("mux=%p stream=%d relay downstream fin/rst flags=%d", mm, streamID, f.flags)
					cancelRelay()
					return
				}
			case <-nextMux.Done():
				if !halfClosed {
					_ = upStream.CloseWrite(context.Background())
				}
				cancelRelay()
				return
			case <-mm.Done():
				if !halfClosed {
					_ = upStream.CloseWrite(context.Background())
				}
				cancelRelay()
				return
			}
		}
	}()

	// upstream -> downstream
	go func() {
		defer wg.Done()
		halfClosed := false
		for {
			select {
			case <-relayCtx.Done():
				return
			case f, ok := <-streamCh:
				if !ok {
					if !halfClosed {
						_ = downStream.CloseWrite(context.Background())
					}
					if !halfClosed {
						cancelRelay()
					}
					return
				}
				if len(f.payload) > 0 {
					logTest("mux=%p stream=%d relay upstream payload len=%d", mm, streamID, len(f.payload))
					_ = downStream.Write(context.Background(), f.payload)
				}
				if f.flags&flagFINW != 0 {
					halfClosed = true
					_ = downStream.CloseWrite(context.Background())
					return
				}
				if f.flags&(flagFIN|flagRST) != 0 {
					closeFlags := uint8(flagFIN)
					if f.flags&flagRST != 0 {
						closeFlags = flagRST
					}
					_ = downStream.WriteFlags(context.Background(), closeFlags, f.payload)
					logTest("mux=%p stream=%d relay upstream fin/rst flags=%d", mm, streamID, f.flags)
					cancelRelay()
					return
				}
			case <-nextMux.Done():
				if !halfClosed {
					_ = downStream.CloseWrite(context.Background())
				}
				cancelRelay()
				return
			case <-mm.Done():
				if !halfClosed {
					_ = downStream.CloseWrite(context.Background())
				}
				cancelRelay()
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		cancelRelay()
		release()
		t.unregisterRelayPair(mm, streamID, nextMux, downStream.ID())
	}()
}
