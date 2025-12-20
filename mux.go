package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"arouter/internal/wscompat"
)

// 协议多路复用帧格式：
// | ver:1 | flags:1 | stream_id:4 (BE) | len:4 (BE) | payload... |
const (
	muxVersion = 1
	flagFIN    = 1 << 0
	flagRST    = 1 << 1
	flagPING   = 1 << 2
	flagPONG   = 1 << 3
	flagCTRL   = 1 << 4 // payload 为控制信息（header/ack/error/probe 等）
	// flagFINW indicates the sender has closed its write side (half-close).
	// The receiver should treat it as EOF for Read(), while keeping its own write side usable.
	flagFINW = 1 << 5
)

type muxFrame struct {
	version  uint8
	flags    uint8
	streamID uint32
	payload  []byte
}

type MuxConn struct {
	ws     *wscompat.Conn
	closed atomic.Bool
	wmu    sync.Mutex
}

func NewMuxConn(ws *wscompat.Conn) *MuxConn {
	return &MuxConn{ws: ws}
}

func (m *MuxConn) Close() {
	if m.closed.CompareAndSwap(false, true) {
		m.ws.Close()
	}
}

func (m *MuxConn) WriteFrame(ctx context.Context, f muxFrame) error {
	if m.closed.Load() {
		return fmt.Errorf("mux closed")
	}
	if f.version == 0 {
		f.version = muxVersion
	}
	m.wmu.Lock()
	defer m.wmu.Unlock()
	var header [10]byte // 1+1+4+4
	header[0] = f.version
	header[1] = f.flags
	binary.BigEndian.PutUint32(header[2:], f.streamID)
	binary.BigEndian.PutUint32(header[6:], uint32(len(f.payload)))
	return m.ws.WriteBinaryv(ctx, header[:], f.payload)
}

func (m *MuxConn) ReadFrame(ctx context.Context) (muxFrame, error) {
	if m.closed.Load() {
		return muxFrame{}, fmt.Errorf("mux closed")
	}
	typ, data, err := m.ws.Read(ctx)
	if err != nil {
		return muxFrame{}, err
	}
	if typ != wscompat.MessageBinary {
		_ = m.ws.Close()
		return muxFrame{}, fmt.Errorf("unexpected ws message type %v", typ)
	}
	if len(data) < 10 {
		return muxFrame{}, fmt.Errorf("frame too short")
	}
	f := muxFrame{
		version:  data[0],
		flags:    data[1],
		streamID: binary.BigEndian.Uint32(data[2:6]),
	}
	payloadLen := binary.BigEndian.Uint32(data[6:10])
	if int(payloadLen) != len(data)-10 {
		return muxFrame{}, fmt.Errorf("frame len mismatch: %d vs %d", payloadLen, len(data)-10)
	}
	f.payload = data[10:]
	return f, nil
}

// KeepAlive 在 mux 上定期发送 ping。
func (m *MuxConn) KeepAlive(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = m.WriteFrame(ctx, muxFrame{flags: flagPING})
		}
	}
}

// Ping wraps websocket Ping with write mutex to avoid concurrent write conflicts.
func (m *MuxConn) Ping(ctx context.Context) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	return m.ws.Ping(ctx)
}
