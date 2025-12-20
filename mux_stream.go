package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// MuxStream represents a logical stream over a MuxConn.
type MuxStream struct {
	id          uint32
	m           *MuxConn
	mgr         *MuxManager
	closed      atomic.Bool
	writeClosed atomic.Bool
}

// MuxManager manages streams on top of a MuxConn.
type MuxManager struct {
	mu        sync.Mutex
	m         *MuxConn
	nextID    uint32
	streams   map[uint32]*MuxStream
	recv      map[uint32]chan muxFrame
	defaultCh chan muxFrame
	ctx       context.Context
	cancel    context.CancelFunc
	pongCh    chan []byte

	stopOnce  sync.Once
	finalOnce sync.Once
	done      chan struct{}

	cfg MuxConfig
}

type MuxConfig struct {
	DefaultQueue int
	StreamQueue  int
	// BlockOnBackpressure blocks the reader when queues are full, applying TCP backpressure.
	// This is recommended when a mux connection only carries a single busy stream (e.g. iperf3).
	BlockOnBackpressure bool
}

func NewMuxManager(m *MuxConn) *MuxManager {
	return NewMuxManagerWithConfig(m, MuxConfig{})
}

func NewMuxManagerWithConfig(m *MuxConn, cfg MuxConfig) *MuxManager {
	ctx, cancel := context.WithCancel(context.Background())
	if cfg.DefaultQueue <= 0 {
		cfg.DefaultQueue = 256
	}
	if cfg.StreamQueue <= 0 {
		cfg.StreamQueue = 64
	}
	mm := &MuxManager{
		m:         m,
		nextID:    2, // start from 2, even numbers for initiator
		streams:   make(map[uint32]*MuxStream),
		recv:      make(map[uint32]chan muxFrame),
		defaultCh: make(chan muxFrame, cfg.DefaultQueue),
		ctx:       ctx,
		cancel:    cancel,
		pongCh:    make(chan []byte, 8),
		done:      make(chan struct{}),
		cfg:       cfg,
	}
	go mm.readLoop()
	return mm
}

func (mm *MuxManager) Close() {
	mm.stopOnce.Do(func() {
		mm.cancel()
		mm.m.Close()
	})
}

func (mm *MuxManager) OpenStream() *MuxStream {
	mm.mu.Lock()
	id := mm.nextID
	mm.nextID += 2
	s := &MuxStream{id: id, m: mm.m, mgr: mm}
	mm.streams[id] = s
	if _, ok := mm.recv[id]; !ok {
		mm.recv[id] = make(chan muxFrame, mm.cfg.StreamQueue)
	}
	mm.mu.Unlock()
	return s
}

func (mm *MuxManager) Conn() *MuxConn {
	return mm.m
}

// Done is closed when mux manager stops.
func (mm *MuxManager) Done() <-chan struct{} {
	return mm.done
}

func (mm *MuxManager) readLoop() {
	defer mm.finalize()
	for {
		select {
		case <-mm.ctx.Done():
			return
		default:
		}
		f, err := mm.m.ReadFrame(mm.ctx)
		if err != nil {
			return
		}
		if f.flags&flagPING != 0 {
			_ = mm.m.WriteFrame(mm.ctx, muxFrame{flags: flagPONG, payload: f.payload})
			continue
		}
		if f.flags&flagPONG != 0 {
			if len(f.payload) == 8 {
				select {
				case mm.pongCh <- f.payload:
				default:
				}
			}
			continue
		}

		var ch chan muxFrame
		mm.mu.Lock()
		ch = mm.recv[f.streamID]
		mm.mu.Unlock()

		if ch != nil {
			if mm.cfg.BlockOnBackpressure {
				select {
				case ch <- f:
				case <-mm.ctx.Done():
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
			if f.flags&flagFINW != 0 {
				mm.mu.Lock()
				if cur := mm.recv[f.streamID]; cur == ch {
					close(ch)
					delete(mm.recv, f.streamID)
				}
				mm.mu.Unlock()
				continue
			}
			if f.flags&(flagFIN|flagRST) != 0 {
				mm.mu.Lock()
				if cur := mm.recv[f.streamID]; cur == ch {
					close(ch)
					delete(mm.recv, f.streamID)
				}
				delete(mm.streams, f.streamID)
				mm.mu.Unlock()
			}
			continue
		}

		// 控制帧等会先落到 defaultCh，这里阻塞发送，除非整体关闭
		if mm.cfg.BlockOnBackpressure {
			select {
			case mm.defaultCh <- f:
			case <-mm.ctx.Done():
				return
			}
		} else {
			select {
			case mm.defaultCh <- f:
			default:
				if f.flags&flagCTRL != 0 {
					mm.Close()
					return
				}
				mm.resetStream(f.streamID)
				continue
			}
		}
	}
}

func (mm *MuxManager) resetStream(streamID uint32) {
	if mm == nil {
		return
	}
	if streamID == 0 {
		mm.Close()
		return
	}

	// Best-effort notify peer to stop sending.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_ = mm.m.WriteFrame(ctx, muxFrame{flags: flagRST, streamID: streamID})
	cancel()

	mm.mu.Lock()
	ch := mm.recv[streamID]
	if ch != nil {
		delete(mm.recv, streamID)
		close(ch)
	}
	delete(mm.streams, streamID)
	mm.mu.Unlock()
}

func (mm *MuxManager) finalize() {
	mm.finalOnce.Do(func() {
		mm.stopOnce.Do(func() {
			mm.cancel()
			mm.m.Close()
		})

		mm.mu.Lock()
		close(mm.defaultCh)
		mm.mu.Unlock()

		close(mm.done)
	})
}

func (mm *MuxManager) Ping(ctx context.Context) (time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if mm == nil {
		return 0, fmt.Errorf("mux manager is nil")
	}

	seq := uint64(time.Now().UnixNano())
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, seq)

	start := time.Now()
	if err := mm.m.WriteFrame(ctx, muxFrame{flags: flagPING, payload: payload}); err != nil {
		return 0, err
	}
	for {
		select {
		case p := <-mm.pongCh:
			if bytes.Equal(p, payload) {
				return time.Since(start), nil
			}
		case <-mm.Done():
			return 0, fmt.Errorf("mux closed")
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func (s *MuxStream) ID() uint32 { return s.id }

func (s *MuxStream) Close(ctx context.Context) error {
	if s.closed.CompareAndSwap(false, true) {
		return s.m.WriteFrame(ctx, muxFrame{flags: flagFIN, streamID: s.id})
	}
	return nil
}

func (s *MuxStream) CloseWrite(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.writeClosed.CompareAndSwap(false, true) {
		return s.m.WriteFrame(ctx, muxFrame{flags: flagFINW, streamID: s.id})
	}
	return nil
}

func (s *MuxStream) Reset(ctx context.Context) error {
	if s.closed.CompareAndSwap(false, true) {
		return s.m.WriteFrame(ctx, muxFrame{flags: flagRST, streamID: s.id})
	}
	return nil
}

func (s *MuxStream) Write(ctx context.Context, payload []byte) error {
	if s.closed.Load() || s.writeClosed.Load() {
		return fmt.Errorf("stream closed")
	}
	return s.m.WriteFrame(ctx, muxFrame{streamID: s.id, payload: payload})
}

// MessageChan allows receiving frames for a stream.
type MessageChan chan muxFrame

func (s *MuxStream) WriteFlags(ctx context.Context, flags uint8, payload []byte) error {
	if s.closed.Load() {
		return fmt.Errorf("stream closed")
	}
	return s.m.WriteFrame(ctx, muxFrame{flags: flags, streamID: s.id, payload: payload})
}

func (mm *MuxManager) subscribe(streamID uint32) chan muxFrame {
	mm.mu.Lock()
	ch := mm.recv[streamID]
	if ch == nil {
		ch = make(chan muxFrame, mm.cfg.StreamQueue)
		mm.recv[streamID] = ch
	}
	mm.mu.Unlock()
	return ch
}

func (mm *MuxManager) subscribeDefault() <-chan muxFrame {
	return mm.defaultCh
}
