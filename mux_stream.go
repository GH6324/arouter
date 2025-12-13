package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// MuxStream represents a logical stream over a MuxConn.
type MuxStream struct {
	id     uint32
	m      *MuxConn
	mgr    *MuxManager
	closed atomic.Bool
}

// MuxManager manages streams on top of a MuxConn.
type MuxManager struct {
	mu        sync.Mutex
	m         *MuxConn
	nextID    uint32
	streams   map[uint32]*MuxStream
	recv      map[uint32]chan muxFrame
	defaultCh chan muxFrame
	shutdown  chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	readOnce  sync.Once
}

func NewMuxManager(m *MuxConn) *MuxManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &MuxManager{
		m:         m,
		nextID:    2, // start from 2, even numbers for initiator
		streams:   make(map[uint32]*MuxStream),
		recv:      make(map[uint32]chan muxFrame),
		defaultCh: make(chan muxFrame, 64),
		shutdown:  make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (mm *MuxManager) Close() {
	close(mm.shutdown)
	mm.m.Close()
	mm.cancel()
	mm.mu.Lock()
	for _, ch := range mm.recv {
		close(ch)
	}
	close(mm.defaultCh)
	mm.mu.Unlock()
}

func (mm *MuxManager) OpenStream() *MuxStream {
	mm.mu.Lock()
	id := mm.nextID
	mm.nextID += 2
	s := &MuxStream{id: id, m: mm.m, mgr: mm}
	mm.streams[id] = s
	if _, ok := mm.recv[id]; !ok {
		mm.recv[id] = make(chan muxFrame, 16)
	}
	mm.mu.Unlock()
	mm.ensureReader()
	return s
}

func (mm *MuxManager) Conn() *MuxConn {
	return mm.m
}

func (mm *MuxManager) ensureReader() {
	mm.readOnce.Do(func() {
		go mm.readLoop()
	})
}

// Done is closed when mux manager stops.
func (mm *MuxManager) Done() <-chan struct{} {
	return mm.ctx.Done()
}

func (mm *MuxManager) readLoop() {
	defer mm.Close()
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
			_ = mm.m.WriteFrame(mm.ctx, muxFrame{flags: flagPONG})
		}
		mm.mu.Lock()
		ch := mm.recv[f.streamID]
		if ch != nil {
			ch <- f
			if f.flags&(flagFIN|flagRST) != 0 {
				close(ch)
				delete(mm.recv, f.streamID)
			}
		} else {
			// 如果无人订阅默认通道则丢弃，避免阻塞 readLoop
			select {
			case mm.defaultCh <- f:
			default:
			}
		}
		mm.mu.Unlock()
	}
}

func (s *MuxStream) ID() uint32 { return s.id }

func (s *MuxStream) Close(ctx context.Context) error {
	if s.closed.CompareAndSwap(false, true) {
		return s.m.WriteFrame(ctx, muxFrame{flags: flagFIN, streamID: s.id})
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
	if s.closed.Load() {
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
		ch = make(chan muxFrame, 16)
		mm.recv[streamID] = ch
	}
	mm.mu.Unlock()
	mm.ensureReader()
	return ch
}

func (mm *MuxManager) subscribeDefault() <-chan muxFrame {
	mm.ensureReader()
	return mm.defaultCh
}
