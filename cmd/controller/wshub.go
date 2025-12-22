package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	wscompat "arouter/internal/wscompat"
)

// wsHub 维护节点 WS 连接，供控制器主动下发指令。
type wsHub struct {
	mu    sync.Mutex
	conns map[string]*wscompat.Conn
}

func newWSHub() *wsHub {
	return &wsHub{conns: make(map[string]*wscompat.Conn)}
}

func (h *wsHub) register(node string, c *wscompat.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, ok := h.conns[node]; ok && old != c {
		old.Close()
	}
	h.conns[node] = c
}

func (h *wsHub) unregister(node string, c *wscompat.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur, ok := h.conns[node]; ok && cur == c {
		delete(h.conns, node)
	}
}

func (h *wsHub) sendCommand(node string, cmd interface{}) error {
	h.mu.Lock()
	c := h.conns[node]
	h.mu.Unlock()
	if c == nil {
		return fmt.Errorf("node %s offline", node)
	}
	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, wscompat.MessageText, data); err != nil {
		return err
	}
	return nil
}
