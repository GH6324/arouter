package wscompat

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// 状态码映射
const (
	StatusNormalClosure   = websocket.CloseNormalClosure
	StatusInternalError   = websocket.CloseInternalServerErr
	StatusUnsupportedData = websocket.CloseUnsupportedData
	StatusPolicyViolation = websocket.ClosePolicyViolation
)

// MessageType 映射
const (
	MessageText   = websocket.TextMessage
	MessageBinary = websocket.BinaryMessage
)

type Conn struct {
	*websocket.Conn
}

type DialOptions struct {
	HTTPHeader      http.Header
	HTTPClient      *http.Client
	TLSClientConfig *tls.Config
	NetDialContext  func(ctx context.Context, network, addr string) (net.Conn, error)
}

type AcceptOptions struct {
	EnableCompression bool
}

func Dial(ctx context.Context, url string, opts *DialOptions) (*Conn, *http.Response, error) {
	d := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	var hdr http.Header
	if opts != nil {
		if opts.HTTPHeader != nil {
			hdr = opts.HTTPHeader
		}
		if opts.TLSClientConfig != nil {
			d.TLSClientConfig = opts.TLSClientConfig
		}
		if opts.NetDialContext != nil {
			d.NetDialContext = opts.NetDialContext
		}
		if opts.HTTPClient != nil {
			if t, ok := opts.HTTPClient.Transport.(*http.Transport); ok {
				if d.TLSClientConfig == nil {
					d.TLSClientConfig = t.TLSClientConfig
				}
				d.Proxy = t.Proxy
			}
		}
	}
	conn, resp, err := d.DialContext(ctx, url, hdr)
	if err != nil {
		return nil, resp, err
	}
	return &Conn{Conn: conn}, resp, nil
}

func Accept(w http.ResponseWriter, r *http.Request, opts *AcceptOptions) (*Conn, error) {
	up := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool { return true },
	}
	// Compression 控制：gorilla 默认开启，手动关闭
	up.EnableCompression = opts != nil && opts.EnableCompression
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	if up.EnableCompression {
		conn.EnableWriteCompression(true)
	}
	return &Conn{Conn: conn}, nil
}

// Ping with context timeout.
func (c *Conn) Ping(ctx context.Context) error {
	if c == nil {
		return net.ErrClosed
	}
	deadline, ok := ctx.Deadline()
	if ok {
		_ = c.SetWriteDeadline(deadline)
		defer c.SetWriteDeadline(time.Time{})
	}
	return c.WriteControl(websocket.PingMessage, nil, deadline)
}

// Read mimics nhooyr interface: returns message type, data, error.
func (c *Conn) Read(ctx context.Context) (int, []byte, error) {
	if c == nil {
		return 0, nil, net.ErrClosed
	}
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	mt, data, err := c.ReadMessage()
	return mt, data, err
}

// Write mimics nhooyr interface.
func (c *Conn) Write(ctx context.Context, msgType int, data []byte) error {
	if c == nil {
		return net.ErrClosed
	}
	deadline, ok := ctx.Deadline()
	if ok {
		_ = c.SetWriteDeadline(deadline)
		defer c.SetWriteDeadline(time.Time{})
	}
	return c.WriteMessage(msgType, data)
}

// WriteBinaryv writes a single binary websocket message composed of multiple byte slices
// without concatenating them into a single buffer.
func (c *Conn) WriteBinaryv(ctx context.Context, parts ...[]byte) error {
	if c == nil {
		return net.ErrClosed
	}
	deadline, ok := ctx.Deadline()
	if ok {
		_ = c.SetWriteDeadline(deadline)
		defer c.SetWriteDeadline(time.Time{})
	}
	w, err := c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return err
	}
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		if _, err := w.Write(p); err != nil {
			_ = w.Close()
			return err
		}
	}
	return w.Close()
}

// NetConn 兼容 nhooyr 的 NetConn 用法。
func NetConn(ctx context.Context, c *Conn, msgType int) net.Conn {
	if c == nil {
		return nil
	}

	return c.NetConn()
	//return websocket.NetConn(ctx, c.Conn, msgType)
}
