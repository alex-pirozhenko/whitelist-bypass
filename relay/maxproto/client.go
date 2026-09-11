package maxproto

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/google/uuid"
)

var AndroidUA = map[string]any{
	"deviceType":     "ANDROID",
	"pushDeviceType": "GCM",
	"appVersion":     "26.30.1",
	"buildNumber":    6819,
	"osVersion":      "14",
	"arch":           "arm64-v8a",
	"locale":         "ru",
	"deviceLocale":   "en",
	"deviceName":     "Pixel 8",
	"screen":         "2400x1080 2.625",
	"timezone":       "Europe/Moscow",
}

// WebUA identifies the connection as the WEB platform. Required for the QR
// login-track creation (op288), which the server refuses on an ANDROID session.
var WebUA = map[string]any{
	"deviceType":      "WEB",
	"pushDeviceType":  "WEBPUSH",
	"locale":          "ru",
	"deviceLocale":    "en",
	"osVersion":       "macOS",
	"deviceName":      "Chrome",
	"headerUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	"isPwa":           false,
	"appVersion":      "26.9.4",
	"screen":          "1080x1920 2.0x",
	"timezone":        "Europe/Moscow",
}

type ResolveFunc func(host string) (ip string, err error)

type reply struct {
	cmd     byte
	payload any
}

type Client struct {
	token    string
	deviceID string
	ua       map[string]any // SessionInit userAgent; AndroidUA by default, WebUA for QR web legs

	conn    net.Conn
	seq     uint16
	pending map[uint16]chan reply
	mu      sync.Mutex
	writeMu sync.Mutex
}

func New(token, deviceID string) *Client {
	if deviceID == "" {
		deviceID = uuid.NewString()
	}
	return &Client{
		token:    token,
		deviceID: deviceID,
		ua:       AndroidUA,
		pending:  make(map[uint16]chan reply),
	}
}

// NewWeb builds a client that identifies as the WEB platform in SessionInit.
// The QR login-track creation (op288) is refused ("qr_login.disabled") on an
// ANDROID-identified connection — that opcode is the web/PWA client's, so the
// web leg of DeriveWebSession must session-init as WEB.
func NewWeb(token, deviceID string) *Client {
	c := New(token, deviceID)
	c.ua = WebUA
	return c
}

// DeviceID returns the device ID the client was constructed with, or the
// randomly generated one if New was called with an empty deviceID.
func (c *Client) DeviceID() string {
	return c.deviceID
}

func (c *Client) Connect(ctx context.Context, resolve ResolveFunc) error {
	host := "api2.oneme.ru"
	port := "443"
	targetAddr := net.JoinHostPort(host, port)

	if resolve != nil {
		ip, err := resolve(host)
		if err != nil {
			return fmt.Errorf("failed to resolve host %s: %w", host, err)
		}
		targetAddr = net.JoinHostPort(ip, port)
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %w", targetAddr, err)
	}

	// api2.oneme.ru is issued under the Russian Trusted CA hierarchy, which is
	// not in the system root store. Rather than disabling verification, trust
	// ONLY that one CA, and only here: onemeRoots is a private pool scoped to
	// this dialer, so the Russian CA is never added to the system or process
	// trust store and cannot affect any other TLS connection. Hostname
	// verification still applies.
	roots, err := onemeRoots()
	if err != nil {
		conn.Close()
		return fmt.Errorf("max ca pool: %w", err)
	}
	tlsConfig := &tls.Config{
		ServerName: host,
		RootCAs:    roots,
	}

	tlsConn := tls.Client(conn, tlsConfig)

	errCh := make(chan error, 1)
	go func() {
		errCh <- tlsConn.HandshakeContext(ctx)
	}()

	select {
	case <-ctx.Done():
		conn.Close()
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			conn.Close()
			return fmt.Errorf("tls handshake failed: %w", err)
		}
	}

	c.mu.Lock()
	c.conn = tlsConn
	c.mu.Unlock()

	go c.readLoop()

	return nil
}

func (c *Client) readLoop() {
	header := make([]byte, 10)
	for {
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn == nil {
			return
		}

		_, err := io.ReadFull(conn, header)
		if err != nil {
			c.handleDisconnect(err)
			return
		}

		payloadLen := (int(header[7]) << 16) | (int(header[8]) << 8) | int(header[9])
		var data []byte
		if payloadLen > 0 {
			payloadBuf := make([]byte, payloadLen)
			_, err = io.ReadFull(conn, payloadBuf)
			if err != nil {
				c.handleDisconnect(err)
				return
			}
			data = make([]byte, 10+payloadLen)
			copy(data[0:10], header)
			copy(data[10:], payloadBuf)
		} else {
			data = make([]byte, 10)
			copy(data[0:10], header)
		}

		cmd, seq, opcode, payload, err := decodeMsg(data)
		if err != nil {
			continue
		}

		c.dispatch(cmd, seq, opcode, payload)
	}
}

func (c *Client) handleDisconnect(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	for seq, ch := range c.pending {
		delete(c.pending, seq)
		ch <- reply{
			cmd: 3,
			payload: map[string]any{
				"error":            "connection_closed",
				"localizedMessage": fmt.Sprintf("connection closed: %v", err),
			},
		}
		close(ch)
	}
}

func (c *Client) dispatch(cmd byte, seq uint16, opcode uint16, payload any) {
	if cmd == 1 || cmd == 3 {
		c.mu.Lock()
		ch, ok := c.pending[seq]
		if ok {
			delete(c.pending, seq)
			c.mu.Unlock()
			ch <- reply{cmd: cmd, payload: payload}
			close(ch)
			return
		}
		c.mu.Unlock()
	}

	c.handlePush(cmd, seq, opcode, payload)
}

func (c *Client) handlePush(cmd byte, seq uint16, opcode uint16, payload any) {
	if cmd == 0 && opcode == 1 {
		_ = c.sendRaw(1, seq, 1, nil)
	}
}

func (c *Client) nextSeq() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	seq := c.seq
	c.seq = (c.seq + 1) & 0x7FFF
	return seq
}

func (c *Client) sendRaw(cmd byte, seq uint16, opcode uint16, payload any) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return errors.New("not connected")
	}

	data, err := encodeMsg(cmd, seq, opcode, payload)
	if err != nil {
		return err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err = conn.Write(data)
	return err
}

func (c *Client) Cmd(ctx context.Context, opcode uint16, payload any) (any, error) {
	seq := c.nextSeq()
	ch := make(chan reply, 1)

	c.mu.Lock()
	c.pending[seq] = ch
	c.mu.Unlock()

	err := c.sendRaw(0, seq, opcode, payload)
	if err != nil {
		c.mu.Lock()
		delete(c.pending, seq)
		c.mu.Unlock()
		return nil, fmt.Errorf("failed to send command %d: %w", opcode, err)
	}

	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, seq)
		c.mu.Unlock()
		return nil, ctx.Err()
	case r := <-ch:
		if r.cmd == 3 {
			errMsg := "?"
			locMsg := ""
			if m, ok := r.payload.(map[string]any); ok {
				if e, exists := m["error"]; exists {
					errMsg = fmt.Sprintf("%v", e)
				}
				if lm, exists := m["localizedMessage"]; exists {
					locMsg = fmt.Sprintf("%v", lm)
				} else if msg, exists := m["message"]; exists {
					locMsg = fmt.Sprintf("%v", msg)
				}
			}
			return nil, fmt.Errorf("Server error on opcode %d: %s — %s", opcode, errMsg, locMsg)
		}
		return r.payload, nil
	}
}

func (c *Client) SessionInit(ctx context.Context) (map[string]any, error) {
	ua := c.ua
	if ua == nil {
		ua = AndroidUA
	}
	payload := map[string]any{
		"userAgent": ua,
		"deviceId":  c.deviceID,
	}
	resp, err := c.Cmd(ctx, 6, payload)
	if err != nil {
		return nil, err
	}
	m, ok := resp.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected SessionInit response type: %T", resp)
	}
	return m, nil
}

func (c *Client) Login(ctx context.Context) (map[string]any, error) {
	payload := map[string]any{
		"token":       c.token,
		"interactive": true,
	}
	resp, err := c.Cmd(ctx, 19, payload)
	if err != nil {
		return nil, err
	}
	m, ok := resp.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected Login response type: %T", resp)
	}
	return m, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()

	if conn != nil {
		err := conn.Close()
		c.handleDisconnect(fmt.Errorf("client closed"))
		return err
	}
	return nil
}
