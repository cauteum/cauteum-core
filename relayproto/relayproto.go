// Package relayproto is the wire contract for the gateway supervisor relay
// (OpenShell ConnectSupervisor / RelayOpen / RelayStream / ForwardTcp).
//
// All streams are HTTP/1.1 Upgrade connections carrying raw bytes, so the relay
// works over plain HTTP and TLS without extra dependencies:
//
//   - Supervisor control: GET PathSupervisorConnect?sandbox=NAME (sandbox token).
//     The gateway writes newline-delimited JSON Messages ("open", "ping"); the
//     supervisor answers "hello" / "pong".
//   - Supervisor data: GET PathSupervisorRelay+CHANNEL (sandbox token) after an
//     "open" message; the supervisor pipes it to the sandbox SSH socket.
//   - Client tunnel: GET PathSSHConnect with HeaderSandboxID and an SSH session
//     token; the gateway bridges it to a fresh supervisor data stream.
//
// The sandbox never accepts inbound connections: every stream is dialed out by
// the supervisor or by the client towards the gateway.
package relayproto

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// UpgradeProtocol is the HTTP Upgrade token for every relay stream.
	UpgradeProtocol = "whaleshell-relay/1"

	PathSupervisorConnect = "/v1/supervisor/connect"
	PathSupervisorRelay   = "/v1/supervisor/relay/"
	PathSSHConnect        = "/v1/ssh/connect"

	// HeaderSandboxID names the target sandbox (name or id) on PathSSHConnect.
	HeaderSandboxID = "X-Whaleshell-Sandbox-Id"

	// TargetSSH asks the supervisor to dial the sandbox SSH socket.
	TargetSSH = "ssh"

	// KeepaliveInterval is how often the gateway pings the supervisor.
	KeepaliveInterval = 15 * time.Second
	// KeepaliveTimeout closes a control stream that stayed silent this long.
	KeepaliveTimeout = 45 * time.Second

	maxMessageBytes = 64 << 10
	maxErrorBody    = 4 << 10
)

// Message types on the supervisor control stream.
const (
	MsgHello = "hello"
	MsgOpen  = "open"
	MsgPing  = "ping"
	MsgPong  = "pong"
)

// Message is one control-stream frame (newline-delimited JSON).
type Message struct {
	Type    string `json:"type"`
	Channel string `json:"channel,omitempty"`
	Target  string `json:"target,omitempty"`
	Sandbox string `json:"sandbox,omitempty"`
}

// StatusError is a non-101 response to an Upgrade request.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("relay upgrade: %d %s", e.Code, http.StatusText(e.Code))
	}
	return fmt.Sprintf("relay upgrade: %d %s: %s", e.Code, http.StatusText(e.Code), e.Body)
}

// DialOptions tune Dial.
type DialOptions struct {
	Header    http.Header
	TLSConfig *tls.Config // cloned; NextProtos forced to http/1.1
	Timeout   time.Duration
}

// Dial opens an Upgrade stream to baseURL+path (path may carry a query).
func Dial(ctx context.Context, baseURL, path string, opt DialOptions) (net.Conn, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("relay dial: %w", err)
	}
	host := u.Host
	if u.Port() == "" {
		switch u.Scheme {
		case "https":
			host = net.JoinHostPort(u.Hostname(), "443")
		case "http":
			host = net.JoinHostPort(u.Hostname(), "80")
		default:
			return nil, fmt.Errorf("relay dial: unsupported scheme %q", u.Scheme)
		}
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	d := net.Dialer{Timeout: timeout, KeepAlive: tcpKeepaliveInterval}
	raw, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("relay dial %s: %w", host, err)
	}
	conn := raw
	if u.Scheme == "https" {
		cfg := &tls.Config{}
		if opt.TLSConfig != nil {
			cfg = opt.TLSConfig.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = u.Hostname()
		}
		cfg.NextProtos = []string{"http/1.1"}
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("relay tls: %w", err)
		}
		conn = tc
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	fullPath := strings.TrimRight(u.Path, "/") + path
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", fullPath)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Upgrade: %s\r\n", UpgradeProtocol)
	for k, vs := range opt.Header {
		for _, v := range vs {
			if strings.ContainsAny(k+v, "\r\n") {
				_ = conn.Close()
				return nil, fmt.Errorf("relay dial: invalid header %q", k)
			}
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("relay dial: write request: %w", err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("relay dial: read response: %w", err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(res.Body, maxErrorBody))
		_ = res.Body.Close()
		_ = conn.Close()
		return nil, &StatusError{Code: res.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if !strings.EqualFold(res.Header.Get("Upgrade"), UpgradeProtocol) {
		_ = conn.Close()
		return nil, fmt.Errorf("relay dial: unexpected upgrade %q", res.Header.Get("Upgrade"))
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, nil
}

// IsUpgrade reports whether r asks for a relay Upgrade.
func IsUpgrade(r *http.Request) bool {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), UpgradeProtocol) {
		return false
	}
	for v := range strings.SplitSeq(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

// Accept completes the server side of an Upgrade and returns the raw stream.
func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return nil, errors.New("relay accept: method not allowed")
	}
	if !IsUpgrade(r) {
		w.Header().Set("Upgrade", UpgradeProtocol)
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
		return nil, errors.New("relay accept: upgrade required")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return nil, errors.New("relay accept: hijack unsupported")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("relay accept: hijack: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	resp := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + UpgradeProtocol + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &bufferedConn{Conn: conn, r: rw.Reader}, nil
}

// bufferedConn drains bytes already buffered during the handshake first.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite half-closes when the underlying stream supports it.
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// MessageWriter serializes Messages onto a control stream.
type MessageWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewMessageWriter wraps w.
func NewMessageWriter(w io.Writer) *MessageWriter { return &MessageWriter{w: w} }

// Write sends one Message.
func (mw *MessageWriter) Write(m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	mw.mu.Lock()
	defer mw.mu.Unlock()
	_, err = mw.w.Write(b)
	return err
}

// MessageReader parses Messages from a control stream.
type MessageReader struct {
	sc *bufio.Scanner
}

// NewMessageReader wraps r.
func NewMessageReader(r io.Reader) *MessageReader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxMessageBytes)
	return &MessageReader{sc: sc}
}

// Read returns the next Message (io.EOF at end of stream).
func (mr *MessageReader) Read() (Message, error) {
	for mr.sc.Scan() {
		line := strings.TrimSpace(mr.sc.Text())
		if line == "" {
			continue
		}
		var m Message
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return Message{}, fmt.Errorf("relay message: %w", err)
		}
		return m, nil
	}
	if err := mr.sc.Err(); err != nil {
		return Message{}, err
	}
	return Message{}, io.EOF
}

// Pipe copies bytes both ways until both directions finish, half-closing
// writers on EOF, then closes both streams. Non-terminal copy and close errors
// are joined and returned so the caller can log them with operation context.
func Pipe(a, b io.ReadWriteCloser) error {
	pipeErrors := make(chan error, 6)
	report := func(op string, err error) {
		if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
			return
		}
		pipeErrors <- fmt.Errorf("%s: %w", op, err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(direction string, dst, src io.ReadWriteCloser) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		report("copy "+direction, err)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			report("half-close "+direction, cw.CloseWrite())
		} else {
			report("close "+direction, dst.Close())
		}
	}
	go cp("a-to-b", b, a)
	go cp("b-to-a", a, b)
	wg.Wait()
	report("close stream a", a.Close())
	report("close stream b", b.Close())
	close(pipeErrors)

	var err error
	for pipeErr := range pipeErrors {
		err = errors.Join(err, pipeErr)
	}
	return err
}
