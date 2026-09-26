package relayproto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func echoServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ok" {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		conn, err := Accept(w, r)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}))
}

func TestDialAcceptEcho(t *testing.T) {
	srv := echoServer(t)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, srv.URL, "/x?y=1", DialOptions{Header: http.Header{"Authorization": {"Bearer ok"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("hello relay")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo = %q", buf)
	}
}

func TestDialNon101ReturnsStatusError(t *testing.T) {
	srv := echoServer(t)
	defer srv.Close()
	_, err := Dial(context.Background(), srv.URL, "/x", DialOptions{})
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Fatalf("err = %v, want 401 StatusError", err)
	}
	if !strings.Contains(se.Body, "nope") {
		t.Fatalf("body = %q", se.Body)
	}
}

func TestAcceptRejectsPlainGET(t *testing.T) {
	srv := echoServer(t)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer ok")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

func TestDialRejectsHeaderInjection(t *testing.T) {
	srv := echoServer(t)
	defer srv.Close()
	_, err := Dial(context.Background(), srv.URL, "/x", DialOptions{Header: http.Header{"X-A": {"v\r\nEvil: 1"}}})
	if err == nil || !strings.Contains(err.Error(), "invalid header") {
		t.Fatalf("err = %v", err)
	}
}

func TestMessageRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewMessageWriter(&buf)
	in := []Message{{Type: MsgHello, Sandbox: "a"}, {Type: MsgOpen, Channel: "c1", Target: TargetSSH}, {Type: MsgPing}}
	for _, m := range in {
		if err := w.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	r := NewMessageReader(&buf)
	for i, want := range in {
		got, err := r.Read()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if got != want {
			t.Fatalf("msg %d = %+v, want %+v", i, got, want)
		}
	}
	if _, err := r.Read(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestPipeBridgesBothWays(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		Pipe(a2, b1)
		close(done)
	}()
	go func() {
		buf := make([]byte, 4)
		_, _ = io.ReadFull(b2, buf)
		_, _ = b2.Write(bytes.ToUpper(buf))
		_ = b2.Close()
	}()
	if _, err := a1.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(a1, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "PING" {
		t.Fatalf("got %q", buf)
	}
	_ = a1.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe did not finish")
	}
}
