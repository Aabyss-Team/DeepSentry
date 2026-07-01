package builtin

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSocks5ProxyConnectNoAuth(t *testing.T) {
	target := startTestTCPResponder(t)
	out, err := Socks5Proxy(Runtime{}, "start", "127.0.0.1", "0", "", "", false)
	if err != nil {
		if isListenUnavailable(err) {
			t.Skipf("local proxy listen unavailable in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	listen := findForwardListen(t, "socks5_proxy")
	t.Cleanup(func() { _, _ = stopForward(Runtime{}, listenPort(listen)) })
	if !strings.Contains(out, "SOCKS5") {
		t.Fatalf("unexpected start output: %s", out)
	}

	conn, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string([]byte{0x05, 0x00}) {
		t.Fatalf("bad method reply: %v", buf)
	}
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host).To4()
	req := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("bad connect reply: %v", reply)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Fatalf("got %q, want pong", got)
	}
}

func TestSocks5ProxyRejectsLanListenByDefault(t *testing.T) {
	_, err := Socks5Proxy(Runtime{}, "start", "0.0.0.0", "0", "", "", false)
	if err == nil || !strings.Contains(err.Error(), "allow_lan") {
		t.Fatalf("expected allow_lan error, got %v", err)
	}
}

func TestTCPForwardSupportsEphemeralListenPort(t *testing.T) {
	target := startTestTCPResponder(t)
	host, port, _ := net.SplitHostPort(target)
	out, err := TCPForward(Runtime{}, "start", "127.0.0.1", "0", host, port)
	if err != nil {
		if isListenUnavailable(err) {
			t.Skipf("local forward listen unavailable in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	listen := findForwardListen(t, "tcp_forward")
	t.Cleanup(func() { _, _ = stopForward(Runtime{}, listenPort(listen)) })
	if !strings.Contains(out, "TCP 转发已启动") || strings.Contains(out, "listen: 127.0.0.1:0") {
		t.Fatalf("unexpected forward output: %s", out)
	}
	conn, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Fatalf("got %q, want pong", got)
	}
}

func startTestTCPResponder(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if isListenUnavailable(err) {
			t.Skipf("local listen unavailable in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4)
				_, _ = io.ReadFull(c, buf)
				_, _ = c.Write([]byte("pong"))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func findForwardListen(t *testing.T, kind string) string {
	t.Helper()
	forwardManager.Lock()
	defer forwardManager.Unlock()
	for _, s := range forwardManager.items {
		if s.Kind == kind {
			return s.Listen
		}
	}
	t.Fatalf("no forward session kind=%s; sessions=%v", kind, forwardManager.items)
	return ""
}

func listenPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Sprintf("%s", addr)
	}
	return port
}

func isListenUnavailable(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "operation not permitted") || strings.Contains(s, "permission denied")
}
