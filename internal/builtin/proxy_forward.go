package builtin

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type forwardSession struct {
	ID         string
	Kind       string
	Listen     string
	Target     string
	Auth       string
	StartedAt  time.Time
	BytesIn    int64
	BytesOut   int64
	ConnCount  int64
	Listener   net.Listener
	StopSignal chan struct{}
}

var forwardManager = struct {
	sync.Mutex
	items map[string]*forwardSession
}{items: map[string]*forwardSession{}}

func TCPForward(rt Runtime, action, listenHost, listenPort, targetHost, targetPort string) (string, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		action = "list"
	}
	switch action {
	case "start":
		return startForward(rt, listenHost, listenPort, targetHost, targetPort)
	case "list":
		return listForwards(rt), nil
	case "stop":
		return stopForward(rt, listenPort)
	default:
		return "", fmt.Errorf("action 仅支持 start|list|stop")
	}
}

func startForward(rt Runtime, listenHost, listenPort, targetHost, targetPort string) (string, error) {
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}
	lp, err := parseListenPort(listenPort)
	if err != nil {
		return "", err
	}
	tp, err := parseTCPPort(targetPort)
	if err != nil {
		return "", err
	}
	if err := validateHost(targetHost); err != nil {
		return "", err
	}
	listenAddr := net.JoinHostPort(listenHost, strconv.Itoa(lp))
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(tp))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", err
	}
	actualListen := ln.Addr().String()
	id := fmt.Sprintf("tcp:%s->%s", actualListen, targetAddr)
	sess := &forwardSession{ID: id, Kind: "tcp_forward", Listen: actualListen, Target: targetAddr, StartedAt: time.Now(), Listener: ln, StopSignal: make(chan struct{})}
	forwardManager.Lock()
	forwardManager.items[id] = sess
	forwardManager.Unlock()
	go serveForward(sess)
	return fmt.Sprintf("%s TCP 转发已启动\nid: %s\nlisten: %s\ntarget: %s\n说明: 进程退出或 stop 后关闭；无持久化/无反连控制面。", rt.tag(), id, actualListen, targetAddr), nil
}

func serveForward(sess *forwardSession) {
	for {
		conn, err := sess.Listener.Accept()
		if err != nil {
			return
		}
		go handleForwardConn(sess, conn)
	}
}

func handleForwardConn(sess *forwardSession, src net.Conn) {
	defer src.Close()
	dst, err := net.DialTimeout("tcp", sess.Target, 8*time.Second)
	if err != nil {
		return
	}
	defer dst.Close()
	forwardManager.Lock()
	sess.ConnCount++
	forwardManager.Unlock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(dst, src)
		forwardManager.Lock()
		sess.BytesOut += n
		forwardManager.Unlock()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(src, dst)
		forwardManager.Lock()
		sess.BytesIn += n
		forwardManager.Unlock()
	}()
	wg.Wait()
}

func listForwards(rt Runtime) string {
	forwardManager.Lock()
	defer forwardManager.Unlock()
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s 代理/转发会话列表\n", rt.tag()))
	if len(forwardManager.items) == 0 {
		b.WriteString("(无活动代理/转发)\n")
		return b.String()
	}
	keys := make([]string, 0, len(forwardManager.items))
	for k := range forwardManager.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := forwardManager.items[k]
		target := s.Target
		if target == "" {
			target = "dynamic"
		}
		auth := ""
		if s.Auth != "" {
			auth = " auth=" + s.Auth
		}
		b.WriteString(fmt.Sprintf("- id=%s kind=%s listen=%s target=%s%s uptime=%s conns=%d bytes_in=%d bytes_out=%d\n",
			s.ID, s.Kind, s.Listen, target, auth, time.Since(s.StartedAt).Round(time.Second), s.ConnCount, s.BytesIn, s.BytesOut))
	}
	return b.String()
}

func stopForward(rt Runtime, idOrPort string) (string, error) {
	forwardManager.Lock()
	defer forwardManager.Unlock()
	for id, s := range forwardManager.items {
		if id == idOrPort || strings.Contains(s.Listen, ":"+idOrPort) {
			_ = s.Listener.Close()
			delete(forwardManager.items, id)
			return fmt.Sprintf("%s 代理/转发已停止\nid: %s\nkind: %s\nlisten: %s\ntarget: %s", rt.tag(), id, s.Kind, s.Listen, s.Target), nil
		}
	}
	return "", fmt.Errorf("未找到转发: %s", idOrPort)
}

func Socks5Proxy(rt Runtime, action, listenHost, listenPort, username, password string, allowLAN bool) (string, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		action = "list"
	}
	switch action {
	case "start":
		return startSocks5Proxy(rt, listenHost, listenPort, username, password, allowLAN)
	case "list":
		return listForwards(rt), nil
	case "stop":
		return stopForward(rt, listenPort)
	default:
		return "", fmt.Errorf("action 仅支持 start|list|stop")
	}
}

func startSocks5Proxy(rt Runtime, listenHost, listenPort, username, password string, allowLAN bool) (string, error) {
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}
	if !allowLAN && !isLoopbackListenHost(listenHost) {
		return "", fmt.Errorf("SOCKS5 默认仅允许监听本机地址；如需局域网监听请显式设置 allow_lan=true")
	}
	if strings.TrimSpace(listenPort) == "" {
		listenPort = "1080"
	}
	if (username == "") != (password == "") {
		return "", fmt.Errorf("username/password 必须同时提供或同时留空")
	}
	lp, err := parseListenPort(listenPort)
	if err != nil {
		return "", err
	}
	listenAddr := net.JoinHostPort(listenHost, strconv.Itoa(lp))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", err
	}
	actualListen := ln.Addr().String()
	id := "socks5:" + actualListen
	auth := "none"
	if username != "" {
		auth = "username"
	}
	sess := &forwardSession{ID: id, Kind: "socks5_proxy", Listen: actualListen, Auth: auth, StartedAt: time.Now(), Listener: ln, StopSignal: make(chan struct{})}
	forwardManager.Lock()
	forwardManager.items[id] = sess
	forwardManager.Unlock()
	go serveSocks5Proxy(sess, username, password)
	return fmt.Sprintf("%s SOCKS5 代理已启动\nid: %s\nlisten: %s\nauth: %s\n说明: 仅支持 CONNECT；进程退出或 stop 后关闭；无持久化/无反连控制面。", rt.tag(), id, actualListen, auth), nil
}

func serveSocks5Proxy(sess *forwardSession, username, password string) {
	for {
		conn, err := sess.Listener.Accept()
		if err != nil {
			return
		}
		go handleSocks5Conn(sess, conn, username, password)
	}
}

func handleSocks5Conn(sess *forwardSession, src net.Conn, username, password string) {
	defer src.Close()
	_ = src.SetDeadline(time.Now().Add(15 * time.Second))
	if err := socks5Handshake(src, username, password); err != nil {
		return
	}
	targetAddr, err := readSocks5ConnectTarget(src)
	if err != nil {
		return
	}
	dst, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		_, _ = src.Write(socks5Reply(0x05, nil))
		return
	}
	defer dst.Close()
	_, _ = src.Write(socks5Reply(0x00, dst.LocalAddr()))
	_ = src.SetDeadline(time.Time{})
	_ = dst.SetDeadline(time.Time{})
	forwardManager.Lock()
	sess.ConnCount++
	forwardManager.Unlock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(dst, src)
		forwardManager.Lock()
		sess.BytesOut += n
		forwardManager.Unlock()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(src, dst)
		forwardManager.Lock()
		sess.BytesIn += n
		forwardManager.Unlock()
	}()
	wg.Wait()
}

func socks5Handshake(conn net.Conn, username, password string) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("not socks5")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	wantAuth := username != ""
	method := byte(0x00)
	if wantAuth {
		method = 0x02
	}
	if !bytesContains(methods, method) {
		_, _ = conn.Write([]byte{0x05, 0xff})
		return fmt.Errorf("unsupported auth method")
	}
	if _, err := conn.Write([]byte{0x05, method}); err != nil {
		return err
	}
	if !wantAuth {
		return nil
	}
	authHead := make([]byte, 2)
	if _, err := io.ReadFull(conn, authHead); err != nil {
		return err
	}
	if authHead[0] != 0x01 {
		return fmt.Errorf("unsupported username auth version")
	}
	user := make([]byte, int(authHead[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	passLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLen); err != nil {
		return err
	}
	pass := make([]byte, int(passLen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	if string(user) != username || string(pass) != password {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid username/password")
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func readSocks5ConnectTarget(conn net.Conn) (string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 {
		return "", fmt.Errorf("invalid socks version")
	}
	if head[1] != 0x01 {
		_, _ = conn.Write(socks5Reply(0x07, nil))
		return "", fmt.Errorf("SOCKS5 仅支持 CONNECT")
	}
	var host string
	switch head[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return "", err
		}
		name := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", err
		}
		host = string(name)
		if err := validateHost(host); err != nil {
			_, _ = conn.Write(socks5Reply(0x04, nil))
			return "", err
		}
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	default:
		_, _ = conn.Write(socks5Reply(0x08, nil))
		return "", fmt.Errorf("unsupported address type")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func socks5Reply(code byte, addr net.Addr) []byte {
	host := net.IPv4(0, 0, 0, 0).To4()
	port := 0
	if tcp, ok := addr.(*net.TCPAddr); ok {
		if ip4 := tcp.IP.To4(); ip4 != nil {
			host = ip4
		}
		port = tcp.Port
	}
	return []byte{0x05, code, 0x00, 0x01, host[0], host[1], host[2], host[3], byte(port >> 8), byte(port)}
}

func isLoopbackListenHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func bytesContains(xs []byte, x byte) bool {
	for _, b := range xs {
		if b == x {
			return true
		}
	}
	return false
}

func parseListenPort(port string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil || p < 0 || p > 65535 {
		return 0, fmt.Errorf("非法 listen_port: %s", port)
	}
	return p, nil
}
