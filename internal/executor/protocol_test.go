package executor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-edr/internal/config"
)

func TestNormalizeHostPort(t *testing.T) {
	if normalizeHostPort("127.0.0.1", "23") != "127.0.0.1:23" {
		t.Fatal("default port not appended")
	}
	if normalizeHostPort("127.0.0.1:2323", "23") != "127.0.0.1:2323" {
		t.Fatal("explicit port should be preserved")
	}
}

func TestStripTelnetIAC(t *testing.T) {
	got := stripTelnetIAC(string([]byte{'a', 255, 251, 1, 'b'}))
	if got != "ab" {
		t.Fatalf("unexpected telnet cleanup: %q", got)
	}
}

func TestNormalizeRemoteCommandDecodesUnicodeEscapes(t *testing.T) {
	got := normalizeRemoteCommand(`chmod +x /tmp/a.sh \u0026\u0026 ls -la /tmp/a.sh`)
	if got != "chmod +x /tmp/a.sh && ls -la /tmp/a.sh" {
		t.Fatalf("unexpected command: %q", got)
	}
}

func TestIsSSHConnectionError(t *testing.T) {
	for _, msg := range []string{"EOF", "write: broken pipe", "use of closed network connection"} {
		if !isSSHConnectionError(errors.New(msg)) {
			t.Fatalf("expected connection error for %q", msg)
		}
	}
	if isSSHConnectionError(errors.New("permission denied")) {
		t.Fatal("permission denied should not be treated as reconnectable transport error")
	}
}

func TestTelnetExecutorEndToEnd(t *testing.T) {
	addr, cleanup := startMockTelnetServer(t)
	defer cleanup()

	ex, err := newTelnetExecutor(config.Config{
		TelnetHost:     addr,
		TelnetUser:     "root",
		TelnetPassword: "pass",
		TelnetPrompt:   "$",
	})
	if err != nil {
		t.Fatalf("newTelnetExecutor: %v", err)
	}
	defer ex.Close()

	var streamed []string
	out, err := ex.RunWithStreaming("echo TELNET_OK", func(line string) {
		streamed = append(streamed, line)
	})
	if err != nil {
		t.Fatalf("telnet run: %v", err)
	}
	if !strings.Contains(out, "TELNET_OK") {
		t.Fatalf("unexpected telnet output: %q", out)
	}
	if len(streamed) == 0 || !strings.Contains(strings.Join(streamed, "\n"), "TELNET_OK") {
		t.Fatalf("streaming output missing TELNET_OK: %#v", streamed)
	}
}

func TestFTPExecutorEndToEnd(t *testing.T) {
	addr, uploaded, cleanup := startMockFTPServer(t)
	defer cleanup()

	ex, err := newFTPExecutor(config.Config{
		FTPHost:     addr,
		FTPUser:     "user",
		FTPPassword: "pass",
	})
	if err != nil {
		t.Fatalf("newFTPExecutor: %v", err)
	}
	defer ex.Close()

	names, err := ex.ListTargetDir("/")
	if err != nil {
		t.Fatalf("ftp list: %v", err)
	}
	if len(names) != 1 || names[0] != "hello.txt" {
		t.Fatalf("unexpected ftp names: %#v", names)
	}

	data, err := ex.ReadTargetFile("hello.txt")
	if err != nil {
		t.Fatalf("ftp read: %v", err)
	}
	if string(data) != "HELLO_FTP\n" {
		t.Fatalf("unexpected ftp file: %q", data)
	}

	local := filepath.Join(t.TempDir(), "upload.txt")
	if err := os.WriteFile(local, []byte("UPLOAD_FTP\n"), 0o600); err != nil {
		t.Fatalf("write local upload: %v", err)
	}
	if _, err := ex.Run("upload " + local + " upload.txt"); err != nil {
		t.Fatalf("ftp upload: %v", err)
	}
	if got := string(uploaded["upload.txt"]); got != "UPLOAD_FTP\n" {
		t.Fatalf("unexpected uploaded data: %q", got)
	}

	if _, err := ex.Run("noop"); err != nil {
		t.Fatalf("ftp noop after transfers should not see stale 226 response: %v", err)
	}
}

func TestFleetTelnetExecEndToEnd(t *testing.T) {
	addr, cleanup := startMockTelnetServer(t)
	defer cleanup()

	results := RunFleet([]config.TargetConfig{{
		Name:     "telnet-mock",
		Protocol: "telnet",
		Host:     addr,
		User:     "root",
		Password: "pass",
		Prompt:   "$",
	}}, "all", "echo TELNET_OK", 1)
	if len(results) != 1 || !results[0].Success {
		t.Fatalf("unexpected telnet fleet result: %#v", results)
	}
	if !strings.Contains(results[0].Output, "TELNET_OK") {
		t.Fatalf("telnet fleet output missing marker: %q", results[0].Output)
	}
}

func TestFleetFileFTPEndToEnd(t *testing.T) {
	addr, _, cleanup := startMockFTPServer(t)
	target := config.TargetConfig{Name: "ftp-mock", Protocol: "ftp", Host: addr, User: "user", Password: "pass"}
	out, err := FleetFile(target, "ls", "/", "")
	cleanup()
	if err != nil {
		t.Fatalf("ftp fleet ls: %v", err)
	}
	if !strings.Contains(out, "hello.txt") {
		t.Fatalf("ftp fleet ls missing hello.txt: %q", out)
	}

	addr, _, cleanup = startMockFTPServer(t)
	target.Host = addr
	out, err = FleetFile(target, "read", "hello.txt", "")
	cleanup()
	if err != nil {
		t.Fatalf("ftp fleet read: %v", err)
	}
	if !strings.Contains(out, "HELLO_FTP") {
		t.Fatalf("ftp fleet read missing content: %q", out)
	}

	addr, uploaded, cleanup := startMockFTPServer(t)
	target.Host = addr
	local := filepath.Join(t.TempDir(), "fleet-upload.txt")
	if err := os.WriteFile(local, []byte("FLEET_UPLOAD\n"), 0o600); err != nil {
		t.Fatalf("write fleet upload: %v", err)
	}
	_, err = FleetFile(target, "upload", "fleet-upload.txt", local)
	cleanup()
	if err != nil {
		t.Fatalf("ftp fleet upload: %v", err)
	}
	if got := string(uploaded["fleet-upload.txt"]); got != "FLEET_UPLOAD\n" {
		t.Fatalf("unexpected fleet uploaded data: %q", got)
	}
}

func startMockTelnetServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen telnet: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_, _ = fmt.Fprint(conn, "login: ")
		_, _ = reader.ReadString('\n')
		_, _ = fmt.Fprint(conn, "Password: ")
		_, _ = reader.ReadString('\n')
		_, _ = fmt.Fprint(conn, "$ ")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if strings.Contains(line, "echo TELNET_OK") {
				_, _ = fmt.Fprint(conn, "TELNET_OK\r\n")
			}
			marker := telnetMarkerFromCommand(line)
			if marker != "" {
				_, _ = fmt.Fprintf(conn, "%s:0\r\n$ ", marker)
			}
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func telnetMarkerFromCommand(line string) string {
	idx := strings.LastIndex(line, "; echo ")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[idx+len("; echo "):])
	return strings.TrimSuffix(rest, ":$?")
}

func startMockFTPServer(t *testing.T) (string, map[string][]byte, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ftp: %v", err)
	}
	uploaded := map[string][]byte{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_, _ = fmt.Fprint(conn, "220 mock ftp ready\r\n")
		var dataLn net.Listener
		closeData := func() {
			if dataLn != nil {
				_ = dataLn.Close()
				dataLn = nil
			}
		}
		defer closeData()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			parts := strings.SplitN(line, " ", 2)
			cmd := strings.ToUpper(parts[0])
			arg := ""
			if len(parts) == 2 {
				arg = parts[1]
			}
			switch cmd {
			case "USER":
				_, _ = fmt.Fprint(conn, "331 password required\r\n")
			case "PASS":
				_, _ = fmt.Fprint(conn, "230 logged in\r\n")
			case "TYPE":
				_, _ = fmt.Fprint(conn, "200 type set\r\n")
			case "PWD":
				_, _ = fmt.Fprint(conn, "257 \"/\"\r\n")
			case "NOOP":
				_, _ = fmt.Fprint(conn, "200 noop\r\n")
			case "PASV":
				closeData()
				dataLn, err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					_, _ = fmt.Fprintf(conn, "425 %v\r\n", err)
					continue
				}
				port := dataLn.Addr().(*net.TCPAddr).Port
				_, _ = fmt.Fprintf(conn, "227 Entering Passive Mode (127,0,0,1,%d,%d)\r\n", port/256, port%256)
			case "NLST":
				_, _ = fmt.Fprint(conn, "150 opening data\r\n")
				dataConn, err := dataLn.Accept()
				if err == nil {
					_, _ = fmt.Fprint(dataConn, "hello.txt\r\n")
					_ = dataConn.Close()
				}
				closeData()
				_, _ = fmt.Fprint(conn, "226 transfer complete\r\n")
			case "RETR":
				_, _ = fmt.Fprint(conn, "150 opening data\r\n")
				dataConn, err := dataLn.Accept()
				if err == nil {
					if arg == "hello.txt" {
						_, _ = fmt.Fprint(dataConn, "HELLO_FTP\n")
					}
					_ = dataConn.Close()
				}
				closeData()
				_, _ = fmt.Fprint(conn, "226 transfer complete\r\n")
			case "STOR":
				_, _ = fmt.Fprint(conn, "150 opening data\r\n")
				dataConn, err := dataLn.Accept()
				if err == nil {
					data, _ := io.ReadAll(dataConn)
					uploaded[arg] = data
					_ = dataConn.Close()
				}
				closeData()
				_, _ = fmt.Fprint(conn, "226 transfer complete\r\n")
			case "QUIT":
				_, _ = fmt.Fprint(conn, "221 bye\r\n")
				return
			default:
				_, _ = fmt.Fprintf(conn, "500 unknown command %s\r\n", cmd)
			}
		}
	}()
	return ln.Addr().String(), uploaded, func() {
		_ = ln.Close()
		<-done
	}
}
