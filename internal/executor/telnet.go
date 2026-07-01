package executor

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"ai-edr/internal/config"
)

type TelnetExecutor struct {
	conn   net.Conn
	reader *bufio.Reader
	prompt string
	mu     sync.Mutex
}

func newTelnetExecutor(cfg config.Config) (*TelnetExecutor, error) {
	host := normalizeHostPort(cfg.TelnetHost, "23")
	conn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("Telnet 连接失败: %v", err)
	}
	t := &TelnetExecutor{conn: conn, reader: bufio.NewReader(conn), prompt: cfg.TelnetPrompt}
	if t.prompt == "" {
		t.prompt = "$,#,>,%"
	}
	if err := t.login(cfg.TelnetUser, cfg.TelnetPassword); err != nil {
		conn.Close()
		return nil, err
	}
	return t, nil
}

func (t *TelnetExecutor) login(user, pass string) error {
	_ = t.conn.SetDeadline(time.Now().Add(15 * time.Second))
	initial := t.readUntilAny([]string{"login:", "Login:", "username:", "Username:", "Password:", "password:"}, 5*time.Second)
	lower := strings.ToLower(initial)
	if strings.Contains(lower, "login:") || strings.Contains(lower, "username:") {
		if user == "" {
			user = "root"
		}
		if _, err := fmt.Fprintf(t.conn, "%s\r\n", user); err != nil {
			return err
		}
	}
	if strings.Contains(lower, "password:") || t.readUntilAny([]string{"Password:", "password:"}, 2*time.Second) != "" {
		if _, err := fmt.Fprintf(t.conn, "%s\r\n", pass); err != nil {
			return err
		}
	}
	_ = t.conn.SetDeadline(time.Time{})
	return nil
}

func (t *TelnetExecutor) Run(cmd string) (string, error) {
	return t.RunWithStreaming(cmd, nil)
}

func (t *TelnetExecutor) RunWithStreaming(cmd string, onLine func(string)) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "(空命令)", nil
	}
	if strings.Contains(cmd, "local_run ") {
		return (&LocalExecutor{}).RunWithStreaming(strings.ReplaceAll(cmd, "local_run ", ""), onLine)
	}
	end := fmt.Sprintf("__DEEPSENTRY_END_%d__", time.Now().UnixNano())
	if _, err := fmt.Fprintf(t.conn, "%s; echo %s:$?\r\n", cmd, end); err != nil {
		return "", err
	}
	_ = t.conn.SetReadDeadline(time.Now().Add(time.Duration(config.GlobalConfig.EffectiveSSHTimeout()) * time.Second))
	defer t.conn.SetReadDeadline(time.Time{})
	var b strings.Builder
	for {
		line, err := t.reader.ReadString('\n')
		if err != nil {
			return strings.TrimSpace(b.String()), err
		}
		if strings.Contains(line, end) {
			break
		}
		b.WriteString(line)
		if onLine != nil {
			onLine(stripTelnetIAC(line))
		}
		if b.Len() > effectiveMaxOutputBytes() {
			return truncateOutput(b.String(), effectiveMaxOutputBytes()), nil
		}
	}
	out := strings.TrimSpace(stripTelnetIAC(b.String()))
	if out == "" {
		out = "(执行成功，无输出)"
	}
	return out, nil
}

func (t *TelnetExecutor) ReadTargetFile(path string) ([]byte, error) {
	out, err := t.Run("cat " + shellQuotePath(path))
	return []byte(out), err
}

func (t *TelnetExecutor) ListTargetDir(path string) ([]string, error) {
	out, err := t.Run("ls -1 " + shellQuotePath(path))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			names = append(names, line)
		}
	}
	return names, nil
}

func (t *TelnetExecutor) IsRemote() bool { return true }
func (t *TelnetExecutor) Mode() string   { return "telnet" }
func (t *TelnetExecutor) Close()         { _ = t.conn.Close() }

func (t *TelnetExecutor) readUntilAny(tokens []string, timeout time.Duration) string {
	_ = t.conn.SetReadDeadline(time.Now().Add(timeout))
	defer t.conn.SetReadDeadline(time.Time{})
	var b strings.Builder
	for {
		c, err := t.reader.ReadByte()
		if err != nil {
			return b.String()
		}
		b.WriteByte(c)
		s := b.String()
		for _, tok := range tokens {
			if strings.Contains(s, tok) {
				return s
			}
		}
		if b.Len() > 4096 {
			return s
		}
	}
}

func stripTelnetIAC(s string) string {
	var out []byte
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] == 255 {
			i += 2
			continue
		}
		out = append(out, b[i])
	}
	return string(out)
}

func normalizeHostPort(host, defPort string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return host
	}
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":" + defPort
}
