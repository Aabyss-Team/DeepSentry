package executor

import (
	"ai-edr/internal/config"
	"ai-edr/internal/ui"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

const truncationNoticeFmt = "\n\n...(输出已截断，仅保留前 %d 字节；大日志请使用 head/tail/wc 限制输出，或通过 read_file 查看 workspace 中的完整输出文件)..."

// outputCollector 收集命令输出，超出上限后丢弃后续内容但仍可继续读取以排空管道
type outputCollector struct {
	buf       strings.Builder
	truncated bool
	maxBytes  int
}

// streamingOutputWriter lets os/exec drain stdout and stderr before Wait
// returns, while preserving line-oriented callbacks. Cmd.WaitDelay bounds the
// case where a deliberately backgrounded child inherits the shell pipes.
type streamingOutputWriter struct {
	mu        sync.Mutex
	pending   []byte
	collector *outputCollector
	onLine    func(string)
}

func newStreamingOutputWriter(collector *outputCollector, onLine func(string)) *streamingOutputWriter {
	return &streamingOutputWriter{collector: collector, onLine: onLine}
}

func (w *streamingOutputWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.consume(p, false)
	return n, nil
}

func (w *streamingOutputWriter) flush() {
	w.consume(nil, true)
}

func (w *streamingOutputWriter) consume(p []byte, flush bool) {
	w.mu.Lock()
	w.pending = append(w.pending, p...)
	var emitted []string
	for {
		end := bytes.IndexByte(w.pending, '\n')
		if end < 0 {
			break
		}
		raw := append([]byte(nil), w.pending[:end+1]...)
		w.pending = w.pending[end+1:]
		if line := normalizeLocalOutputLine(raw); line != "" {
			w.collector.appendLine(line)
			emitted = append(emitted, line)
		}
	}
	if flush && len(w.pending) > 0 {
		raw := append([]byte(nil), w.pending...)
		w.pending = nil
		if line := normalizeLocalOutputLine(raw); line != "" {
			w.collector.appendLine(line)
			emitted = append(emitted, line)
		}
	}
	w.mu.Unlock()

	if w.onLine != nil {
		for _, line := range emitted {
			w.onLine(line)
		}
	}
}

func normalizeLocalOutputLine(raw []byte) string {
	line := string(raw)
	if runtime.GOOS == "windows" {
		if utf8Out, err := GbkToUtf8(raw); err == nil {
			line = string(utf8Out)
		}
	}
	line = strings.ReplaceAll(line, "Active code page: 65001\r\n", "")
	line = strings.ReplaceAll(line, "Active code page: 65001\n", "")
	return line
}

func newOutputCollector(maxBytes int) *outputCollector {
	if maxBytes <= 0 {
		maxBytes = 512 * 1024
	}
	return &outputCollector{maxBytes: maxBytes}
}

func (c *outputCollector) appendLine(line string) {
	if c.truncated {
		return
	}
	if c.buf.Len()+len(line) > c.maxBytes {
		c.truncated = true
		if remain := c.maxBytes - c.buf.Len(); remain > 0 {
			c.buf.WriteString(safeUTF8BytePrefix(line, remain))
		}
		return
	}
	c.buf.WriteString(line)
}

func (c *outputCollector) result() string {
	out := strings.TrimSpace(c.buf.String())
	if c.truncated {
		out += fmt.Sprintf(truncationNoticeFmt, c.maxBytes)
	}
	return out
}

func truncateOutput(s string, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = 512 * 1024
	}
	if len(s) <= maxBytes {
		return s
	}
	return strings.TrimSpace(safeUTF8BytePrefix(s, maxBytes)) + fmt.Sprintf(truncationNoticeFmt, maxBytes)
}

func safeUTF8BytePrefix(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	end := maxBytes
	for end > 0 && !utf8.ValidString(s[:end]) {
		end--
	}
	return s[:end]
}

func effectiveMaxOutputBytes() int {
	return config.GlobalConfig.EffectiveSSHMaxOutputBytes()
}

// Executor 接口定义了执行器的标准行为
type Executor interface {
	Run(cmd string) (string, error)
	ReadTargetFile(path string) ([]byte, error)
	ListTargetDir(path string) ([]string, error)
	IsRemote() bool
	Close()
}

type StreamingExecutor interface {
	RunWithStreaming(cmd string, onLine func(string)) (string, error)
}

type StoppableStreamingExecutor interface {
	RunWithStreamingAndStop(cmd string, onLine func(string), stop <-chan struct{}) (string, error)
}

type ModeReporter interface {
	Mode() string
}

func CurrentMode() string {
	if Current == nil {
		return "local"
	}
	if m, ok := Current.(ModeReporter); ok {
		return m.Mode()
	}
	if Current.IsRemote() {
		return "remote"
	}
	return "local"
}

// Current 全局变量，存储当前活动的执行器实例
var Current Executor
var modeOutputEnabled atomic.Bool

func init() {
	modeOutputEnabled.Store(true)
}

func SetModeOutputEnabled(enabled bool) {
	modeOutputEnabled.Store(enabled)
}

func emitModeSwitch(format string, args ...interface{}) {
	if modeOutputEnabled.Load() {
		fmt.Print(ui.TerminalText(fmt.Sprintf(format, args...)))
	}
}

// Reconnect 断线后重新初始化执行器
func Reconnect(cfg config.Config) error {
	if Current != nil {
		Current.Close()
		Current = nil
	}
	return Init(cfg)
}

// Init 初始化执行器
func Init(cfg config.Config) error {
	mode := strings.ToLower(strings.TrimSpace(cfg.TargetProtocol))
	if mode == "" {
		switch {
		case cfg.SSHHost != "":
			mode = "ssh"
		case cfg.TelnetHost != "":
			mode = "telnet"
		case cfg.FTPHost != "":
			mode = "ftp"
		default:
			mode = "local"
		}
	}
	switch mode {
	case "ssh":
		e, err := newSSHExecutor(cfg)
		if err != nil {
			return err
		}
		Current = e
		emitModeSwitch("🔌 [模式切换] 已连接至远程主机 (SSH): %s@%s\n", cfg.SSHUser, cfg.SSHHost)
	case "telnet":
		e, err := newTelnetExecutor(cfg)
		if err != nil {
			return err
		}
		Current = e
		emitModeSwitch("🔌 [模式切换] 已连接至远程主机 (Telnet): %s@%s\n", cfg.TelnetUser, cfg.TelnetHost)
	case "ftp":
		e, err := newFTPExecutor(cfg)
		if err != nil {
			return err
		}
		Current = e
		emitModeSwitch("🔌 [模式切换] 已连接至远程主机 (FTP): %s@%s\n", cfg.FTPUser, cfg.FTPHost)
	case "local":
		Current = &LocalExecutor{}
		emitModeSwitch("🔌 [模式切换] 本地执行模式\n")
	default:
		return fmt.Errorf("不支持的 target_protocol: %s", mode)
	}
	return nil
}

// ==========================================
// Local Executor (本地模式)
// ==========================================

type LocalExecutor struct{}

func (l *LocalExecutor) Run(cmdStr string) (string, error) {
	return l.RunWithStreaming(cmdStr, nil)
}

func (l *LocalExecutor) RunWithStreaming(cmdStr string, onLine func(string)) (string, error) {
	return l.RunWithStreamingAndStop(cmdStr, onLine, nil)
}

func (l *LocalExecutor) RunWithStreamingAndStop(cmdStr string, onLine func(string), stop <-chan struct{}) (string, error) {
	// 1. 清洗 local_run 标记
	if strings.Contains(cmdStr, "local_run ") {
		cmdStr = strings.ReplaceAll(cmdStr, "local_run ", "")
	}
	cmdStr = strings.TrimSpace(cmdStr)
	if CommandUsesSudo(cmdStr) {
		cmdStr = ForceNonInteractiveSudo(cmdStr)
	}

	// 2. 拦截 download/upload
	if strings.HasPrefix(cmdStr, "download ") || strings.HasPrefix(cmdStr, "upload ") {
		action, src, dst, ok := parseTransferCommand(cmdStr)
		if !ok {
			return "", fmt.Errorf("用法错误: transfer <src> <dst>")
		}
		_ = action
		return copyLocalFile(src, dst)
	}

	if guidance, blocked := blockRawSSHLikeCommand(cmdStr); blocked {
		return guidance, nil
	}

	outputStr, err := runLocalShellCommandWithStop(cmdStr, onLine, stop)

	if outputStr == "" && err == nil {
		outputStr = "(执行成功，无输出)"
	}

	return outputStr, err
}

func blockRawSSHLikeCommand(cmdStr string) (string, bool) {
	parts, err := splitShellFields(cmdStr)
	if err != nil || len(parts) == 0 {
		return "", false
	}
	name, args := unwrapSSHLikeCommand(parts)
	if name == "" || !sshLikeCommandConnects(name, args) {
		return "", false
	}
	return rawSSHLikeGuidance(name, cmdStr), true
}

func unwrapSSHLikeCommand(parts []string) (string, []string) {
	for len(parts) > 0 {
		name := filepath.Base(parts[0])
		switch name {
		case "ssh", "scp", "sftp":
			return name, parts[1:]
		case "sshpass":
			rest := skipSSHPassOptions(parts[1:])
			if len(rest) == 0 {
				return "", nil
			}
			parts = rest
		case "env":
			parts = skipEnvPrefix(parts[1:])
		case "timeout", "gtimeout":
			parts = skipTimeoutPrefix(parts[1:])
		case "command", "nohup":
			parts = parts[1:]
		case "sudo":
			parts = skipSudoPrefix(parts[1:])
		default:
			if strings.Contains(parts[0], "=") && !strings.HasPrefix(parts[0], "-") {
				parts = parts[1:]
				continue
			}
			return "", nil
		}
	}
	return "", nil
}

func skipSSHPassOptions(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "-p" || a == "-f" || a == "-d" || a == "-P":
			if len(args) < 2 {
				return nil
			}
			args = args[2:]
		case strings.HasPrefix(a, "-p") || strings.HasPrefix(a, "-f") || strings.HasPrefix(a, "-d") || strings.HasPrefix(a, "-P"):
			args = args[1:]
		case a == "-e" || a == "-v" || a == "-h" || a == "-V":
			args = args[1:]
		default:
			return args
		}
	}
	return args
}

func skipEnvPrefix(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		if strings.Contains(a, "=") || strings.HasPrefix(a, "-") {
			args = args[1:]
			continue
		}
		return args
	}
	return args
}

func skipTimeoutPrefix(args []string) []string {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		if args[0] == "-s" || args[0] == "--signal" || args[0] == "-k" || args[0] == "--kill-after" {
			if len(args) < 2 {
				return nil
			}
			args = args[2:]
			continue
		}
		args = args[1:]
	}
	if len(args) == 0 {
		return nil
	}
	return args[1:]
}

func skipSudoPrefix(args []string) []string {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		if args[0] == "-u" || args[0] == "-g" || args[0] == "-h" || args[0] == "-p" {
			if len(args) < 2 {
				return nil
			}
			args = args[2:]
			continue
		}
		args = args[1:]
	}
	return args
}

func sshLikeCommandConnects(name string, args []string) bool {
	switch name {
	case "ssh":
		return sshArgsHaveDestination(args)
	case "scp":
		return scpArgsHaveRemotePath(args)
	case "sftp":
		return sftpArgsHaveDestination(args)
	default:
		return false
	}
}

func sshArgsHaveDestination(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return i+1 < len(args)
		}
		if a == "-V" || a == "-h" || a == "-?" || a == "--help" || a == "-G" {
			return false
		}
		if strings.HasPrefix(a, "-") {
			if sshOptionTakesValue(a) && !sshOptionHasInlineValue(a) {
				i++
			}
			continue
		}
		return true
	}
	return false
}

func sftpArgsHaveDestination(args []string) bool {
	if hasAnyArg(args, "-V", "-h", "-?", "--help") {
		return false
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return i+1 < len(args)
		}
		if strings.HasPrefix(a, "-") {
			if sshOptionTakesValue(a) && !sshOptionHasInlineValue(a) {
				i++
			}
			continue
		}
		return true
	}
	return false
}

func scpArgsHaveRemotePath(args []string) bool {
	if hasAnyArg(args, "-V", "-h", "-?", "--help") {
		return false
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			for _, rest := range args[i+1:] {
				if isSCPRemotePath(rest) {
					return true
				}
			}
			return false
		}
		if strings.HasPrefix(a, "-") {
			if sshOptionTakesValue(a) && !sshOptionHasInlineValue(a) {
				i++
			}
			continue
		}
		if isSCPRemotePath(a) {
			return true
		}
	}
	return false
}

func sshOptionTakesValue(opt string) bool {
	opt = strings.TrimLeft(opt, "-")
	if opt == "" {
		return false
	}
	switch opt[:1] {
	case "B", "b", "c", "D", "E", "e", "F", "I", "i", "J", "L", "l", "m", "O", "o", "P", "p", "Q", "R", "S", "W", "w":
		return true
	default:
		return false
	}
}

func sshOptionHasInlineValue(opt string) bool {
	if strings.HasPrefix(opt, "--") {
		return strings.Contains(opt, "=")
	}
	return len(opt) > 2
}

func hasAnyArg(args []string, wants ...string) bool {
	for _, a := range args {
		for _, want := range wants {
			if a == want {
				return true
			}
		}
	}
	return false
}

func isSCPRemotePath(s string) bool {
	if strings.Contains(s, "://") {
		return true
	}
	colon := strings.Index(s, ":")
	if colon <= 0 {
		return false
	}
	if len(s) >= 2 && s[1] == ':' && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) {
		return false
	}
	return strings.Contains(s[:colon], "@") || !strings.Contains(s[:colon], "/")
}

func rawSSHLikeGuidance(toolName, cmdStr string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("已拦截控制端裸 %s 命令，避免进入交互式密码提示导致 TUI 卡住。\n", toolName))
	b.WriteString("原因: `ssh/scp/sftp` 子进程不会读取 DeepSentry config.yaml 中的 targets 密码；OpenSSH 会直接向终端请求密码，而底部输入框不是该子进程 stdin。\n\n")
	if len(config.GlobalConfig.Targets) > 0 {
		b.WriteString("当前已配置 Fleet 目标，请改用会读取配置密码/私钥的内置工具:\n")
		b.WriteString(`{"action":"tool","tool_name":"fleet_exec","tool_args":{"selector":"target-01","command":"echo SSH_OK","concurrency":"1"}}` + "\n")
		b.WriteString(`{"action":"tool","tool_name":"fleet_file","tool_args":{"selector":"target-01","action":"download","remote_path":"/tmp/flag.txt","local_path":"~/.deepsentry/workspace/flag.txt"}}` + "\n\n")
		b.WriteString("可用目标:\n")
		for _, t := range config.GlobalConfig.Targets {
			b.WriteString(fmt.Sprintf("- %s protocol=%s host=%s user=%s tags=%s\n", TargetDisplayName(t), t.Protocol, t.Host, t.User, strings.Join(t.Tags, ",")))
		}
	} else {
		b.WriteString("请先把主机添加到 config.yaml targets，或使用 config_manage 添加目标，然后通过 fleet_exec/fleet_file 执行。\n")
		b.WriteString(`{"action":"tool","tool_name":"config_manage","tool_args":{"action":"add_target","protocol":"ssh","host":"<host:port>","user":"<user>","password":"<password>","tags":"prod"}}` + "\n")
	}
	b.WriteString("\n原始命令未执行:\n")
	b.WriteString(cmdStr)
	return b.String()
}

func expandLocalPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func runLocalShellCommandWithStop(cmdStr string, onLine func(string), stop <-chan struct{}) (string, error) {
	ctx := context.Background()
	cancel := func() {}
	if stop != nil {
		var cancelContext context.CancelFunc
		ctx, cancelContext = context.WithCancel(ctx)
		cancel = cancelContext
		go func() {
			select {
			case <-stop:
				cancelContext()
			case <-ctx.Done():
			}
		}()
	}
	defer cancel()
	var cmd *exec.Cmd

	lowerCmd := strings.ToLower(cmdStr)
	isPowerShell := strings.HasPrefix(lowerCmd, "powershell") || strings.HasPrefix(lowerCmd, "pwsh")

	if runtime.GOOS == "windows" {
		if isPowerShell {
			shell, script := parsePowerShellCommand(cmdStr)
			cmd = exec.CommandContext(ctx, shell, "-NoProfile", "-NonInteractive", "-Command", script)
		} else {
			cmd = exec.CommandContext(ctx, "cmd", "/c", cmdStr)
		}
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", cmdStr)
	}
	configureCommandProcessGroup(cmd)
	if stop != nil {
		cmd.Cancel = func() error {
			killCommandProcessGroup(cmd)
			return nil
		}
	}

	collector := newOutputCollector(effectiveMaxOutputBytes())
	stream := newStreamingOutputWriter(collector, onLine)
	cmd.Stdout = stream
	cmd.Stderr = stream
	// A background service may inherit stdout/stderr after the foreground shell
	// has exited. Give normal commands time to drain, then close inherited pipes
	// instead of blocking the Agent forever.
	cmd.WaitDelay = 250 * time.Millisecond
	if err := cmd.Start(); err != nil {
		return "", err
	}
	err := cmd.Wait()
	stream.flush()
	if errors.Is(err, exec.ErrWaitDelay) {
		// The foreground shell exited successfully; only an inherited pipe from
		// a background child exceeded the bounded drain window.
		err = nil
	}
	if ctx.Err() != nil {
		return strings.TrimSpace(collector.result()), fmt.Errorf("命令已按用户请求中断")
	}
	return strings.TrimSpace(collector.result()), err
}

func parsePowerShellCommand(cmdStr string) (string, string) {
	lowerCmd := strings.ToLower(strings.TrimSpace(cmdStr))
	shell := "powershell"
	script := strings.TrimSpace(cmdStr)
	if strings.HasPrefix(lowerCmd, "powershell") {
		script = strings.TrimSpace(script[len("powershell"):])
	} else if strings.HasPrefix(lowerCmd, "pwsh") {
		shell = "pwsh"
		script = strings.TrimSpace(script[len("pwsh"):])
	}

	lowerScript := strings.ToLower(script)
	if strings.HasPrefix(lowerScript, "-command ") {
		script = strings.TrimSpace(script[len("-command "):])
	} else if strings.HasPrefix(lowerScript, "-c ") {
		script = strings.TrimSpace(script[len("-c "):])
	}
	script = strings.Trim(script, " \"'")
	return shell, script
}

func parseTransferCommand(cmd string) (action, src, dst string, ok bool) {
	parts, err := splitShellFields(cmd)
	if err != nil || len(parts) != 3 {
		return "", "", "", false
	}
	if parts[0] != "upload" && parts[0] != "download" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func splitShellFields(s string) ([]string, error) {
	var fields []string
	var b strings.Builder
	inSingle := false
	inDouble := false
	escaped := false
	have := false

	for _, r := range s {
		switch {
		case escaped:
			b.WriteRune(r)
			have = true
			escaped = false
		case r == '\\' && !inSingle:
			escaped = true
			have = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			have = true
		case r == '"' && !inSingle:
			inDouble = !inDouble
			have = true
		case (r == ' ' || r == '\t' || r == '\n' || r == '\r') && !inSingle && !inDouble:
			if have {
				fields = append(fields, b.String())
				b.Reset()
				have = false
			}
		default:
			b.WriteRune(r)
			have = true
		}
	}
	if escaped || inSingle || inDouble {
		return nil, fmt.Errorf("未闭合的引号或转义")
	}
	if have {
		fields = append(fields, b.String())
	}
	return fields, nil
}

func (l *LocalExecutor) IsRemote() bool { return false }
func (l *LocalExecutor) Close()         {}
func (l *LocalExecutor) Mode() string   { return "local" }

func (l *LocalExecutor) ReadTargetFile(path string) ([]byte, error) {
	return ReadLocalFile(path)
}

func (l *LocalExecutor) ListTargetDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

func copyLocalFile(src, dst string) (string, error) {
	src = expandLocalPath(src)
	dst = expandLocalPath(dst)

	sourceFile, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("打开源文件失败: %v", err)
	}
	defer sourceFile.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", fmt.Errorf("创建目录失败: %v", err)
	}
	destFile, err := createPrivateOutputFile(dst)
	if err != nil {
		return "", fmt.Errorf("创建目标文件失败: %v", err)
	}
	defer destFile.Close()

	n, err := io.Copy(destFile, sourceFile)
	if err != nil {
		return "", fmt.Errorf("复制失败: %v", err)
	}
	return fmt.Sprintf("%s文件传输成功 (Bytes: %d): %s -> %s", ui.Prefix("✅", "[OK]"), n, src, dst), nil
}

func createPrivateOutputFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// ==========================================
// SSH Executor (远程模式)
// ==========================================

type SSHExecutor struct {
	client         *ssh.Client
	session        *ssh.Session
	sftpClient     *sftp.Client
	stdin          io.WriteCloser
	stdout         *bufio.Reader
	commandTimeout time.Duration
	mu             sync.Mutex
}

var knownHostsMu sync.Mutex

func normalizeSSHHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return host
	}
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":22"
}

func resolveKnownHostsPath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "~/.deepsentry/known_hosts"
	}
	if raw == "~" || strings.HasPrefix(raw, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("无法定位用户主目录: %w", err)
		}
		if raw == "~" {
			raw = home
		} else {
			raw = filepath.Join(home, strings.TrimPrefix(raw, "~/"))
		}
	}
	return filepath.Clean(raw), nil
}

func ensureKnownHostsFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func sshHostKeyCallback(cfg config.Config) (ssh.HostKeyCallback, error) {
	policy := strings.ToLower(strings.TrimSpace(cfg.SSHHostKeyPolicy))
	if policy == "" {
		policy = "accept-new"
	}
	if policy == "insecure" {
		// #nosec G106 -- explicit operator-selected compatibility mode. The
		// secure default is accept-new and public docs reject insecure in prod.
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if policy != "strict" && policy != "accept-new" {
		return nil, fmt.Errorf("ssh_host_key_policy 不支持 %q，请使用 strict|accept-new|insecure", policy)
	}

	path, err := resolveKnownHostsPath(cfg.SSHKnownHostsPath)
	if err != nil {
		return nil, err
	}
	if policy == "accept-new" {
		if err := ensureKnownHostsFile(path); err != nil {
			return nil, fmt.Errorf("创建 SSH known_hosts 失败: %w", err)
		}
	} else if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("SSH strict 模式需要已存在的 known_hosts %s: %w", path, err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		knownHostsMu.Lock()
		defer knownHostsMu.Unlock()

		check, err := knownhosts.New(path)
		if err != nil {
			return fmt.Errorf("读取 SSH known_hosts 失败: %w", err)
		}
		if err = check(hostname, remote, key); err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if policy != "accept-new" || !errors.As(err, &keyErr) || len(keyErr.Want) > 0 {
			return fmt.Errorf("SSH 主机密钥校验失败（%s）: %w", hostname, err)
		}

		line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key) + "\n"
		f, openErr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if openErr != nil {
			return fmt.Errorf("写入 SSH known_hosts 失败: %w", openErr)
		}
		_, writeErr := f.WriteString(line)
		if syncErr := f.Sync(); writeErr == nil {
			writeErr = syncErr
		}
		if closeErr := f.Close(); writeErr == nil {
			writeErr = closeErr
		}
		if writeErr != nil {
			return fmt.Errorf("写入 SSH known_hosts 失败: %w", writeErr)
		}
		return nil
	}, nil
}

func newSSHExecutor(cfg config.Config) (Executor, error) {
	client, err := dialSSHClient(cfg)
	if err != nil {
		return nil, err
	}
	deviceType := normalizeDeviceType(cfg.SSHDeviceType)
	if deviceType != "auto" && deviceType != "linux" {
		network, networkErr := newSSHNetworkExecutor(client, cfg)
		if networkErr != nil {
			_ = client.Close()
			return nil, networkErr
		}
		return network, nil
	}

	// SFTP is a strong Linux/server signal, but it is optional. Many network
	// appliances and minimal hosts intentionally do not expose the subsystem.
	sftpClient, sftpErr := sftp.NewClient(client)
	if deviceType == "auto" && sftpErr != nil {
		if network, networkErr := newSSHNetworkExecutor(client, cfg); networkErr == nil {
			return network, nil
		}
	}

	linux, linuxErr := newLinuxSSHExecutor(client, sftpClient, cfg)
	if linuxErr == nil {
		return linux, nil
	}
	if sftpClient != nil {
		_ = sftpClient.Close()
	}
	if deviceType == "auto" {
		if network, networkErr := newSSHNetworkExecutor(client, cfg); networkErr == nil {
			return network, nil
		} else {
			_ = client.Close()
			return nil, fmt.Errorf("SSH 目标既无法启动 Linux shell，也无法建立网络设备 CLI: shell=%v; cli=%v", linuxErr, networkErr)
		}
	}
	_ = client.Close()
	return nil, linuxErr
}

func dialSSHClient(cfg config.Config) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod
	if cfg.SSHKeyPath != "" {
		key, err := os.ReadFile(cfg.SSHKeyPath)
		if err != nil {
			return nil, fmt.Errorf("读取私钥失败: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else {
		authMethods = append(authMethods, ssh.Password(cfg.SSHPassword))
	}

	hostKeyCallback, err := sshHostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}
	sshConfig := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	addr := normalizeSSHHost(cfg.SSHHost)
	rawConn, err := config.ControllerDialTimeout("tcp", addr, sshConfig.Timeout)
	if err != nil {
		return nil, fmt.Errorf("SSH连接失败: %v", err)
	}
	_ = rawConn.SetDeadline(time.Now().Add(sshConfig.Timeout))
	clientConn, channels, requests, err := ssh.NewClientConn(rawConn, addr, sshConfig)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("SSH握手失败: %v", err)
	}
	_ = rawConn.SetDeadline(time.Time{})
	client := ssh.NewClient(clientConn, channels, requests)
	return client, nil
}

func newLinuxSSHExecutor(client *ssh.Client, sftpClient *sftp.Client, cfg config.Config) (*SSHExecutor, error) {
	session, stdin, stdout, err := startSSHCommandShell(client, "/bin/bash")
	if err != nil {
		session, stdin, stdout, err = startSSHCommandShell(client, "/bin/sh")
		if err != nil {
			return nil, fmt.Errorf("无法启动远程 Shell: %v", err)
		}
	}

	exe := &SSHExecutor{
		client:         client,
		session:        session,
		sftpClient:     sftpClient,
		stdin:          stdin,
		stdout:         bufio.NewReader(stdout),
		commandTimeout: 5 * time.Second,
	}

	if _, err := exe.run("export TERM=xterm; export LANG=en_US.UTF-8", false, nil, nil); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("远程 Linux Shell 探测失败: %w", err)
	}
	exe.commandTimeout = secondsOrDefault(cfg.SSHCommandTimeoutSec, 90)

	return exe, nil
}

func startSSHCommandShell(client *ssh.Client, command string) (*ssh.Session, io.WriteCloser, io.Reader, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("创建 Session 失败: %w", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, nil, nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, nil, nil, err
	}
	session.Stderr = session.Stdout
	if err := session.Start(command); err != nil {
		_ = session.Close()
		return nil, nil, nil, err
	}
	return session, stdin, stdout, nil
}

func (s *SSHExecutor) Run(cmdStr string) (string, error) {
	return s.run(cmdStr, true, nil, nil)
}

func (s *SSHExecutor) RunWithStreaming(cmdStr string, onLine func(string)) (string, error) {
	return s.run(cmdStr, true, onLine, nil)
}

func (s *SSHExecutor) RunWithStreamingAndStop(cmdStr string, onLine func(string), stop <-chan struct{}) (string, error) {
	return s.run(cmdStr, true, onLine, stop)
}

func (s *SSHExecutor) run(cmdStr string, retryOnWriteFailure bool, onLine func(string), stop <-chan struct{}) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cmdStr = normalizeRemoteCommand(cmdStr)
	if CommandUsesSudo(cmdStr) {
		cmdStr = ForceNonInteractiveSudo(cmdStr)
	}

	if strings.Contains(cmdStr, "local_run ") {
		realCmd := strings.ReplaceAll(cmdStr, "local_run ", "")
		outputStr, err := runLocalShellCommandWithStop(realCmd, onLine, stop)

		if err != nil {
			return fmt.Sprintf("%s[Local Exec Error]: %v\nOutput:\n%s", ui.Prefix("💻", "[CMD]"), err, outputStr), nil
		}
		return fmt.Sprintf("%s[Local Exec Success]:\n%s", ui.Prefix("💻", "[CMD]"), outputStr), nil
	}

	if strings.HasPrefix(cmdStr, "upload ") {
		_, localPath, remotePath, ok := parseTransferCommand(cmdStr)
		if !ok {
			return "", fmt.Errorf("用法: upload <本地文件> <远程路径>")
		}
		return s.uploadFile(localPath, remotePath)
	}

	if strings.HasPrefix(cmdStr, "download ") {
		_, remotePath, localPath, ok := parseTransferCommand(cmdStr)
		if !ok {
			return "", fmt.Errorf("用法: download <远程文件> <本地路径>")
		}
		return s.downloadFile(remotePath, localPath)
	}

	endMarker := fmt.Sprintf("__END_%d__", time.Now().UnixNano())
	fullCmd := fmt.Sprintf("%s; echo \"\"; echo \"%s:$?\"\n", cmdStr, endMarker)

	if _, err := s.stdin.Write([]byte(fullCmd)); err != nil {
		if retryOnWriteFailure && isSSHConnectionError(err) {
			if reconnectErr := reconnectSSHExecutor(s); reconnectErr != nil {
				return "", fmt.Errorf("写入命令失败: %v；自动重连失败: %v", err, reconnectErr)
			}
			if next, ok := Current.(*SSHExecutor); ok && next != s {
				return next.run(cmdStr, false, onLine, stop)
			}
			return "", fmt.Errorf("写入命令失败: %v；已尝试自动重连但未获得新的 SSH 执行器", err)
		}
		return "", fmt.Errorf("写入命令失败: %v", err)
	}

	timeout := s.commandTimeout
	if timeout <= 0 {
		timeout = time.Duration(config.GlobalConfig.EffectiveSSHTimeout()) * time.Second
	}
	type readResult struct {
		out string
		err error
	}
	ch := make(chan readResult, 1)
	maxBytes := effectiveMaxOutputBytes()
	go func() {
		collector := newOutputCollector(maxBytes)
		for {
			line, err := s.stdout.ReadString('\n')
			if err != nil {
				ch <- readResult{collector.result(), fmt.Errorf("读取中断: %v", err)}
				return
			}
			if strings.Contains(line, endMarker) {
				ch <- readResult{collector.result(), nil}
				return
			}
			collector.appendLine(line)
			if onLine != nil {
				onLine(line)
			}
		}
	}()

	select {
	case res := <-ch:
		if res.err != nil && strings.Contains(res.err.Error(), "读取中断") {
			_ = reconnectSSHExecutor(s)
		}
		return res.out, res.err
	case <-time.After(timeout):
		if !retryOnWriteFailure {
			return "", fmt.Errorf("SSH Shell 探测超时 (%v)", timeout)
		}
		reconnectErr := reconnectSSHExecutor(s)
		if reconnectErr != nil {
			return "", fmt.Errorf("SSH 命令超时 (%v)，且重连失败: %v", timeout, reconnectErr)
		}
		return "", fmt.Errorf("SSH 命令超时 (%v)，已重建远程 shell，后续命令可继续执行", timeout)
	case <-stop:
		reconnectErr := reconnectSSHExecutor(s)
		if reconnectErr != nil {
			return "", fmt.Errorf("SSH 命令已按用户请求中断，但远程 shell 重连失败: %v", reconnectErr)
		}
		return "", fmt.Errorf("SSH 命令已按用户请求中断，远程 shell 已重建")
	}
}

func normalizeRemoteCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if !strings.Contains(cmd, `\u`) && !strings.Contains(cmd, `\U`) {
		return cmd
	}
	var b strings.Builder
	for i := 0; i < len(cmd); i++ {
		if cmd[i] != '\\' || i+5 >= len(cmd) || (cmd[i+1] != 'u' && cmd[i+1] != 'U') {
			b.WriteByte(cmd[i])
			continue
		}
		v, err := strconv.ParseInt(cmd[i+2:i+6], 16, 32)
		if err != nil {
			b.WriteByte(cmd[i])
			continue
		}
		b.WriteRune(rune(v))
		i += 5
	}
	return b.String()
}

func isSSHConnectionError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{"eof", "closed", "broken pipe", "connection reset", "use of closed network connection"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

func reconnectSSHExecutor(s *SSHExecutor) error {
	if s != nil {
		s.Close()
	}
	if Current == s {
		Current = nil
	}
	return Init(config.GlobalConfig)
}

func (s *SSHExecutor) uploadFile(localPath, remotePath string) (string, error) {
	localPath = expandLocalPath(localPath)

	srcFile, err := os.Open(localPath)
	if err != nil {
		return "", fmt.Errorf("无法打开本地文件: %v", err)
	}
	defer srcFile.Close()

	if err := s.sftpClient.MkdirAll(filepath.Dir(remotePath)); err != nil {
		return "", fmt.Errorf("创建远程目录失败: %v", err)
	}

	dstFile, err := s.sftpClient.Create(remotePath)
	if err != nil {
		return "", fmt.Errorf("无法创建远程文件: %v", err)
	}
	defer dstFile.Close()

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return "", fmt.Errorf("上传传输失败: %v", err)
	}
	return fmt.Sprintf("%s上传成功 (Bytes: %d): %s -> %s", ui.Prefix("✅", "[OK]"), n, localPath, remotePath), nil
}

func (s *SSHExecutor) downloadFile(remotePath, localPath string) (string, error) {
	localPath = expandLocalPath(localPath)

	srcFile, err := s.sftpClient.Open(remotePath)
	if err != nil {
		return "", fmt.Errorf("无法打开远程文件: %v", err)
	}
	defer srcFile.Close()

	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return "", fmt.Errorf("创建本地目录失败: %v", err)
	}

	dstFile, err := createPrivateOutputFile(localPath)
	if err != nil {
		return "", fmt.Errorf("无法创建本地文件: %v", err)
	}
	defer dstFile.Close()

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return "", fmt.Errorf("下载传输失败: %v", err)
	}
	return fmt.Sprintf("%s下载成功 (Bytes: %d): %s -> %s", ui.Prefix("✅", "[OK]"), n, remotePath, localPath), nil
}

func (s *SSHExecutor) IsRemote() bool { return true }
func (s *SSHExecutor) Mode() string   { return "ssh" }

func (s *SSHExecutor) ReadTargetFile(path string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sftpClient != nil {
		f, err := s.sftpClient.Open(path)
		if err == nil {
			defer f.Close()
			const maxSize = 2 << 20 // 2MB
			return io.ReadAll(io.LimitReader(f, maxSize))
		}
	}
	// 极简系统 fallback: busybox cat
	out, err := s.runLocked(fmt.Sprintf("cat %s 2>/dev/null", shellQuotePath(path)))
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %v", path, err)
	}
	return []byte(out), nil
}

func (s *SSHExecutor) ListTargetDir(path string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sftpClient != nil {
		entries, err := s.sftpClient.ReadDir(path)
		if err == nil {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			return names, nil
		}
	}
	out, err := s.runLocked(fmt.Sprintf("ls -1 %s 2>/dev/null", shellQuotePath(path)))
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

// runLocked 不加锁执行（调用方需已持有 mu）
func (s *SSHExecutor) runLocked(cmdStr string) (string, error) {
	endMarker := fmt.Sprintf("__END_%d__", time.Now().UnixNano())
	fullCmd := fmt.Sprintf("%s; echo \"\"; echo \"%s:$?\"\n", cmdStr, endMarker)
	if _, err := s.stdin.Write([]byte(fullCmd)); err != nil {
		return "", err
	}
	collector := newOutputCollector(effectiveMaxOutputBytes())
	for {
		line, err := s.stdout.ReadString('\n')
		if err != nil {
			return collector.result(), err
		}
		if strings.Contains(line, endMarker) {
			break
		}
		collector.appendLine(line)
	}
	return collector.result(), nil
}

func shellQuotePath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
}

func (s *SSHExecutor) Close() {
	if s.sftpClient != nil {
		s.sftpClient.Close()
	}
	if s.session != nil {
		s.session.Close()
	}
	if s.client != nil {
		s.client.Close()
	}
}

// GbkToUtf8 核心转码函数：将 GBK 转换为 UTF-8
func GbkToUtf8(s []byte) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := io.ReadAll(reader)
	if e != nil {
		return s, e
	}
	return d, nil
}
