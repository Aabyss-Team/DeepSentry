package executor

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ai-edr/internal/config"
	"ai-edr/internal/ui"
)

type FTPExecutor struct {
	conn   net.Conn
	reader *bufio.Reader
	host   string
	mu     sync.Mutex
}

func newFTPExecutor(cfg config.Config) (*FTPExecutor, error) {
	host := normalizeHostPort(cfg.FTPHost, "21")
	conn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("FTP 连接失败: %v", err)
	}
	f := &FTPExecutor{conn: conn, reader: bufio.NewReader(conn), host: host}
	if _, err := f.readResponse(); err != nil {
		conn.Close()
		return nil, err
	}
	user := cfg.FTPUser
	if user == "" {
		user = "anonymous"
	}
	pass := cfg.FTPPassword
	if pass == "" && user == "anonymous" {
		pass = "deepsentry@example.local"
	}
	if _, err := f.cmd("USER " + user); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := f.cmd("PASS " + pass); err != nil {
		conn.Close()
		return nil, err
	}
	_, _ = f.cmd("TYPE I")
	return f, nil
}

func (f *FTPExecutor) Run(cmd string) (string, error) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "", nil
	}
	switch parts[0] {
	case "download":
		if len(parts) != 3 {
			return "", fmt.Errorf("用法: download <远程文件> <本地路径>")
		}
		return f.downloadFile(parts[1], parts[2])
	case "upload":
		if len(parts) != 3 {
			return "", fmt.Errorf("用法: upload <本地文件> <远程路径>")
		}
		return f.uploadFile(parts[1], parts[2])
	case "pwd", "noop":
		return f.cmd(strings.ToUpper(parts[0]))
	default:
		return "", fmt.Errorf("FTP 模式不支持 shell 命令: %s；请使用 file_download/file_upload/ListTargetDir/ReadTargetFile", parts[0])
	}
}

func (f *FTPExecutor) ReadTargetFile(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	dataConn, err := f.pasv()
	if err != nil {
		return nil, err
	}
	if _, err := f.cmdNoRead("RETR " + path); err != nil {
		dataConn.Close()
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(dataConn, maxReadSize))
	_ = dataConn.Close()
	_, respErr := f.readTransferResponse()
	if readErr != nil {
		return nil, readErr
	}
	return data, respErr
}

func (f *FTPExecutor) ListTargetDir(path string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	dataConn, err := f.pasv()
	if err != nil {
		return nil, err
	}
	cmd := "NLST"
	if strings.TrimSpace(path) != "" {
		cmd += " " + path
	}
	if _, err := f.cmdNoRead(cmd); err != nil {
		dataConn.Close()
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(dataConn, maxReadSize))
	_ = dataConn.Close()
	_, respErr := f.readTransferResponse()
	if readErr != nil {
		return nil, readErr
	}
	if respErr != nil {
		return nil, respErr
	}
	var names []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			names = append(names, filepath.Base(line))
		}
	}
	return names, nil
}

func (f *FTPExecutor) IsRemote() bool { return true }
func (f *FTPExecutor) Mode() string   { return "ftp" }
func (f *FTPExecutor) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, _ = f.cmd("QUIT")
	_ = f.conn.Close()
}

func (f *FTPExecutor) uploadFile(localPath, remotePath string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	localPath = expandLocalPath(localPath)

	src, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer src.Close()
	dataConn, err := f.pasv()
	if err != nil {
		return "", err
	}
	if _, err := f.cmdNoRead("STOR " + remotePath); err != nil {
		dataConn.Close()
		return "", err
	}
	n, copyErr := io.Copy(dataConn, src)
	_ = dataConn.Close()
	_, respErr := f.readTransferResponse()
	if copyErr != nil {
		return "", copyErr
	}
	if respErr != nil {
		return "", respErr
	}
	return fmt.Sprintf("%sFTP 上传成功 (Bytes: %d): %s -> %s", ui.Prefix("✅", "[OK]"), n, localPath, remotePath), nil
}

func (f *FTPExecutor) downloadFile(remotePath, localPath string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	localPath = expandLocalPath(localPath)

	dataConn, err := f.pasv()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		dataConn.Close()
		return "", err
	}
	if _, err := f.cmdNoRead("RETR " + remotePath); err != nil {
		dataConn.Close()
		return "", err
	}
	dst, err := os.Create(localPath)
	if err != nil {
		dataConn.Close()
		return "", err
	}
	n, copyErr := io.Copy(dst, dataConn)
	_ = dst.Close()
	_ = dataConn.Close()
	_, respErr := f.readTransferResponse()
	if copyErr != nil {
		return "", copyErr
	}
	if respErr != nil {
		return "", respErr
	}
	return fmt.Sprintf("%sFTP 下载成功 (Bytes: %d): %s -> %s", ui.Prefix("✅", "[OK]"), n, remotePath, localPath), nil
}

func (f *FTPExecutor) cmd(command string) (string, error) {
	if _, err := f.cmdNoRead(command); err != nil {
		return "", err
	}
	return f.readResponse()
}

func (f *FTPExecutor) cmdNoRead(command string) (string, error) {
	_, err := fmt.Fprintf(f.conn, "%s\r\n", command)
	return command, err
}

func (f *FTPExecutor) readResponse() (string, error) {
	_ = f.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer f.conn.SetReadDeadline(time.Time{})
	line, err := f.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	code := ""
	if len(line) >= 3 {
		code = line[:3]
	}
	var b strings.Builder
	b.WriteString(line)
	if len(line) > 3 && line[3] == '-' {
		for {
			l, err := f.reader.ReadString('\n')
			if err != nil {
				return b.String(), err
			}
			b.WriteString(l)
			if strings.HasPrefix(l, code+" ") {
				break
			}
		}
	}
	if code >= "400" {
		return b.String(), fmt.Errorf("%s", strings.TrimSpace(b.String()))
	}
	return b.String(), nil
}

func (f *FTPExecutor) readTransferResponse() (string, error) {
	resp, err := f.readResponse()
	if err != nil {
		return resp, err
	}
	if isFTPPreliminary(resp) {
		finalResp, finalErr := f.readResponse()
		return resp + finalResp, finalErr
	}
	return resp, nil
}

func isFTPPreliminary(resp string) bool {
	resp = strings.TrimSpace(resp)
	if len(resp) < 3 {
		return false
	}
	code, err := strconv.Atoi(resp[:3])
	return err == nil && code >= 100 && code < 200
}

func (f *FTPExecutor) pasv() (net.Conn, error) {
	resp, err := f.cmd("PASV")
	if err != nil {
		return nil, err
	}
	start := strings.Index(resp, "(")
	end := strings.Index(resp, ")")
	if start < 0 || end < start {
		return nil, fmt.Errorf("无法解析 PASV 响应: %s", resp)
	}
	parts := strings.Split(resp[start+1:end], ",")
	if len(parts) != 6 {
		return nil, fmt.Errorf("非法 PASV 响应: %s", resp)
	}
	p1, _ := strconv.Atoi(strings.TrimSpace(parts[4]))
	p2, _ := strconv.Atoi(strings.TrimSpace(parts[5]))
	port := p1*256 + p2
	host := strings.Join(parts[:4], ".")
	return net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 10*time.Second)
}
