package executor

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ai-edr/internal/config"
)

type FleetResult struct {
	Target   config.TargetConfig
	Success  bool
	Output   string
	Error    string
	Duration time.Duration
}

type FleetProgress struct {
	Target config.TargetConfig
	Status string
	Output string
	Error  string
}

func MatchTargets(targets []config.TargetConfig, selector string) []config.TargetConfig {
	selector = strings.TrimSpace(selector)
	if selector == "" || selector == "all" {
		return targets
	}
	parts := strings.Split(selector, ",")
	want := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			want[p] = true
		}
	}
	var out []config.TargetConfig
	for _, t := range targets {
		if want[t.Name] || want[t.Host] || want[t.Protocol] {
			out = append(out, t)
			continue
		}
		for _, tag := range t.Tags {
			if want[tag] || want["tag:"+tag] {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

func RunFleet(targets []config.TargetConfig, selector, command string, concurrency int) []FleetResult {
	return RunFleetWithProgress(targets, selector, command, concurrency, nil)
}

func RunFleetWithProgress(targets []config.TargetConfig, selector, command string, concurrency int, onProgress func(FleetProgress)) []FleetResult {
	selected := MatchTargets(targets, selector)
	if concurrency <= 0 {
		concurrency = 5
	}
	if concurrency > 20 {
		concurrency = 20
	}
	results := make([]FleetResult, 0, len(selected))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, target := range selected {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			if onProgress != nil {
				onProgress(FleetProgress{Target: target, Status: "running"})
			}
			var out string
			var err error
			if strings.EqualFold(target.Protocol, "ftp") {
				err = fmt.Errorf("FTP 目标不支持 shell 命令，请使用 fleet_file")
			} else {
				out, err = RunOnTarget(target, command)
			}
			res := FleetResult{Target: target, Success: err == nil, Output: out, Duration: time.Since(start)}
			if err != nil {
				res.Error = err.Error()
			}
			if onProgress != nil {
				status := "ok"
				if err != nil {
					status = "error"
				}
				onProgress(FleetProgress{Target: target, Status: status, Output: out, Error: res.Error})
			}
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Target.Name < results[j].Target.Name })
	return results
}

func RunOnTarget(target config.TargetConfig, command string) (string, error) {
	exe, err := NewEphemeralExecutor(target)
	if err != nil {
		return "", err
	}
	defer exe.Close()
	return exe.Run(command)
}

func NewEphemeralExecutor(target config.TargetConfig) (Executor, error) {
	cfg := config.GlobalConfig
	switch strings.ToLower(strings.TrimSpace(target.Protocol)) {
	case "ssh":
		cfg.TargetProtocol = "ssh"
		cfg.SSHHost = target.Host
		cfg.SSHUser = firstNonEmpty(target.User, cfg.SSHUser, "root")
		cfg.SSHPassword = target.Password
		cfg.SSHKeyPath = target.KeyPath
		return newSSHExecutor(cfg)
	case "telnet":
		cfg.TargetProtocol = "telnet"
		cfg.TelnetHost = target.Host
		cfg.TelnetUser = firstNonEmpty(target.User, cfg.TelnetUser, "root")
		cfg.TelnetPassword = target.Password
		cfg.TelnetPrompt = target.Prompt
		return newTelnetExecutor(cfg)
	case "ftp":
		cfg.TargetProtocol = "ftp"
		cfg.FTPHost = target.Host
		cfg.FTPUser = firstNonEmpty(target.User, cfg.FTPUser, "anonymous")
		cfg.FTPPassword = target.Password
		return newFTPExecutor(cfg)
	default:
		return nil, fmt.Errorf("目标 %s 协议不支持: %s", target.Name, target.Protocol)
	}
}

func FleetFile(target config.TargetConfig, action, remotePath, localPath string) (string, error) {
	exe, err := NewEphemeralExecutor(target)
	if err != nil {
		return "", err
	}
	defer exe.Close()
	switch action {
	case "ls":
		names, err := exe.ListTargetDir(remotePath)
		return strings.Join(names, "\n"), err
	case "read":
		data, err := exe.ReadTargetFile(remotePath)
		return string(data), err
	case "download":
		return downloadWithExecutor(exe, remotePath, localPath)
	case "upload":
		return uploadWithExecutor(exe, localPath, remotePath)
	default:
		return "", fmt.Errorf("fleet file action 仅支持 ls|read|download|upload")
	}
}

func downloadWithExecutor(exe Executor, remotePath, localPath string) (string, error) {
	switch e := exe.(type) {
	case *SSHExecutor:
		return e.downloadFile(remotePath, localPath)
	case *FTPExecutor:
		return e.downloadFile(remotePath, localPath)
	case *LocalExecutor:
		return copyLocalFile(remotePath, localPath)
	default:
		return "", fmt.Errorf("%s 不支持 download", CurrentModeOf(exe))
	}
}

func uploadWithExecutor(exe Executor, localPath, remotePath string) (string, error) {
	switch e := exe.(type) {
	case *SSHExecutor:
		return e.uploadFile(localPath, remotePath)
	case *FTPExecutor:
		return e.uploadFile(localPath, remotePath)
	case *LocalExecutor:
		return copyLocalFile(localPath, remotePath)
	default:
		return "", fmt.Errorf("%s 不支持 upload", CurrentModeOf(exe))
	}
}

func FormatFleetResults(results []FleetResult) string {
	var b strings.Builder
	success := 0
	for _, r := range results {
		if r.Success {
			success++
		}
	}
	b.WriteString(fmt.Sprintf("Fleet 执行完成: %d/%d 成功\n\n", success, len(results)))
	for _, r := range results {
		status := "OK"
		if !r.Success {
			status = "ERR"
		}
		name := firstNonEmpty(r.Target.Name, r.Target.Host)
		b.WriteString(fmt.Sprintf("[%s] %s (%s %s) %s\n", status, name, r.Target.Protocol, r.Target.Host, r.Duration.Round(time.Millisecond)))
		if r.Error != "" {
			b.WriteString("error: " + r.Error + "\n")
		}
		if strings.TrimSpace(r.Output) != "" {
			b.WriteString(truncateFleetOutput(r.Output, 2000) + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncateFleetOutput(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n...(单目标输出已截断)..."
}

func TargetDisplayName(t config.TargetConfig) string {
	name := firstNonEmpty(t.Name, filepath.Base(t.Host), t.Host)
	if len(t.Tags) > 0 {
		return fmt.Sprintf("%s [%s]", name, strings.Join(t.Tags, ","))
	}
	return name
}
