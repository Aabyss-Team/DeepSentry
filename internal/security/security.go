package security

import (
	"ai-edr/internal/executor"
	"crypto/md5"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// approvedCache 用于记录用户已授权的高危命令哈希
// 作用：一旦用户批准某条命令，本次运行期间不再重复询问
var (
	approvedCache = make(map[string]bool)
	cacheMutex    sync.RWMutex
)

// RecordApproval 记录用户已批准的命令
func RecordApproval(cmd string) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return
	}
	hash := fmt.Sprintf("%x", md5.Sum([]byte(cmd)))

	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	approvedCache[hash] = true
}

// isApproved 检查命令是否已被批准过
func isApproved(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	hash := fmt.Sprintf("%x", md5.Sum([]byte(cmd)))

	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	return approvedCache[hash]
}

var shellSplitRe = regexp.MustCompile(`\s*(?:&&|\|\||;)\s*`)

// CheckRisk 评估命令的风险等级。
// 策略尽量贴近 Claude Code 的交互体验：只读观测命令默认放行，明确有副作用的操作才确认。
// 返回值: (riskLevel: "high"|"low", reason: string)
func CheckRisk(cmd string) (string, string) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "low", "空命令"
	}

	// 0. [Session Cache] 检查是否是用户已批准过的命令
	if isApproved(cmd) {
		return "low", "用户已授权 (Session)"
	}

	analyzeCmd := normalizeCommand(cmd)

	if reason := dangerousShellPattern(analyzeCmd); reason != "" {
		return "high", reason
	}

	subCmds := splitShellCommands(analyzeCmd)
	for _, sub := range subCmds {
		risk, reason := checkSingleCommand(sub)
		if risk == "high" {
			return "high", reason
		}
	}

	return "low", "只读/低副作用操作"
}

// CanReviewHighRiskWithAI 判断一条规则命中的高风险命令是否适合交给 LLM 二次复核。
// 明确破坏、提权、持久化和管道执行脚本的命令仍保持硬拦截；只对容易误判的观测/枚举类命令链开放复核。
func CanReviewHighRiskWithAI(cmd, reason string) bool {
	cmd = strings.TrimSpace(cmd)
	reason = strings.TrimSpace(reason)
	if cmd == "" || reason == "" {
		return false
	}
	if isApproved(cmd) {
		return false
	}
	if isClearlyDestructive(cmd, reason) {
		return false
	}
	return true
}

func isClearlyDestructive(cmd, reason string) bool {
	analyzeCmd := strings.ToLower(normalizeCommand(cmd))
	reason = strings.ToLower(reason)

	if strings.Contains(reason, "管道执行脚本") {
		return true
	}

	hardVerbs := map[string]bool{
		"rm": true, "del": true, "erase": true, "rmdir": true,
		"mkfs": true, "format": true, "fdisk": true, "dd": true,
		"shred": true, "wipe": true, "truncate": true,
		"reboot": true, "shutdown": true, "halt": true, "poweroff": true, "init": true,
		"chown": true, "chgrp": true, "useradd": true, "usermod": true, "userdel": true,
		"passwd": true, "groupadd": true, "groupmod": true, "groupdel": true,
		"sudo": true, "su": true, "doas": true, "mount": true, "umount": true,
		"kill": true, "pkill": true, "killall": true, "taskkill": true,
		"invoke-expression": true, "iex": true,
	}
	for _, sub := range splitShellCommands(analyzeCmd) {
		parts := strings.Fields(sub)
		if len(parts) == 0 {
			continue
		}
		verb := strings.Trim(strings.ToLower(parts[0]), "\"'")
		if hardVerbs[verb] {
			return true
		}
	}

	if strings.Contains(analyzeCmd, "| sh") || strings.Contains(analyzeCmd, "| bash") ||
		strings.Contains(analyzeCmd, "| sudo") || strings.Contains(analyzeCmd, "| powershell") ||
		strings.Contains(analyzeCmd, "| pwsh") {
		return true
	}

	return false
}

func normalizeCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, "local_run ") {
		cmd = strings.TrimSpace(strings.TrimPrefix(cmd, "local_run "))
	}
	return cleanShellWrapper(cmd)
}

// cleanShellWrapper 清洗 Shell 包装器和引号
func cleanShellWrapper(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	prefixes := []string{"/bin/sh -c", "sh -c", "/bin/bash -c", "bash -c", "cmd /c", "powershell -Command", "powershell -c"}
	for _, p := range prefixes {
		if len(cmd) > len(p) && strings.EqualFold(cmd[:len(p)], p) {
			cmd = cmd[len(p):]
			cmd = strings.TrimSpace(cmd)
			break
		}
	}

	// 移除首尾的引号 (单引号或双引号)
	if len(cmd) >= 2 {
		first := cmd[0]
		last := cmd[len(cmd)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			cmd = cmd[1 : len(cmd)-1]
		}
	}

	return strings.TrimSpace(cmd)
}

func splitShellCommands(cmd string) []string {
	raw := shellSplitRe.Split(cmd, -1)
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func dangerousShellPattern(cmd string) string {
	lower := strings.ToLower(cmd)
	if strings.Contains(cmd, ">") {
		return "检测到文件重定向，可能覆盖/写入文件"
	}
	if strings.Contains(cmd, "|") {
		if strings.Contains(lower, "| sh") || strings.Contains(lower, "| bash") ||
			strings.Contains(lower, "| sudo") || strings.Contains(lower, "| powershell") ||
			strings.Contains(lower, "| pwsh") {
			return "检测到管道执行脚本"
		}
	}
	if strings.Contains(lower, "$(") || strings.Contains(lower, "`") {
		return "检测到命令替换，需确认真实执行内容"
	}
	return ""
}

// checkSingleCommand 单个命令判定逻辑
func checkSingleCommand(subCmd string) (string, string) {
	subCmd = strings.TrimSpace(subCmd)
	if subCmd == "" {
		return "low", ""
	}

	parts := strings.Fields(subCmd)
	if len(parts) == 0 {
		return "low", ""
	}

	// 获取动词并转小写
	verb := strings.ToLower(parts[0])
	// 二次清洗：防止动词本身带引号 (如 "cd")
	verb = strings.Trim(verb, "\"'")

	if isAssignmentOrEnvPrefix(verb) && len(parts) > 1 {
		return checkSingleCommand(strings.Join(parts[1:], " "))
	}

	lowRiskVerbs := map[string]bool{
		// 浏览与查看
		"ls": true, "dir": true, "pwd": true, "cd": true,
		"cat": true, "echo": true, "head": true, "tail": true,
		"more": true, "less": true, "tree": true,
		"find": true, "grep": true, "findstr": true,
		"stat": true, "file": true, "where": true, "which": true,
		"awk": true, "sed": true, "sort": true, "uniq": true, "wc": true,
		"cut": true, "tr": true, "xargs": true,

		// 系统/网络信息
		"whoami": true, "id": true, "hostname": true, "uname": true,
		"uptime": true, "date": true, "w": true, "who": true, "last": true,
		"lastlog": true, "groups": true, "env": true, "printenv": true,
		"history": true, "locale": true, "ulimit": true,
		"ps": true, "top": true, "tasklist": true, "free": true, "df": true, "du": true,
		"vmstat": true, "iostat": true, "mpstat": true, "sar": true,
		"lsof": true, "fuser": true, "journalctl": true, "dmesg": true,
		"loginctl": true, "systemd-analyze": true,
		"ipconfig": true, "ifconfig": true, "ip": true, "netstat": true, "ss": true,
		"ping": true, "arp": true, "route": true, "nslookup": true, "dig": true,
		"host": true, "traceroute": true, "tracepath": true, "mtr": true,
		"wmic": true, "ver": true, "scutil": true, "sw_vers": true,
		"curl": true, "wget": true,

		// 文件操作 (非破坏性)
		"mkdir": true, "touch": true, "type": true,

		"get-childitem": true, "gci": true,
		"get-content": true, "gc": true,
		"get-location": true, "gl": true,
		"get-process": true, "gps": true,
		"get-service": true, "gsv": true,
		"get-date": true, "get-host": true,
		"write-host": true, "write-output": true,
		"select-object": true, "where-object": true, "foreach-object": true,
	}

	if lowRiskVerbs[verb] {
		if reason := lowRiskCommandWithDangerousArgs(verb, parts[1:]); reason != "" {
			return "high", reason
		}
		return "low", "只读/低副作用操作"
	}

	highRiskVerbs := map[string]bool{
		// 破坏性操作
		"rm": true, "del": true, "erase": true, "rmdir": true,
		"mv": true, "move": true, "cp": true, "copy": true,
		"mkfs": true, "format": true, "fdisk": true, "dd": true,
		"shred": true, "wipe": true, "truncate": true,

		// 系统控制与权限
		"reboot": true, "shutdown": true, "halt": true, "poweroff": true, "init": true,
		"systemctl": true, "service": true, "sc": true, "reg": true,
		"chmod": true, "chown": true, "chgrp": true, "attrib": true,
		"useradd": true, "usermod": true, "userdel": true, "passwd": true,
		"groupadd": true, "groupmod": true, "groupdel": true,
		"sudo": true, "su": true, "doas": true,
		"mount": true, "umount": true, "crontab": true,

		// 进程与网络传输
		"kill": true, "pkill": true, "killall": true, "taskkill": true,
		"nc": true, "ncat": true, "socat": true,
		"ssh": true, "scp": true, "rsync": true, "ftp": true, "sftp": true,
		"nmap": true, "masscan": true, "tcpdump": true,

		// PowerShell 敏感操作
		"invoke-expression": true, "iex": true,
		"start-process": true,
	}

	if highRiskVerbs[verb] {
		return "high", fmt.Sprintf("敏感指令: %s", verb)
	}

	return "low", fmt.Sprintf("未识别指令(%s)，未发现写入/破坏/提权特征，按低风险执行", verb)
}

func isAssignmentOrEnvPrefix(verb string) bool {
	if verb == "env" {
		return true
	}
	return strings.Contains(verb, "=") && !strings.HasPrefix(verb, "-")
}

func lowRiskCommandWithDangerousArgs(verb string, args []string) string {
	for i, arg := range args {
		lower := strings.ToLower(strings.TrimSpace(arg))
		if lower == "" {
			continue
		}
		if lower == "-exec" || strings.HasPrefix(lower, "-exec=") || lower == "-delete" {
			return fmt.Sprintf("%s 参数包含可执行/删除动作: %s", verb, arg)
		}
		if verb == "xargs" && isDangerousToken(lower) {
			return fmt.Sprintf("xargs 将执行敏感指令: %s", arg)
		}
		if (verb == "sed" || verb == "perl") && (lower == "-i" || strings.HasPrefix(lower, "-i")) {
			return fmt.Sprintf("%s 原地修改文件", verb)
		}
		if verb == "curl" {
			if lower == "-o" || lower == "--output" || lower == "-O" || strings.HasPrefix(lower, "--output=") {
				return "curl 下载写入文件"
			}
			if lower == "-d" || lower == "--data" || lower == "--data-raw" || lower == "--data-binary" || strings.HasPrefix(lower, "-d") {
				return "curl 发送请求体，可能改变远端状态"
			}
			if (lower == "-x" || lower == "--request") && i+1 < len(args) {
				method := strings.ToUpper(strings.Trim(args[i+1], "\"'"))
				if method != "GET" && method != "HEAD" && method != "OPTIONS" {
					return "curl 使用非只读 HTTP 方法: " + method
				}
			}
		}
		if verb == "wget" && (lower == "-o" || lower == "-O" || lower == "--output-document" || strings.HasPrefix(lower, "--output-document=")) {
			return "wget 下载写入文件"
		}
		if i == 0 && isDangerousToken(lower) {
			return fmt.Sprintf("%s 将调用敏感指令: %s", verb, arg)
		}
	}
	return ""
}

func isDangerousToken(token string) bool {
	token = strings.Trim(token, "\"'")
	switch token {
	case "rm", "sh", "bash", "sudo", "su", "chmod", "chown", "systemctl", "service", "kill", "curl", "wget", "nc", "ncat":
		return true
	default:
		return false
	}
}

// SafeExecV3 执行命令的安全封装
func SafeExecV3(cmd string) (string, error) {
	if executor.Current == nil {
		return "", fmt.Errorf("执行器未初始化")
	}
	return executor.Current.Run(cmd)
}
