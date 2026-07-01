package builtin

import (
	"ai-edr/internal/executor"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ScriptRun(rt Runtime, language, content, path, args string, timeoutSec int) (string, error) {
	language = strings.ToLower(strings.TrimSpace(language))
	if language == "" {
		language = "python"
	}
	if language != "python" && language != "shell" && language != "sh" {
		return "", fmt.Errorf("script_run 仅支持 language=python|shell")
	}
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	if timeoutSec > 300 {
		timeoutSec = 300
	}
	if executor.Current == nil {
		return "", fmt.Errorf("执行器未初始化")
	}

	scriptPath := strings.TrimSpace(path)
	cleanup := false
	if strings.TrimSpace(content) != "" {
		ext := ".py"
		if language == "shell" || language == "sh" {
			ext = ".sh"
		}
		scriptPath = fmt.Sprintf("/tmp/deepsentry_script_%d%s", time.Now().UnixNano(), ext)
		if !executor.Current.IsRemote() {
			scriptPath = filepath.Join(os.TempDir(), filepath.Base(scriptPath))
		}
		if err := executor.WriteTargetFile(scriptPath, []byte(content)); err != nil {
			return "", err
		}
		cleanup = true
	}
	if scriptPath == "" {
		return "", fmt.Errorf("必须提供 content 或 path")
	}

	var cmd string
	quotedPath := shellQuote(scriptPath)
	switch language {
	case "python":
		cmd = fmt.Sprintf("timeout %d python3 %s %s 2>&1 || timeout %d python %s %s 2>&1", timeoutSec, quotedPath, args, timeoutSec, quotedPath, args)
	default:
		cmd = fmt.Sprintf("timeout %d sh %s %s 2>&1", timeoutSec, quotedPath, args)
	}
	start := time.Now()
	out, err := executor.Current.Run(cmd)
	elapsed := time.Since(start).Round(time.Millisecond)
	if cleanup {
		_, _ = executor.Current.Run("rm -f " + quotedPath)
	}

	logPath := writeToolExecLog("script_run", fmt.Sprintf("language=%s path=%s args=%s timeout=%d", language, scriptPath, args, timeoutSec), out, err)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s 受控脚本执行\n", rt.tag()))
	b.WriteString(fmt.Sprintf("language=%s path=%s elapsed=%v\n", language, scriptPath, elapsed))
	if logPath != "" {
		b.WriteString("执行日志: " + logPath + "\n")
	}
	if err != nil {
		b.WriteString("状态: 失败: " + err.Error() + "\n")
	} else {
		b.WriteString("状态: 完成\n")
	}
	b.WriteString("\n输出:\n" + truncate(out, 30000))
	return b.String(), err
}

func writeToolExecLog(tool, meta, output string, runErr error) string {
	if err := os.MkdirAll("reports", 0755); err != nil {
		return ""
	}
	path := filepath.Join("reports", fmt.Sprintf("tool_exec_%s_%d.log", tool, time.Now().UnixNano()))
	var b strings.Builder
	b.WriteString("tool: " + tool + "\n")
	b.WriteString("time: " + time.Now().Format(time.RFC3339) + "\n")
	b.WriteString("meta: " + meta + "\n")
	if runErr != nil {
		b.WriteString("error: " + runErr.Error() + "\n")
	}
	b.WriteString("\noutput:\n")
	b.WriteString(output)
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		return ""
	}
	return path
}
