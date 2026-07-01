package harness

import (
	"ai-edr/internal/executor"
	"ai-edr/internal/memory"
	"ai-edr/internal/ui"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxFileReadDisplay = 8000

// fsPerspective 返回当前文件操作视角描述
func fsPerspective(local bool) string {
	if local {
		return "controller"
	}
	if executor.Current != nil && executor.Current.IsRemote() {
		return "target"
	}
	return "local"
}

func fsPerspectiveForExecutor(local bool, ex executor.Executor) string {
	if local {
		return "controller"
	}
	if ex != nil && ex.IsRemote() {
		return "target"
	}
	return "local"
}

func isControllerLocalPath(path string) bool {
	path = expandUserPath(path)
	if memory.IsAgentsMDPath(path) {
		return true
	}
	home, _ := os.UserHomeDir()
	workspace := filepath.Join(home, ".deepsentry", "workspace")
	abs, err := filepath.Abs(path)
	if err != nil {
		return strings.Contains(path, ".deepsentry/workspace") || strings.Contains(path, ".deepsentry\\workspace")
	}
	wsAbs, _ := filepath.Abs(workspace)
	return strings.HasPrefix(abs, wsAbs+string(os.PathSeparator)) || abs == wsAbs
}

func expandUserPath(path string) string {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}

func readTargetOrLocal(path string) ([]byte, error) {
	return readTargetOrLocalWithExecutor(path, executor.Current)
}

func readTargetOrLocalWithExecutor(path string, ex executor.Executor) ([]byte, error) {
	path = expandUserPath(path)
	if isControllerLocalPath(path) {
		return executor.ReadLocalFile(path)
	}
	if ex == nil {
		return nil, fmt.Errorf("执行器未初始化")
	}
	return executor.ReadFileWithExecutor(ex, path)
}

func writeTargetOrLocal(path string, content []byte) error {
	return writeTargetOrLocalWithExecutor(path, content, executor.Current)
}

func writeTargetOrLocalWithExecutor(path string, content []byte, ex executor.Executor) error {
	path = expandUserPath(path)
	if isControllerLocalPath(path) {
		return executor.WriteLocalFile(path, content)
	}
	return executor.WriteFileWithExecutor(ex, path, content)
}

func formatFSResult(perspective, body string) string {
	tag := perspective
	switch perspective {
	case "target":
		tag = "目标机"
	case "controller":
		tag = "控制端"
	case "local":
		tag = "本地"
	}
	return fmt.Sprintf("[视角: %s]\n%s", tag, body)
}

func truncateContent(content string, total int) string {
	if len(content) <= maxFileReadDisplay {
		if total > len(content) {
			return content + fmt.Sprintf("\n...(内容已截断，共 %d 字节)...", total)
		}
		return content
	}
	return content[:maxFileReadDisplay] + fmt.Sprintf("\n...(内容已截断，共 %d 字节)...", total)
}

func formatDirListing(path string, entries []executor.DirEntry) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("total %d\n", len(entries)))
	for _, e := range entries {
		prefix := "-"
		if e.IsDir {
			prefix = "d"
		}
		b.WriteString(fmt.Sprintf("%s %8d %s\n", prefix, e.Size, e.Name))
	}
	return b.String()
}

func editFileContent(path, oldStr, newStr string, replaceAll bool) (string, error) {
	return editFileContentWithExecutor(path, oldStr, newStr, replaceAll, executor.Current)
}

func editFileContentWithExecutor(path, oldStr, newStr string, replaceAll bool, ex executor.Executor) (string, error) {
	data, err := readTargetOrLocalWithExecutor(path, ex)
	if err != nil {
		return "", err
	}
	content := string(data)
	if oldStr == "" {
		return "", fmt.Errorf("old_string 不能为空")
	}
	if !strings.Contains(content, oldStr) {
		return "", fmt.Errorf("未找到 old_string，文件未修改")
	}
	var updated string
	if replaceAll {
		updated = strings.ReplaceAll(content, oldStr, newStr)
	} else {
		updated = strings.Replace(content, oldStr, newStr, 1)
	}
	if err := writeTargetOrLocalWithExecutor(path, []byte(updated), ex); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s已编辑 %s (%d -> %d 字节)", ui.Prefix("✅", "[OK]"), path, len(content), len(updated)), nil
}

func maybeReloadAgentsMD(store *memory.Store, path string, content []byte) {
	if store == nil {
		return
	}
	path = expandUserPath(path)
	if memory.IsAgentsMDPath(path) {
		store.UpdateAgentsMD(path, string(content))
	}
}
