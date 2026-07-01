package logger

import (
	"ai-edr/internal/analyzer"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Reporter 负责生成审计报告
type Reporter struct {
	file  *os.File
	path  string
	title string
}

// NewReporter 创建一个新的审计报告文件
func NewReporter() (*Reporter, string, error) {
	return NewReporterWithTitle(DefaultReportTitle)
}

const DefaultReportTitle = "DeepSentry 安全排查报告"

// NewReporterWithTitle 创建一个新的审计报告文件，并使用任务相关标题。
func NewReporterWithTitle(title string) (*Reporter, string, error) {
	fullPath := strings.TrimSpace(os.Getenv("DEEPSENTRY_REPORT_PATH"))
	if fullPath == "" {
		timestamp := time.Now().Format("20060102_150405")
		fullPath = filepath.Join("reports", fmt.Sprintf("report_%s.md", timestamp))
	}
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return nil, "", fmt.Errorf("无法创建日志目录: %v", err)
	}

	// 3. 创建文件
	file, err := os.Create(fullPath)
	if err != nil {
		return nil, "", fmt.Errorf("无法创建报告文件: %v", err)
	}

	// 🟢 [核心修复] 写入 UTF-8 BOM (Byte Order Mark)
	// Windows 的记事本和部分编辑器在打开没有 BOM 的 UTF-8 文件时，
	// 可能会错误地将其识别为 GBK 编码，导致中文显示为乱码。
	// 写入这三个字节 (\xEF\xBB\xBF) 可以显式声明文件为 UTF-8 编码。
	file.WriteString("\xEF\xBB\xBF")

	// 4. 写入报告头部信息
	title = NormalizeReportTitle(title)
	header := fmt.Sprintf("# %s\n\n"+
		"- **启动时间**: %s\n"+
		"- **操作员**: %s\n"+
		"- **工具版本**: v2.0 Ultimate\n\n"+
		"---\n\n",
		title,
		time.Now().Format("2006-01-02 15:04:05"),
		currentUser(),
	)
	file.WriteString(header)

	return &Reporter{
		file:  file,
		path:  fullPath,
		title: title,
	}, fullPath, nil
}

func currentUser() string {
	if user := strings.TrimSpace(os.Getenv("USER")); user != "" {
		return user
	}
	return strings.TrimSpace(os.Getenv("USERNAME"))
}

// TitleFromHistory 从当前会话里提取适合作为报告标题的任务名。
func TitleFromHistory(history []analyzer.Message) string {
	for i := len(history) - 1; i >= 0; i-- {
		if history[i].Role != "user" {
			continue
		}
		if title := NormalizeReportTitle(history[i].Content); title != DefaultReportTitle {
			return title
		}
	}
	return DefaultReportTitle
}

// NormalizeReportTitle 将用户需求整理成简洁的 Markdown 报告标题。
func NormalizeReportTitle(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return DefaultReportTitle
	}
	replacers := []string{
		"【用户中途打断/改写目标】", "",
		"需求：", "", "需求:", "",
		"用户补充：", "", "用户补充:", "",
		"--task", "", "-q", "",
		"\"", "", "'", "", "`", "",
	}
	r := strings.NewReplacer(replacers...)
	s = r.Replace(s)
	s = strings.Join(strings.Fields(s), " ")
	s = strings.Trim(s, " ，。,.!！?？:：;；-_")
	if s == "" {
		return DefaultReportTitle
	}

	runes := []rune(s)
	const maxRunes = 36
	if len(runes) > maxRunes {
		s = string(runes[:maxRunes])
		s = strings.Trim(s, " ，。,.!！?？:：;；-_") + "..."
	}
	if !hasReportLikeSuffix(s) {
		if len([]rune(s)) <= 6 {
			s += "安全排查报告"
		} else {
			s += "报告"
		}
	}
	return s
}

func hasReportLikeSuffix(s string) bool {
	return strings.Contains(s, "报告") || strings.Contains(s, "排查") ||
		strings.Contains(s, "巡检") || strings.Contains(s, "审计") ||
		strings.Contains(s, "分析")
}

// SetTitle 更新报告第一行标题。TUI 首屏等待用户输入任务时，报告可在任务开始后再重命名。
func (r *Reporter) SetTitle(title string) error {
	if r == nil || r.file == nil || r.path == "" {
		return nil
	}
	title = NormalizeReportTitle(title)
	if title == "" || title == r.title {
		return nil
	}
	if err := r.file.Sync(); err != nil {
		return err
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	const bom = "\xEF\xBB\xBF"
	content := string(data)
	prefix := ""
	if strings.HasPrefix(content, bom) {
		prefix = bom
		content = strings.TrimPrefix(content, bom)
	}
	lines := strings.SplitN(content, "\n", 2)
	if len(lines) == 0 {
		return nil
	}
	if !strings.HasPrefix(lines[0], "# ") {
		return nil
	}
	rest := ""
	if len(lines) > 1 {
		rest = "\n" + lines[1]
	}
	updated := prefix + "# " + title + rest
	if err := r.file.Truncate(0); err != nil {
		return err
	}
	if _, err := r.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := r.file.WriteString(updated); err != nil {
		return err
	}
	if _, err := r.file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	r.title = title
	return r.file.Sync()
}

// Log 记录常规思考和日志
func (r *Reporter) Log(title, content string) {
	if r.file == nil {
		return
	}
	timestamp := time.Now().Format("15:04:05")
	// 使用 Markdown 格式记录
	entry := fmt.Sprintf("### [%s] %s\n%s\n\n", timestamp, title, content)

	if _, err := r.file.WriteString(entry); err == nil {
		// 强制刷入磁盘，防止程序意外崩溃导致日志未保存
		r.file.Sync()
	}
}

// LogCommand 专门记录命令执行
func (r *Reporter) LogCommand(cmd, output string) {
	if r.file == nil {
		return
	}

	// 对超长输出进行截断，避免报告体积过大导致阅读困难
	if len(output) > 2000 {
		output = output[:2000] + "\n... (输出过长已截断) ..."
	}

	// 格式化为代码块
	entry := fmt.Sprintf("```bash\n> %s\n```\n**执行结果**:\n```text\n%s\n```\n\n", cmd, output)

	if _, err := r.file.WriteString(entry); err == nil {
		r.file.Sync()
	}
}

// Close 关闭文件句柄
func (r *Reporter) Close() {
	if r.file != nil {
		r.file.Close()
		r.file = nil
	}
}
