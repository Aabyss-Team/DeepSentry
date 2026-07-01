package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestRenderMarkdownReportRendersTableAndInlineStyles(t *testing.T) {
	md := strings.Join([]string{
		"# 总结",
		"",
		"✅ 已完成以下操作：",
		"",
		"| 步骤 | 操作 | 结果 |",
		"|------|------|------|",
		"| 1 | 创建 `/tmp/test_flag.txt` | **成功** |",
		"| 2 | 下载到本机 | 成功 |",
		"",
		"解压密码是 **123456**。",
	}, "\n")

	rendered := renderMarkdownReport(md, 96)
	plain := stripANSIForTest(rendered)
	for _, bad := range []string{"|------|", "**123456**", "`/tmp/test_flag.txt`", "# 总结"} {
		if strings.Contains(plain, bad) {
			t.Fatalf("markdown marker %q should not remain in rendered report:\n%s", bad, plain)
		}
	}
	for _, want := range []string{"总结", "步骤", "操作", "结果", "123456"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("rendered report missing %q:\n%s", want, plain)
		}
	}
	if !strings.Contains(plain, "┌") && !strings.Contains(plain, "+") {
		t.Fatalf("table should render with borders:\n%s", plain)
	}
}

func TestRenderMarkdownReportFitsWidth(t *testing.T) {
	md := "| 字段 | 很长的说明 |\n|---|---|\n| 路径 | /var/www/html/uploads/reports/report_20260630_214228.md |"
	rendered := renderMarkdownReport(md, 48)
	for _, line := range strings.Split(rendered, "\n") {
		if got := lipgloss.Width(line); got > 48 {
			t.Fatalf("rendered markdown line width=%d want <=48: %q", got, line)
		}
	}
}
