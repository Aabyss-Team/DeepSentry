package tui

import (
	"strings"
	"testing"

	"ai-edr/internal/ui"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

func TestRenderWelcomeBannerFitsWidth(t *testing.T) {
	info := StartupInfo{
		Version:    "2.0",
		BuildTime:  "2026-06-26",
		ModelInfo:  "lmstudio / local-model",
		ConnInfo:   "Fleet 多目标: 2 台",
		ConfigPath: "/Users/kaka/安全工具/自研工具/DeepSentry-deepagent/build/config.yaml",
		ReportPath: "/Users/kaka/安全工具/自研工具/DeepSentry-deepagent/build/reports/report.md",
		OS:         "Darwin",
		Arch:       "arm64",
		Username:   "kaka",
		WorkDir:    "/Users/kaka/安全工具/自研工具/DeepSentry-deepagent",
		ModeLine:   "🔌 [模式切换] 本地执行模式",
		ToolCount:  51,
		Tip:        "Tab 聚焦输入框，Enter 发送安全任务",
	}
	for _, w := range []int{96, 120, 140} {
		cw := ChromeContentWidth(w)
		out := renderWelcomeBanner(info, cw)
		plain := stripANSIForTest(out)
		lines := strings.Split(plain, "\n")
		sideBorder := "│"
		if ui.PlainTextMode() {
			sideBorder = "|"
		}
		if len(lines) > 22 {
			t.Fatalf("width=%d banner too tall: %d lines", w, len(lines))
		}
		for i, line := range lines {
			if got := lipgloss.Width(line); got != cw {
				t.Fatalf("width=%d line %d width mismatch: got=%d want=%d line=%q", w, i, got, cw, line)
			}
			if i > 0 && i < len(lines)-1 && !strings.HasPrefix(line, sideBorder) {
				t.Fatalf("width=%d broken side border at line %d: %q", w, i, line)
			}
		}
		if !strings.Contains(plain, "DeepSentry") {
			t.Fatalf("banner should include brand title: %q", plain)
		}
		if !strings.Contains(plain, "深海哨兵") {
			t.Fatalf("banner should include brand tagline: %q", plain)
		}
		if !strings.Contains(plain, "小技巧") {
			t.Fatalf("banner should include usage tip: %q", plain)
		}
		if !strings.Contains(plain, "目录") || !strings.Contains(plain, "报告") {
			t.Fatalf("banner should include workdir and report paths: %q", plain)
		}
	}
}

func TestBannerAndInputBoxAlign(t *testing.T) {
	w := 120
	cw := ChromeContentWidth(w)
	info := StartupInfo{
		Version:   "2.0",
		ModelInfo: "lmstudio / local-model",
		ConnInfo:  "local",
		Tip:       "test tip",
	}
	banner := stripANSIForTest(renderWelcomeBanner(info, cw))
	input := stripANSIForTest(renderChromeBox([]string{"hello"}, cw, styleBannerBorder))
	bLines := strings.Split(banner, "\n")
	iLines := strings.Split(input, "\n")
	if lipgloss.Width(bLines[0]) != lipgloss.Width(iLines[0]) {
		t.Fatalf("top border mismatch: banner=%d input=%d", lipgloss.Width(bLines[0]), lipgloss.Width(iLines[0]))
	}
	if lipgloss.Width(bLines[len(bLines)-1]) != lipgloss.Width(iLines[len(iLines)-1]) {
		t.Fatalf("bottom border mismatch")
	}
}

func TestBannerColumnRatio(t *testing.T) {
	cw := ChromeContentWidth(100)
	inner := cw - 2
	leftW := inner * 40 / 100
	rightW := inner - leftW - 1
	if leftW < 30 {
		t.Fatalf("left column too narrow: %d", leftW)
	}
	if rightW < leftW {
		t.Fatalf("expected right wider than left, left=%d right=%d", leftW, rightW)
	}
}

func TestRobotLogoSymmetric(t *testing.T) {
	lines := ui.RobotLogoLines()
	if len(lines) != 9 {
		t.Fatalf("expected 9 robot lines, got %d", len(lines))
	}
	wantW := 15
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			t.Fatalf("empty robot line at %d", i)
		}
		if got := runewidth.StringWidth(line); got != wantW {
			t.Fatalf("line %d width=%d want %d: %q", i, got, wantW, line)
		}
		if i == 5 && !strings.Contains(line, "SENTRY") {
			t.Fatalf("robot body should include SENTRY: %q", line)
		}
	}
	if len(robotLogoLines()) != len(lines) {
		t.Fatalf("styled line count mismatch")
	}
}

func TestRandomUsageTipStablePool(t *testing.T) {
	if len(bannerTips) < 20 {
		t.Fatalf("expected a rich tip pool, got %d", len(bannerTips))
	}
	seen := map[string]struct{}{}
	for i := 0; i < 80; i++ {
		tip := randomUsageTip()
		if tip == "" {
			t.Fatal("empty tip")
		}
		seen[tip] = struct{}{}
	}
	if len(seen) < 10 {
		t.Fatalf("expected varied tips, got %d unique in 80 draws", len(seen))
	}
}

func TestStartupTipPinnedAtInit(t *testing.T) {
	m := NewAgentModel(nil, "lmstudio / local-model", "local", 30, true, false, StartupInfo{
		Version:   "2.0",
		ModelInfo: "lmstudio / local-model",
	})
	if m.startupInfo.Tip == "" {
		t.Fatal("tip should be pinned once at model init")
	}
	if m.startupInfo.StartedAt == "" {
		t.Fatal("StartedAt should be pinned once at model init")
	}
	pinned := m.startupInfo.Tip
	startedAt := m.startupInfo.StartedAt
	m.width = 120
	m.height = 32
	m.recalcLayout()
	var firstBanner string
	for i := 0; i < 12; i++ {
		m.appendLine("info", "log line", "log")
		m.thinking = i%2 == 0
		m.refreshViewport()
		if m.startupInfo.Tip != pinned {
			t.Fatalf("refresh %d: startupInfo.Tip changed", i)
		}
		banner := stripANSIForTest(m.cachedWelcomeBanner(m.viewport.Width))
		if !strings.Contains(banner, pinned) {
			t.Fatalf("refresh %d: cached banner lost pinned tip %q", i, pinned)
		}
		if !strings.Contains(banner, startedAt) {
			t.Fatalf("refresh %d: cached banner lost pinned StartedAt %q", i, startedAt)
		}
		if firstBanner == "" {
			firstBanner = banner
		} else if banner != firstBanner {
			t.Fatalf("refresh %d: cached banner changed", i)
		}
	}
}

func TestStartupInfoShowsInViewport(t *testing.T) {
	m := NewAgentModel(nil, "lmstudio / local-model", "Fleet 多目标: 2 台", 30, true, false, StartupInfo{
		Version:   "2.0",
		ModelInfo: "lmstudio / local-model",
		ConnInfo:  "Fleet 多目标: 2 台",
		OS:        "Darwin",
		Arch:      "arm64",
		Tip:       "输入 /help 查看命令",
	})
	m.width = 120
	m.height = 32
	m.recalcLayout()
	m.refreshViewport()
	view := stripANSIForTest(m.viewport.View())
	if !strings.Contains(view, "DeepSentry") {
		t.Fatalf("viewport should render startup banner, got %q", view)
	}
}
