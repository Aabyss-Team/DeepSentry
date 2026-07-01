package tui

import (
	"ai-edr/internal/harness"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestRenderWrappedKeepsToolOutputWithinViewport(t *testing.T) {
	m := NewAgentModel(nil, "model", "local", 30, true, false, StartupInfo{})
	m.width = 48
	m.height = 18
	m.recalcLayout()

	longPorts := strings.Repeat(":8080|:8081|:8082|:8083|:8084|", 8)
	m.appendLine("tool", "Shell · ss -tuln | grep -E '"+longPorts+"'", longPorts)
	m.refreshViewport()

	for _, line := range strings.Split(m.viewport.View(), "\n") {
		if got := lipgloss.Width(line); got > m.viewport.Width {
			t.Fatalf("rendered line width = %d, want <= %d: %q", got, m.viewport.Width, stripANSIForTest(line))
		}
	}
}

func TestInputFocusedAbsorbsGlobalShortcuts(t *testing.T) {
	shortcuts := []string{"q", "e", "j", "k"}
	for _, k := range shortcuts {
		m := NewAgentModel(nil, "model", "local", 30, true, false, StartupInfo{})
		if !m.inputFocused() {
			t.Fatalf("key %q: expected input focused", k)
		}
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
		model := updated.(AgentModel)
		if model.quitting {
			t.Fatalf("key %q should not quit when input focused", k)
		}
		if !strings.Contains(model.input.Value(), k) {
			t.Fatalf("key %q should be typed into input, got %q", k, model.input.Value())
		}
	}
}

func TestGlobalQuitOnlyWhenInputBlurred(t *testing.T) {
	m := NewAgentModel(nil, "model", "local", 30, false, false, StartupInfo{})
	m.done = true
	m.input.Blur()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	model := updated.(AgentModel)
	if !model.quitting {
		t.Fatal("q should quit when input blurred and session idle")
	}
	if cmd == nil {
		t.Fatal("expected quit command")
	}
}

func TestTruncateStrIsUnicodeSafe(t *testing.T) {
	got := truncateStr("这个任务会检查 Windows Terminal 里的 emoji ✅ 和中文宽度", 18)
	if !utf8.ValidString(got) {
		t.Fatalf("truncateStr returned invalid UTF-8: %q", got)
	}
	if width := lipgloss.Width(got); width > 18 {
		t.Fatalf("truncateStr width = %d, want <= 18: %q", width, got)
	}
}

func TestTargetStatusUpdatesCurrentTarget(t *testing.T) {
	m := NewAgentModel(nil, "model", "Fleet 多目标: 2 台", 30, true, false, StartupInfo{})
	m.applyEvent(harness.UIEvent{
		Kind:           harness.EventTargetStatus,
		Status:         "running",
		Message:        "fleet_exec uptime",
		TargetName:     "web-01",
		TargetProtocol: "ssh",
		TargetHost:     "10.0.0.1:22",
	})
	if !strings.Contains(m.currentTarget, "web-01") {
		t.Fatalf("current target not updated: %q", m.currentTarget)
	}
	if len(m.lines) == 0 || m.lines[len(m.lines)-1].kind != "target" {
		t.Fatalf("target event not appended: %#v", m.lines)
	}
}

func TestFormatActionLineShowsExecutionTarget(t *testing.T) {
	local := FormatActionLine(&harness.AgentAction{Type: harness.ActionExecute, Command: "date", TargetProtocol: "local"})
	if !strings.Contains(local, "控制端本机") || !strings.Contains(local, "date") {
		t.Fatalf("local action line missing target: %q", local)
	}
	if strings.Contains(local, "远端") {
		t.Fatalf("local action line should not be remote: %q", local)
	}

	localRun := FormatActionLine(&harness.AgentAction{Type: harness.ActionExecute, Command: "local_run hostname", TargetProtocol: "local", TargetHost: "8.137.114.242:2222"})
	if !strings.Contains(localRun, "控制端本机") || strings.Contains(localRun, "远端") {
		t.Fatalf("local_run action line should stay local even with stale host: %q", localRun)
	}

	remote := FormatActionLine(&harness.AgentAction{Type: harness.ActionExecute, Command: "id", TargetProtocol: "ssh", TargetHost: "8.137.114.242:2222"})
	for _, want := range []string{"远端 SSH", "8.137.114.242:2222", "id"} {
		if !strings.Contains(remote, want) {
			t.Fatalf("remote action line missing %q: %q", want, remote)
		}
	}

	fleet := FormatActionLine(&harness.AgentAction{Type: harness.ActionExecute, Command: "uptime", TargetName: "web-01", TargetProtocol: "ssh", TargetHost: "10.0.0.1:22"})
	for _, want := range []string{"远端 SSH", "web-01", "10.0.0.1:22", "uptime"} {
		if !strings.Contains(fleet, want) {
			t.Fatalf("fleet action line missing %q: %q", want, fleet)
		}
	}
}

func TestFormatActionLineShowsIncompleteSubAgentTask(t *testing.T) {
	line := FormatActionLine(&harness.AgentAction{Type: harness.ActionTask})
	if !strings.Contains(line, "参数不完整") {
		t.Fatalf("empty sub-agent task should show incomplete params: %q", line)
	}
	if strings.Contains(line, "->") || strings.Contains(line, "→") {
		t.Fatalf("empty sub-agent task should not render an empty arrow: %q", line)
	}
}

func TestStatusContextAvoidsNoActivityPlaceholder(t *testing.T) {
	m := NewAgentModel(nil, "model", "SSH -> 1.2.3.4:22", 30, true, false, StartupInfo{})
	if got := m.statusContextText(); got != "就绪/等待任务" {
		t.Fatalf("idle status=%q", got)
	}
	m.running = true
	if got := m.statusContextText(); got != "执行中" {
		t.Fatalf("running status=%q", got)
	}
	m.thinking = true
	if got := m.statusContextText(); got != "模型思考中" {
		t.Fatalf("thinking status=%q", got)
	}
	m.currentTarget = "web-01 (ssh 10.0.0.1:22)"
	if got := m.statusContextText(); !strings.Contains(got, "web-01") {
		t.Fatalf("target status=%q", got)
	}
}

func TestAwaitUserEventAndAskMsgDeduplicate(t *testing.T) {
	m := NewAgentModel(nil, "model", "local", 30, false, false, StartupInfo{})
	action := &harness.AgentAction{
		Type:     harness.ActionAskUser,
		Question: "请选择 CPU 告警阈值",
		Options:  []string{"CPU阈值 80%", "CPU阈值 90%"},
	}
	m.applyEvent(harness.UIEvent{
		Kind:    harness.EventAwaitUser,
		Message: "请选择 CPU 告警阈值\n\n可选：\n1. CPU阈值 80%\n2. CPU阈值 90%",
		Action:  action,
	})
	updated, _ := m.Update(askMsg{
		action:  action,
		prompt:  action.Question,
		options: action.Options,
		respCh:  make(chan string, 1),
	})
	model := updated.(AgentModel)
	askLines := 0
	for _, line := range model.lines {
		if line.kind == "ask" {
			askLines++
			if strings.Count(line.content, "CPU阈值 80%") != 1 {
				t.Fatalf("option rendered more than once: %q", line.content)
			}
		}
	}
	if askLines != 1 {
		t.Fatalf("expected one ask line, got %d: %#v", askLines, model.lines)
	}
}

func TestInputViewRendersFocusedInputAboveHelpLine(t *testing.T) {
	m := NewAgentModel(nil, "model", "local", 30, true, false, StartupInfo{})
	m.width = 80
	m.height = 24
	m.recalcLayout()
	m.input.SetValue("ni")
	m.input.SetCursor(2)

	view := m.View()
	row, col, ok := m.inputCursorAnchor()
	if !ok {
		t.Fatal("focused input should expose terminal cursor anchor")
	}
	if strings.Contains(view, fmt.Sprintf("\x1b[%d;%dH", row, col)) {
		t.Fatalf("view should not embed cursor movement; anchor must run after renderer")
	}
	if row <= 0 || col <= 0 {
		t.Fatalf("invalid cursor anchor row=%d col=%d", row, col)
	}
	m.scheduleInputCursorAnchor()
	lines := strings.Split(stripANSIForTest(view), "\n")
	var inputLine string
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "ni") {
			inputLine = lines[i]
			break
		}
	}
	if inputLine == "" {
		t.Fatalf("focused input should render in bordered box, got footer %#v", lines[len(lines)-4:])
	}
	lastLine := strings.TrimRight(lines[len(lines)-1], " ")
	if !strings.Contains(lastLine, "Enter 发送") {
		t.Fatalf("help line should stay below input, got %q", lastLine)
	}
}

func TestFocusedInputCursorAnchorUsesDisplayColumns(t *testing.T) {
	m := NewAgentModel(nil, "model", "local", 30, true, false, StartupInfo{})
	m.width = 80
	m.height = 24
	m.recalcLayout()
	m.input.SetValue("你好abc")
	m.input.SetCursor(2)

	_, col, ok := m.inputCursorAnchor()
	if !ok {
		t.Fatal("expected cursor anchor")
	}
	if col != 7 {
		t.Fatalf("cursor col = %d, want 7 for two CJK runes plus input chrome", col)
	}
	content := m.renderFocusedInputContent(20)
	if !strings.Contains(stripANSIForTest(content), "你好abc") {
		t.Fatalf("focused input should preserve text, got %q", stripANSIForTest(content))
	}
}

func TestSlashCommandTabCompletesFirstSuggestion(t *testing.T) {
	m := NewAgentModel(nil, "model", "local", 30, true, false, StartupInfo{})
	m.width = 80
	m.height = 24
	m.recalcLayout()
	m.input.SetValue("/c")
	m.input.SetCursor(2)
	m.recalcLayout()
	withSuggestionsHeight := m.viewport.Height

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	model := updated.(AgentModel)
	if got := model.input.Value(); got != "/clear" {
		t.Fatalf("tab completion = %q, want /clear", got)
	}
	if model.hasSlashSuggestions() {
		t.Fatalf("slash suggestions should close after exact completion")
	}
	if model.slashSuggestionLineCount() != 0 {
		t.Fatalf("suggestion rows should be gone after completion")
	}
	if model.viewport.Height <= withSuggestionsHeight {
		t.Fatalf("viewport height should return after suggestions close: got=%d before=%d", model.viewport.Height, withSuggestionsHeight)
	}
}

func TestSlashCommandSuggestionsRenderAboveInput(t *testing.T) {
	m := NewAgentModel(nil, "model", "local", 30, true, false, StartupInfo{})
	m.width = 80
	m.height = 24
	m.input.SetValue("/c")
	m.input.SetCursor(2)
	m.recalcLayout()

	view := stripANSIForTest(m.View())
	if !strings.Contains(view, "/clear") {
		t.Fatalf("slash suggestions should include /clear: %q", view)
	}
	lines := strings.Split(view, "\n")
	clearIdx, inputIdx, helpIdx := -1, -1, -1
	for i, line := range lines {
		if clearIdx < 0 && strings.Contains(line, "/clear") {
			clearIdx = i
		}
		if inputIdx < 0 && strings.Contains(line, "/c") && !strings.Contains(line, "/clear") {
			inputIdx = i
		}
		if strings.Contains(line, "Enter 发送") {
			helpIdx = i
		}
	}
	if clearIdx < 0 || inputIdx < 0 || helpIdx < 0 {
		t.Fatalf("missing suggestion/input/help rows: clear=%d input=%d help=%d\n%s", clearIdx, inputIdx, helpIdx, view)
	}
	if !(clearIdx < inputIdx && inputIdx < helpIdx) {
		t.Fatalf("expected suggestions above input and help below input, got clear=%d input=%d help=%d", clearIdx, inputIdx, helpIdx)
	}
}

func TestExactSlashCommandDoesNotRenderSuggestionBox(t *testing.T) {
	m := NewAgentModel(nil, "model", "local", 30, true, false, StartupInfo{})
	m.width = 80
	m.height = 24
	m.input.SetValue("/clear")
	m.input.SetCursor(6)
	m.recalcLayout()

	view := stripANSIForTest(m.View())
	if count := strings.Count(view, "/clear"); count != 1 {
		t.Fatalf("exact slash command should appear only in input, got %d occurrences:\n%s", count, view)
	}
	if got, want := m.slashSuggestionLineCount(), 0; got != want {
		t.Fatalf("slash suggestion line count=%d want %d", got, want)
	}
}

func TestSplitSlashCommandKeepsArgument(t *testing.T) {
	cmd, arg := splitSlashCommand("/new 排查 nginx 和 php-fpm")
	if cmd != "new" {
		t.Fatalf("cmd=%q want new", cmd)
	}
	if arg != "排查 nginx 和 php-fpm" {
		t.Fatalf("arg=%q", arg)
	}
}

func TestSlashCommandNamesIncludeNewAndCost(t *testing.T) {
	names := slashCommandNames()
	for _, want := range []string{"/new", "/restart", "/cost", "/mcp", "/skill", "/exit", "/quit"} {
		if !strings.Contains(names, want) {
			t.Fatalf("slash commands missing %s: %s", want, names)
		}
	}
}

func TestTokenUsagePrefersRealUsageOverEstimate(t *testing.T) {
	m := NewAgentModel(nil, "model", "local", 30, true, false, StartupInfo{})
	m.applyEvent(harness.UIEvent{
		Kind:             harness.EventTokenUsage,
		PromptTokens:     1000,
		CompletionTokens: 250,
		TotalTokens:      1250,
	})
	got := m.tokenUsageLabel(SessionStats{ApproxTokens: 99})
	if got != "1.2k tok" {
		t.Fatalf("token label=%q", got)
	}
}

func TestHeaderStatsExpandsWhenWidthAllows(t *testing.T) {
	stats := SessionStats{
		SessionID:    "session_1782803719386444000",
		Turns:        5,
		Messages:     8,
		ApproxTokens: 14200,
	}
	wide := formatHeaderStats(stats, false, "~14.2k tok", 90)
	for _, want := range []string{"会话 sid 1782803719386444000", "状态 idle", "轮次 5", "消息 8", "token ~14.2k"} {
		if !strings.Contains(wide, want) {
			t.Fatalf("wide header missing %q: %q", want, wide)
		}
	}

	narrow := formatHeaderStats(stats, false, "~14.2k tok", 42)
	if strings.Contains(narrow, "状态") || strings.Contains(narrow, "轮次") {
		t.Fatalf("narrow header should compact labels, got %q", narrow)
	}
	if !strings.Contains(narrow, "sid 444000") {
		t.Fatalf("narrow header should keep short session id, got %q", narrow)
	}
}

func stripANSIForTest(s string) string {
	var b strings.Builder
	inSeq := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inSeq {
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				inSeq = false
			}
			continue
		}
		if ch == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			inSeq = true
			i++
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}
