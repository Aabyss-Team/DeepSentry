package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"ai-edr/internal/config"
	"ai-edr/internal/harness"
	"ai-edr/internal/skills"
	"ai-edr/internal/ui"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
	"golang.org/x/term"
)

type logLine struct {
	kind      string
	content   string
	raw       string
	collapsed bool
	id        int
	at        time.Time
}

type confirmState struct {
	action *harness.AgentAction
	prompt string
	respCh chan bool
}

type askState struct {
	action  *harness.AgentAction
	prompt  string
	options []string
	respCh  chan string
}

type slashCommand struct {
	Name        string
	Description string
}

type tokenStats struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	Calls            int
}

var slashCommands = []slashCommand{
	{Name: "help", Description: "显示快捷键和斜杠命令"},
	{Name: "new", Description: "开启全新任务/会话；可直接 /new 任务"},
	{Name: "restart", Description: "等同 /new，重新开始一个会话"},
	{Name: "clear", Description: "清空当前屏幕日志"},
	{Name: "status", Description: "显示运行状态、步骤和连接"},
	{Name: "cost", Description: "显示会话轮次、消息数和估算 token"},
	{Name: "model", Description: "显示当前模型"},
	{Name: "compact", Description: "折叠长输出并整理上下文"},
	{Name: "sessions", Description: "列出可恢复 checkpoint"},
	{Name: "resume", Description: "提示如何恢复历史会话"},
	{Name: "config", Description: "显示连接与模型配置"},
	{Name: "mcp", Description: "MCP 管理：/mcp list|import|add|off|on"},
	{Name: "skill", Description: "Skill 管理：/skill list|load|unload|add|off|on|remove"},
	{Name: "exit", Description: "退出 TUI"},
	{Name: "quit", Description: "退出 TUI"},
}

type agentDoneMsg struct{}
type confirmMsg confirmState
type askMsg askState
type uiEventMsg harness.UIEvent
type userMsgEvent struct{ text string }
type agentStartMsg struct{ followUp bool }
type streamRefreshMsg struct{}
type streamCollapseMsg struct{ id int }
type copyToastMsg struct {
	chars int
	err   string
}
type copyToastClearMsg struct{}

var inputCursorAnchorSeq atomic.Uint64

func cancelInputCursorAnchor() {
	inputCursorAnchorSeq.Add(1)
}

// AgentModel 主 Agent TUI（多轮对话 + 子 Agent 面板）
type AgentModel struct {
	ctrl *SessionController

	width, height int
	viewport      viewport.Model
	spinner       spinner.Model
	input         textinput.Model

	title, statusLine string
	currentTarget     string
	maxSteps          int

	lines         []logLine
	lineID        int
	streamIdx     int // 当前流式行索引，-1 表示无
	streamTick    bool
	running       bool
	thinking      bool
	currentStep   int
	done          bool
	awaitGoal     bool
	sessionLive   bool
	autoStart     bool // 带 history 启动时由 Init 触发首轮
	autoScroll    bool
	stopping      bool
	inputHistory  []string
	historyIdx    int
	pendingPaste  string
	slashSelected int

	pendingConfirm *confirmState
	pendingAsk     *askState
	quitting       bool
	startupInfo    StartupInfo
	bannerCache    string
	bannerCacheW   int

	viewportPlain string
	selecting     bool
	selRow1       int
	selCol1       int
	selRow2       int
	selCol2       int
	selActive     bool
	copyToast     string
	tokenUsage    tokenStats
}

func NewAgentModel(ctrl *SessionController, title, status string, maxSteps int, awaitGoal, autoStart bool, startup StartupInfo) AgentModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(colorAccent)

	ti := textinput.New()
	ti.Placeholder = "task, Enter to start..."
	ti.Prompt = ""
	ti.CharLimit = 256 * 1024
	ti.Width = 70
	_ = ti.SetCursorMode(textinput.CursorStatic)
	if awaitGoal {
		ti.Focus()
	} else {
		ti.Blur()
	}

	vp := viewport.New(80, 18)
	if strings.TrimSpace(startup.Tip) == "" {
		startup.Tip = randomUsageTip()
	}
	if strings.TrimSpace(startup.StartedAt) == "" {
		startup.StartedAt = time.Now().Format("2006-01-02 15:04:05")
	}
	return AgentModel{
		ctrl:        ctrl,
		title:       title,
		statusLine:  status,
		maxSteps:    maxSteps,
		awaitGoal:   awaitGoal,
		autoStart:   autoStart,
		spinner:     sp,
		viewport:    vp,
		input:       ti,
		lines:       []logLine{},
		lineID:      0,
		streamIdx:   -1,
		autoScroll:  true,
		historyIdx:  -1,
		startupInfo: startup,
	}
}

func (m AgentModel) Init() tea.Cmd {
	cmds := []tea.Cmd{m.spinner.Tick}
	m.scheduleInputCursorAnchor()
	if m.autoStart && m.ctrl != nil && m.ctrl.beginRun() {
		cmds = append(cmds, agentStartCmd(false))
	}
	return tea.Batch(cmds...)
}

func agentStartCmd(followUp bool) tea.Cmd {
	return func() tea.Msg { return agentStartMsg{followUp: followUp} }
}

func isSubmitKey(msg tea.KeyMsg) bool {
	if msg.Type == tea.KeyEnter {
		return true
	}
	switch msg.String() {
	case "enter", "return":
		return true
	default:
		return false
	}
}

func (m AgentModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.bannerCache = ""
		m.bannerCacheW = 0
		m.recalcLayout()
		m.refreshViewport()
		m.scheduleInputCursorAnchor()
		return m, nil

	case uiEventMsg:
		e := harness.UIEvent(msg)
		m.applyEvent(e)
		if msg.Kind != harness.EventThinking {
			m.thinking = false
		}
		var cmds []tea.Cmd
		if e.Kind == harness.EventStreamDelta {
			if !m.streamTick {
				m.streamTick = true
				cmds = append(cmds, streamRefreshCmd())
			}
		} else {
			m.refreshViewport()
			if m.inputFocused() {
				m.scheduleInputCursorAnchor()
			}
			if e.Kind == harness.EventStreamEnd {
				if id := m.lastStreamLineID(); id > 0 {
					cmds = append(cmds, streamCollapseCmd(id))
				}
			}
		}
		if m.thinking {
			cmds = append(cmds, m.spinner.Tick)
		}
		return m, tea.Batch(cmds...)

	case streamRefreshMsg:
		m.streamTick = false
		m.refreshViewport()
		if m.inputFocused() {
			m.scheduleInputCursorAnchor()
		}
		return m, nil

	case streamCollapseMsg:
		m.collapseStreamLine(msg.id)
		m.refreshViewport()
		if m.inputFocused() {
			m.scheduleInputCursorAnchor()
		}
		return m, nil

	case copyToastMsg:
		m.copyToast = m.copyToastText(msg)
		return m, nil

	case copyToastClearMsg:
		m.copyToast = ""
		return m, nil

	case confirmMsg:
		m.pendingConfirm = &confirmState{action: msg.action, prompt: msg.prompt, respCh: msg.respCh}
		return m, nil

	case askMsg:
		m.pendingAsk = &askState{action: msg.action, prompt: msg.prompt, options: msg.options, respCh: msg.respCh}
		m.input.Focus()
		m.input.SetValue("")
		m.pendingPaste = ""
		m.appendAskLine(msg.prompt, msg.options)
		m.refreshViewport()
		m.scheduleInputCursorAnchor()
		return m, nil

	case agentDoneMsg:
		m.done = true
		m.running = false
		m.thinking = false
		m.stopping = false
		m.awaitGoal = false
		m.sessionLive = true
		m.pendingConfirm = nil
		m.pendingAsk = nil
		m.input.SetValue("")
		m.pendingPaste = ""
		m.input.Width = ChromeContentWidth(m.width) - 2
		m.input.Focus()
		m.refreshViewport()
		m.scheduleInputCursorAnchor()
		return m, nil

	case userMsgEvent:
		m.appendLine("user", "You: "+msg.text, msg.text)
		m.refreshViewport()
		return m, nil

	case agentStartMsg:
		m.done = false
		m.running = true
		m.sessionLive = true
		m.input.Blur()
		cancelInputCursorAnchor()
		m.input.SetValue("")
		if msg.followUp {
			m.appendLine("info", "▶ 追问处理中…", "followup")
		} else if !m.autoStart {
			m.appendLine("info", "▶ 开始执行...", "start")
		}
		m.autoStart = false
		m.refreshViewport()
		return m, nil

	case spinner.TickMsg:
		if m.thinking {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			m.refreshViewport()
			return m, cmd
		}
		return m, nil

	case tea.MouseMsg:
		if !m.inputFocused() {
			switch msg.Action {
			case tea.MouseActionPress:
				if msg.Button == tea.MouseButtonLeft {
					if row, col, ok := m.mouseToContentCoord(msg.X, msg.Y); ok {
						m.selecting = true
						m.selActive = true
						m.selRow1, m.selCol1 = row, col
						m.selRow2, m.selCol2 = row, col
					}
				}
			case tea.MouseActionMotion:
				if m.selecting {
					if row, col, ok := m.mouseToContentCoord(msg.X, msg.Y); ok {
						m.selRow2, m.selCol2 = row, col
					}
				}
			case tea.MouseActionRelease:
				if msg.Button == tea.MouseButtonLeft && m.selecting {
					m.selecting = false
					text := m.selectedPlainText()
					if cmd := m.copyTextCmd(text); cmd != nil {
						return m, cmd
					}
				}
			}
		}
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			m.autoScroll = false
			m.viewport.LineUp(3)
			return m, nil
		case tea.MouseButtonWheelDown:
			m.viewport.LineDown(3)
			if m.viewport.AtBottom() {
				m.autoScroll = true
			}
			return m, nil
		}

	case tea.KeyMsg:
		key := msg.String()

		if m.pendingConfirm != nil {
			switch {
			case key == "y":
				ch := m.pendingConfirm.respCh
				m.pendingConfirm = nil
				if ch != nil {
					ch <- true
				}
				m.appendLine("info", "✓ 已批准", "ok")
				m.refreshViewport()
			case key == "n" || key == "esc":
				ch := m.pendingConfirm.respCh
				m.pendingConfirm = nil
				if ch != nil {
					ch <- false
				}
				m.appendLine("info", "✗ 已拒绝", "no")
				m.refreshViewport()
			case key == "ctrl+c":
				if ch := m.pendingConfirm.respCh; ch != nil {
					ch <- false
				}
				m.pendingConfirm = nil
				m.quitting = true
				cancelInputCursorAnchor()
				return m, tea.Quit
			}
			return m, nil
		}

		if m.pendingAsk != nil && (key == "esc" || key == "ctrl+c") {
			ch := m.pendingAsk.respCh
			m.pendingAsk = nil
			if ch != nil {
				ch <- ""
			}
			m.appendLine("info", "已暂停等待补充；可稍后直接输入追问继续。", "ask-cancel")
			m.refreshViewport()
			if key == "ctrl+c" {
				m.quitting = true
				cancelInputCursorAnchor()
				return m, tea.Quit
			}
			return m, nil
		}

		// Ctrl+C：有选区时复制；否则停止任务 / 退出
		if key == "ctrl+c" || key == "cmd+c" {
			if !m.inputFocused() && m.hasCopySelection() {
				return m, m.copyTextCmd(m.selectedPlainText())
			}
			if m.running && !m.stopping && m.ctrl != nil {
				m.stopping = true
				m.ctrl.RequestStop()
				m.appendLine("info", "正在停止当前任务，会在当前 LLM/命令返回后保存 checkpoint。再次 Ctrl+C 强制退出。", "stopping")
				m.refreshViewport()
				return m, nil
			}
			m.quitting = true
			cancelInputCursorAnchor()
			return m, tea.Quit
		}

		// Esc：运行中中断任务；输入聚焦时退出输入模式便于滚动
		if key == "esc" {
			if m.running && !m.stopping && m.ctrl != nil {
				m.stopping = true
				m.ctrl.RequestStop()
				m.appendLine("info", "正在停止当前任务，会在当前 LLM/命令返回后保存 checkpoint。", "stopping")
				m.refreshViewport()
				return m, nil
			}
			if m.inputFocused() {
				m.input.Blur()
				cancelInputCursorAnchor()
				return m, nil
			}
			if m.selActive {
				m.selActive = false
				m.selecting = false
				return m, nil
			}
			return m, nil
		}

		if m.inputFocused() && msg.Paste {
			m.acceptPaste(string(msg.Runes))
			m.refreshViewport()
			m.scheduleInputCursorAnchor()
			return m, nil
		}

		// 输入聚焦：仅处理输入相关快捷键，其余字符交给 textinput（避免 q/e/j/k 等全局键抢输入）
		if m.inputFocused() {
			if isSubmitKey(msg) && m.pendingAsk != nil {
				if cmd := m.submitAskResponse(); cmd != nil {
					return m, cmd
				}
				return m, nil
			}
			if isSubmitKey(msg) && m.running && m.pendingConfirm == nil {
				if cmd := m.tryInterruptSubmit(); cmd != nil {
					return m, cmd
				}
				return m, nil
			}
			if isSubmitKey(msg) && !m.running && m.pendingConfirm == nil {
				if cmd := m.trySubmit(); cmd != nil {
					return m, cmd
				}
				return m, nil
			}
			switch key {
			case "alt+enter", "shift+enter", "ctrl+j":
				m.appendInputNewline()
				m.scheduleInputCursorAnchor()
				return m, nil
			case "ctrl+l":
				m.clearView()
				m.scheduleInputCursorAnchor()
				return m, nil
			case "ctrl+u":
				m.clearInputDraft()
				m.recalcLayout()
				m.scheduleInputCursorAnchor()
				return m, nil
			case "backspace", "delete":
				if m.pendingPaste != "" {
					m.clearInputDraft()
					m.recalcLayout()
					m.scheduleInputCursorAnchor()
					return m, nil
				}
			case "up":
				if m.hasSlashSuggestions() {
					m.moveSlashSelection(-1)
					m.scheduleInputCursorAnchor()
					return m, nil
				}
				m.recallInputHistory(-1)
				m.scheduleInputCursorAnchor()
				return m, nil
			case "down":
				if m.hasSlashSuggestions() {
					m.moveSlashSelection(1)
					m.scheduleInputCursorAnchor()
					return m, nil
				}
				m.recallInputHistory(1)
				m.scheduleInputCursorAnchor()
				return m, nil
			case "tab":
				if m.acceptSlashSuggestion() {
					m.recalcLayout()
					m.scheduleInputCursorAnchor()
					return m, nil
				}
			case "pgup":
				m.autoScroll = false
				m.viewport.ViewUp()
				m.scheduleInputCursorAnchor()
				return m, nil
			case "pgdown":
				m.viewport.ViewDown()
				if m.viewport.AtBottom() {
					m.autoScroll = true
				}
				m.scheduleInputCursorAnchor()
				return m, nil
			}
			if m.pendingPaste != "" {
				if msg.Type == tea.KeyRunes {
					m.pendingPaste += string(msg.Runes)
					m.input.SetValue(pasteSummary(m.pendingPaste))
					m.scheduleInputCursorAnchor()
					return m, nil
				}
			}
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			m.clampSlashSelection()
			m.recalcLayout()
			m.scheduleInputCursorAnchor()
			return m, cmd
		}

		// 提交：Enter（必须用 tea.Cmd 更新状态，禁止 program.Send 防死锁）
		if isSubmitKey(msg) && m.pendingAsk != nil {
			if cmd := m.submitAskResponse(); cmd != nil {
				return m, cmd
			}
			return m, nil
		}
		if isSubmitKey(msg) && m.running && m.pendingConfirm == nil {
			if cmd := m.tryInterruptSubmit(); cmd != nil {
				return m, cmd
			}
			return m, nil
		}
		if isSubmitKey(msg) && !m.running && m.pendingConfirm == nil {
			if cmd := m.trySubmit(); cmd != nil {
				return m, cmd
			}
			return m, nil
		}

		// 以下全局快捷键仅在输入未聚焦时生效
		switch key {
		case "ctrl+l":
			m.clearView()
			return m, nil
		case "q":
			if m.done || m.awaitGoal || m.sessionLive || !m.running {
				m.quitting = true
				cancelInputCursorAnchor()
				return m, tea.Quit
			}
		case "e":
			m.toggleLastCollapsible()
			m.refreshViewport()
			return m, nil
		case "up", "k", "pgup":
			m.autoScroll = false
			if key == "pgup" {
				m.viewport.ViewUp()
			} else {
				m.viewport.LineUp(1)
			}
			return m, nil
		case "down", "j", "pgdown":
			if key == "pgdown" {
				m.viewport.ViewDown()
			} else {
				m.viewport.LineDown(1)
			}
			if m.viewport.AtBottom() {
				m.autoScroll = true
			}
			return m, nil
		case "G":
			m.autoScroll = true
			m.viewport.GotoBottom()
			return m, nil
		case "tab":
			if m.done || m.awaitGoal || m.sessionLive {
				m.input.Focus()
				m.scheduleInputCursorAnchor()
				return m, nil
			}
		}

		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	}

	if m.inputFocused() {
		m.scheduleInputCursorAnchor()
	}
	return m, nil
}

func (m *AgentModel) submitAskResponse() tea.Cmd {
	if m.pendingAsk == nil {
		return nil
	}
	text := strings.TrimSpace(m.currentInputValue())
	if text == "" {
		return nil
	}
	text = normalizeAskAnswer(text, m.pendingAsk.options)
	if runewidth.StringWidth(text) <= 4000 {
		m.inputHistory = append(m.inputHistory, text)
	}
	ch := m.pendingAsk.respCh
	m.pendingAsk = nil
	m.clearInputDraft()
	m.input.Blur()
	cancelInputCursorAnchor()
	m.appendLine("user", "You: "+summarizeIfNeeded(text), text)
	m.refreshViewport()
	if ch != nil {
		ch <- text
	}
	return nil
}

func (m *AgentModel) tryInterruptSubmit() tea.Cmd {
	text := strings.TrimSpace(m.currentInputValue())
	if text == "" || m.ctrl == nil {
		return nil
	}
	if !m.ctrl.InterruptWithInput(text) {
		return nil
	}
	if runewidth.StringWidth(text) <= 4000 {
		m.inputHistory = append(m.inputHistory, text)
	}
	m.clearInputDraft()
	m.input.Blur()
	cancelInputCursorAnchor()
	m.appendLine("user", "You: "+summarizeIfNeeded(text), text)
	m.appendLine("info", "↳ 已注入新指令，当前轮停止后会按最新目标继续。", text)
	m.refreshViewport()
	m.scheduleInputCursorAnchor()
	return nil
}

func summarizeIfNeeded(text string) string {
	if strings.Count(text, "\n") >= 3 || runewidth.StringWidth(text) > 400 {
		return summarizeUserText(text)
	}
	return text
}

func normalizeAskAnswer(text string, options []string) string {
	idx := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(text), "%d", &idx); err == nil && idx > 0 && idx <= len(options) {
		if opt := strings.TrimSpace(options[idx-1]); opt != "" {
			return opt
		}
	}
	return text
}

func slashCommandNames() string {
	names := make([]string, 0, len(slashCommands))
	for _, cmd := range slashCommands {
		names = append(names, "/"+cmd.Name)
	}
	return strings.Join(names, " ")
}

func splitSlashCommand(text string) (string, string) {
	text = strings.TrimSpace(strings.TrimPrefix(text, "/"))
	if text == "" {
		return "", ""
	}
	for i, r := range text {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return strings.ToLower(strings.TrimSpace(text[:i])), strings.TrimSpace(text[i:])
		}
	}
	return strings.ToLower(text), ""
}

func (m AgentModel) slashQuery() (string, bool) {
	if !m.inputFocused() || m.pendingPaste != "" || m.pendingAsk != nil {
		return "", false
	}
	value := strings.TrimSpace(m.input.Value())
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, " \t\r\n") {
		return "", false
	}
	return strings.TrimPrefix(value, "/"), true
}

func (m AgentModel) slashSuggestions() []slashCommand {
	query, ok := m.slashQuery()
	if !ok {
		return nil
	}
	query = strings.ToLower(query)
	if query != "" {
		for _, cmd := range slashCommands {
			if strings.ToLower(cmd.Name) == query {
				return nil
			}
		}
	}
	out := make([]slashCommand, 0, len(slashCommands))
	for _, cmd := range slashCommands {
		if query == "" || strings.HasPrefix(strings.ToLower(cmd.Name), query) {
			out = append(out, cmd)
		}
	}
	return out
}

func (m AgentModel) hasSlashSuggestions() bool {
	return len(m.slashSuggestions()) > 0
}

func (m *AgentModel) clampSlashSelection() {
	suggestions := m.slashSuggestions()
	if len(suggestions) == 0 {
		m.slashSelected = 0
		return
	}
	if m.slashSelected < 0 {
		m.slashSelected = 0
	}
	if m.slashSelected >= len(suggestions) {
		m.slashSelected = len(suggestions) - 1
	}
}

func (m *AgentModel) moveSlashSelection(delta int) {
	suggestions := m.slashSuggestions()
	if len(suggestions) == 0 {
		m.slashSelected = 0
		return
	}
	m.slashSelected = (m.slashSelected + delta + len(suggestions)) % len(suggestions)
}

func (m *AgentModel) acceptSlashSuggestion() bool {
	suggestions := m.slashSuggestions()
	if len(suggestions) == 0 {
		return false
	}
	m.clampSlashSelection()
	m.input.SetValue("/" + suggestions[m.slashSelected].Name)
	m.input.SetCursor(len([]rune(m.input.Value())))
	return true
}

func (m *AgentModel) trySubmit() tea.Cmd {
	pasted := m.pendingPaste != ""
	text := strings.TrimSpace(m.currentInputValue())
	if text == "" {
		return nil
	}
	if !pasted && strings.HasPrefix(text, "/") {
		return m.handleSlashCommand(text)
	}
	if runewidth.StringWidth(text) <= 4000 {
		m.inputHistory = append(m.inputHistory, text)
	}
	m.historyIdx = -1

	followUp := !m.awaitGoal && (m.sessionLive || m.done)
	firstTurn := m.awaitGoal || (!m.sessionLive && !m.done && !followUp)

	m.clearInputDraft()
	m.input.Blur()
	cancelInputCursorAnchor()
	m.awaitGoal = false
	m.done = false
	m.sessionLive = true
	displayText := text
	if pasted || strings.Count(text, "\n") >= 3 || runewidth.StringWidth(text) > 400 {
		displayText = summarizeUserText(text)
	}
	m.appendLine("user", "You: "+displayText, text)
	m.refreshViewport()

	var ok bool
	if followUp {
		ok = m.ctrl.PrepareFollowUp(text)
	} else if firstTurn {
		m.ctrl.SetInitialGoal(text)
		ok = m.ctrl.beginRun()
	} else {
		ok = m.ctrl.PrepareFollowUp(text)
		followUp = true
	}

	if !ok {
		if followUp {
			m.done = true
		} else {
			m.awaitGoal = true
			m.sessionLive = false
		}
		m.input.Focus()
		if pasted {
			m.pendingPaste = text
			m.input.SetValue(pasteSummary(text))
		}
		m.appendLine("error", "Agent 仍在运行，请稍候", "busy")
		m.refreshViewport()
		m.scheduleInputCursorAnchor()
		return nil
	}

	return agentStartCmd(followUp)
}

func streamRefreshCmd() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(time.Time) tea.Msg { return streamRefreshMsg{} })
}

func streamCollapseCmd(id int) tea.Cmd {
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg { return streamCollapseMsg{id: id} })
}

func (m *AgentModel) recallInputHistory(delta int) {
	if len(m.inputHistory) == 0 {
		return
	}
	if m.historyIdx < 0 {
		if delta < 0 {
			m.historyIdx = len(m.inputHistory) - 1
		} else {
			return
		}
	} else {
		m.historyIdx += delta
		if m.historyIdx < 0 {
			m.historyIdx = 0
		}
		if m.historyIdx >= len(m.inputHistory) {
			m.historyIdx = -1
			m.input.SetValue("")
			return
		}
	}
	m.input.SetValue(m.inputHistory[m.historyIdx])
	m.pendingPaste = ""
}

func (m *AgentModel) handleSlashCommand(text string) tea.Cmd {
	cmd, arg := splitSlashCommand(text)
	m.clearInputDraft()
	switch {
	case cmd == "clear":
		m.clearView()
		return nil
	case cmd == "" || cmd == "help":
		m.appendLine("info", "可用命令: "+slashCommandNames(), "help")
	case cmd == "new" || cmd == "restart":
		return m.startNewSession(arg)
	case cmd == "status":
		target := m.statusContextText()
		m.appendLine("info", fmt.Sprintf("状态: running=%v step=%d/%d target=%s connection=%s · %s", m.running, m.currentStep, m.maxSteps, target, m.statusLine, m.sessionStatsText(false)), "status")
	case cmd == "cost":
		m.appendLine("info", m.sessionStatsText(true), "cost")
	case cmd == "model":
		m.appendLine("info", "模型: "+m.title, "model")
	case cmd == "compact":
		m.appendLine("info", "已折叠最近的长输出/思考块；完整上下文仍保留在会话历史中。", "compact")
		for i := range m.lines {
			if m.lines[i].kind == "subagent_result" || m.lines[i].kind == "stream" {
				m.lines[i].collapsed = true
			}
		}
	case cmd == "sessions":
		summaries, err := harness.ListSessionSummaries()
		if err != nil {
			m.appendLine("error", "读取会话失败: "+err.Error(), err.Error())
			break
		}
		if len(summaries) == 0 {
			m.appendLine("info", "暂无可恢复会话", "no sessions")
			break
		}
		var b strings.Builder
		for _, s := range summaries {
			b.WriteString(fmt.Sprintf("%s · step %d · %s\n", s.ID, s.StepNum, s.SavedAt.Format("01-02 15:04")))
		}
		m.appendLine("result", strings.TrimSpace(b.String()), b.String())
	case strings.HasPrefix(cmd, "resume"):
		m.appendLine("info", "请退出后使用 deepsentry --resume <session_id>，或从启动选择器恢复会话。", text)
	case cmd == "config":
		m.appendLine("info", fmt.Sprintf("连接: %s · 模型: %s · 最大步数: %d", m.statusLine, m.title, m.maxSteps), text)
	case cmd == "mcp":
		m.handleMCPSlash(arg)
	case cmd == "skill":
		m.handleSkillSlash(arg)
	case cmd == "exit" || cmd == "quit":
		m.quitting = true
		cancelInputCursorAnchor()
		return tea.Quit
	default:
		m.appendLine("error", "未知命令: /"+cmd+"（可用 "+slashCommandNames()+"）", text)
	}
	m.refreshViewport()
	return nil
}

func (m *AgentModel) handleMCPSlash(arg string) {
	fields := strings.Fields(arg)
	action := "status"
	args := map[string]string{"action": "status"}
	if len(fields) > 0 {
		switch fields[0] {
		case "list", "status":
			args["action"] = "status"
		case "import":
			if len(fields) < 2 {
				m.appendLine("error", "用法: /mcp import /path/to/claude_desktop_config.json", arg)
				return
			}
			args = map[string]string{"action": "import_claude_mcp", "import_path": strings.TrimSpace(strings.TrimPrefix(arg, "import"))}
			action = "import"
		case "add":
			if len(fields) < 3 {
				m.appendLine("error", "用法: /mcp add <name> <command> [arg1,arg2] [cwd=/path] [env=A=B,C=D]", arg)
				return
			}
			args = map[string]string{"action": "add_mcp_server", "name": fields[1], "command": fields[2]}
			if len(fields) >= 4 {
				args["args"] = fields[3]
			}
			for _, field := range fields[4:] {
				if k, v, ok := strings.Cut(field, "="); ok {
					args[k] = v
				}
			}
			action = "add"
		case "off", "disable":
			if len(fields) < 2 {
				m.appendLine("error", "用法: /mcp off <name>", arg)
				return
			}
			args = map[string]string{"action": "disable_mcp_server", "name": fields[1]}
			action = "off"
		case "on", "enable":
			if len(fields) < 2 {
				m.appendLine("error", "用法: /mcp on <name>", arg)
				return
			}
			args = map[string]string{"action": "enable_mcp_server", "name": fields[1]}
			action = "on"
		case "remove", "rm":
			if len(fields) < 2 {
				m.appendLine("error", "用法: /mcp remove <name>", arg)
				return
			}
			args = map[string]string{"action": "remove_mcp_server", "name": fields[1]}
			action = "remove"
		default:
			m.appendLine("info", "用法: /mcp list | /mcp import <claude.json> | /mcp add <name> <command> [args] | /mcp off <name> | /mcp on <name> | /mcp remove <name>", arg)
			return
		}
	}
	out, err := config.ManageConfig(args)
	if err != nil {
		m.appendLine("error", "MCP "+action+" 失败: "+err.Error(), err.Error())
		return
	}
	m.appendLine("result", out+"\n提示: MCP 配置变更通常在新会话/重启后生效。", out)
}

func (m *AgentModel) handleSkillSlash(arg string) {
	fields := strings.Fields(arg)
	args := map[string]string{"action": "status"}
	action := "status"
	if len(fields) > 0 {
		switch fields[0] {
		case "list", "status":
			args["action"] = "status"
		case "load":
			if len(fields) < 2 {
				m.appendLine("error", "用法: /skill load <skill-name>", arg)
				return
			}
			m.loadCurrentSkill(fields[1])
			return
		case "unload", "close":
			if len(fields) < 2 {
				m.appendLine("error", "用法: /skill unload <skill-name>", arg)
				return
			}
			m.unloadCurrentSkill(fields[1])
			return
		case "add":
			source := strings.TrimSpace(strings.TrimPrefix(arg, "add"))
			if source == "" {
				m.appendLine("error", "用法: /skill add /path/to/skills", arg)
				return
			}
			args = map[string]string{"action": "add_skill_source", "source": source}
			action = "add"
		case "off", "disable":
			source := strings.TrimSpace(strings.TrimPrefix(arg, fields[0]))
			if source == "" {
				m.appendLine("error", "用法: /skill off /path/to/skills", arg)
				return
			}
			args = map[string]string{"action": "disable_skill_source", "source": source}
			action = "off"
		case "on", "enable":
			source := strings.TrimSpace(strings.TrimPrefix(arg, fields[0]))
			if source == "" {
				m.appendLine("error", "用法: /skill on /path/to/skills", arg)
				return
			}
			args = map[string]string{"action": "enable_skill_source", "source": source}
			action = "on"
		case "remove", "rm":
			source := strings.TrimSpace(strings.TrimPrefix(arg, fields[0]))
			if source == "" {
				m.appendLine("error", "用法: /skill remove /path/to/skills", arg)
				return
			}
			args = map[string]string{"action": "remove_skill_source", "source": source}
			action = "remove"
		default:
			m.appendLine("info", "用法: /skill list | /skill load <name> | /skill unload <name> | /skill add <dir> | /skill off <dir> | /skill on <dir> | /skill remove <dir>", arg)
			return
		}
	}
	out, err := config.ManageConfig(args)
	if err != nil {
		m.appendLine("error", "Skill "+action+" 失败: "+err.Error(), err.Error())
		return
	}
	m.appendLine("result", out+"\n提示: Skill 来源变更通常在新会话后生效；已加载进当前上下文的 Skill 不会从历史中删除。", out)
}

func (m *AgentModel) loadCurrentSkill(name string) {
	if m.ctrl == nil || m.ctrl.cfg.Agent == nil || m.ctrl.cfg.Agent.Catalog == nil {
		m.appendLine("error", "当前 Agent 没有可用 Skill 目录", name)
		return
	}
	meta, ok := m.ctrl.cfg.Agent.Catalog.FindSkill(name)
	if !ok {
		m.appendLine("error", "未找到 Skill: "+name, name)
		return
	}
	content, err := skills.LoadSkillContent(*meta)
	if err != nil {
		m.appendLine("error", "加载 Skill 失败: "+err.Error(), err.Error())
		return
	}
	if m.ctrl.cfg.Agent.State.LoadedSkills == nil {
		m.ctrl.cfg.Agent.State.LoadedSkills = map[string]string{}
	}
	m.ctrl.cfg.Agent.State.LoadedSkills[name] = content
	m.appendLine("result", fmt.Sprintf("已加载 Skill [%s] 到当前会话 (%d 字符)", name, len(content)), name)
}

func (m *AgentModel) unloadCurrentSkill(name string) {
	if m.ctrl == nil || m.ctrl.cfg.Agent == nil || m.ctrl.cfg.Agent.State == nil {
		m.appendLine("error", "当前 Agent 状态不可用", name)
		return
	}
	if _, ok := m.ctrl.cfg.Agent.State.LoadedSkills[name]; !ok {
		m.appendLine("info", "当前会话未加载 Skill: "+name, name)
		return
	}
	delete(m.ctrl.cfg.Agent.State.LoadedSkills, name)
	m.appendLine("result", "已从当前会话关闭 Skill: "+name, name)
}

func (m *AgentModel) startNewSession(goal string) tea.Cmd {
	if m.ctrl == nil {
		m.appendLine("error", "当前界面没有可重置的 Agent 控制器", "no controller")
		m.refreshViewport()
		return nil
	}
	if m.running {
		m.appendLine("error", "当前任务仍在运行；请先 Esc 停止，或直接输入新指令中途打断。", "running")
		m.refreshViewport()
		return nil
	}
	sessionID, hasGoal, err := m.ctrl.StartNewSession(goal)
	if err != nil {
		m.appendLine("error", "新建会话失败: "+err.Error(), err.Error())
		m.refreshViewport()
		return nil
	}

	m.lines = []logLine{}
	m.lineID = 0
	m.streamIdx = -1
	m.streamTick = false
	m.running = false
	m.thinking = false
	m.currentStep = 0
	m.done = false
	m.awaitGoal = !hasGoal
	m.sessionLive = hasGoal
	m.autoStart = false
	m.autoScroll = true
	m.stopping = false
	m.pendingConfirm = nil
	m.pendingAsk = nil
	m.historyIdx = -1
	m.currentTarget = ""
	m.copyToast = ""
	m.tokenUsage = tokenStats{}
	m.startupInfo.SessionID = sessionID
	m.startupInfo.AwaitGoal = !hasGoal
	m.startupInfo.StartedAt = time.Now().Format("2006-01-02 15:04:05")
	m.bannerCache = ""
	m.bannerCacheW = 0
	m.clearInputDraft()
	cancelInputCursorAnchor()

	if hasGoal {
		m.input.Blur()
		m.appendLine("info", fmt.Sprintf("已开启新会话 %s，并开始执行新任务。", shortSessionID(sessionID)), sessionID)
		m.appendLine("user", "You: "+summarizeIfNeeded(goal), goal)
		m.refreshViewport()
		if m.ctrl.beginRun() {
			return agentStartCmd(false)
		}
		m.appendLine("error", "Agent 仍在运行，请稍候", "busy")
		m.refreshViewport()
		return nil
	}

	m.input.Focus()
	m.appendLine("info", fmt.Sprintf("已开启新会话 %s。输入任务后 Enter 开始。", shortSessionID(sessionID)), sessionID)
	m.refreshViewport()
	m.scheduleInputCursorAnchor()
	return nil
}

func (m *AgentModel) clearView() {
	m.lines = []logLine{}
	m.lineID = 0
	m.streamIdx = -1
	m.appendLine("info", "已清空当前视图", "clear")
	m.refreshViewport()
}

func (m *AgentModel) inputFocused() bool {
	return m.input.Focused()
}

func (m AgentModel) currentInputValue() string {
	if m.pendingPaste != "" {
		return m.pendingPaste
	}
	return m.input.Value()
}

func (m *AgentModel) clearInputDraft() {
	m.pendingPaste = ""
	m.input.SetValue("")
	m.slashSelected = 0
}

func (m *AgentModel) acceptPaste(text string) {
	if text == "" {
		return
	}
	base := m.input.Value()
	if m.pendingPaste != "" {
		base = m.pendingPaste
	}
	full := base + text
	if isLargePaste(full) {
		m.pendingPaste = full
		m.input.SetValue(pasteSummary(full))
		m.slashSelected = 0
		return
	}
	m.pendingPaste = ""
	m.input.SetValue(full)
	m.clampSlashSelection()
}

func (m *AgentModel) appendInputNewline() {
	base := m.currentInputValue()
	m.pendingPaste = base + "\n"
	m.input.SetValue(pasteSummary(m.pendingPaste))
	m.slashSelected = 0
}

func isLargePaste(s string) bool {
	return strings.Contains(s, "\n") || len([]rune(s)) > 300 || runewidth.StringWidth(s) > 300
}

func (m AgentModel) pendingConfirmActive() bool {
	return m.pendingConfirm != nil
}

func (m *AgentModel) toggleLastCollapsible() {
	for i := len(m.lines) - 1; i >= 0; i-- {
		if m.lines[i].kind == "subagent_result" || m.lines[i].kind == "stream" {
			m.lines[i].collapsed = !m.lines[i].collapsed
			return
		}
	}
}

func (m *AgentModel) lastStreamLineID() int {
	for i := len(m.lines) - 1; i >= 0; i-- {
		if m.lines[i].kind == "stream" {
			return m.lines[i].id
		}
	}
	return 0
}

func (m *AgentModel) applyEvent(e harness.UIEvent) {
	switch e.Kind {
	case harness.EventStepStart:
		m.currentStep = e.Step
		m.maxSteps = e.MaxSteps
		m.appendLine("step", fmt.Sprintf("Step %d / %d", e.Step, e.MaxSteps), e.Message)
	case harness.EventThinking:
		m.thinking = true
		m.streamIdx = -1
	case harness.EventStreamDelta:
		m.thinking = false
		m.appendStreamDelta(e.Message)
	case harness.EventStreamEnd:
		m.finalizeStream(e.Detail)
	case harness.EventThought:
		m.appendLine("thought", e.Message, e.Message)
	case harness.EventTokenUsage:
		m.recordTokenUsage(e)
	case harness.EventAction:
		if e.Action != nil && e.Action.Type == harness.ActionTodo {
			line := harness.FormatTodoList(e.Action.Todos)
			m.appendLine("todo", line, line)
			break
		}
		kind := "tool"
		line := FormatActionLine(e.Action)
		if e.Action != nil && e.Action.Type == harness.ActionTask {
			kind = "subagent_start"
			if len(e.Action.ParallelTasks) > 0 {
				line = FormatActionLine(e.Action)
			} else if strings.TrimSpace(e.Action.TaskName) == "" || strings.TrimSpace(e.Action.TaskPrompt) == "" {
				line = FormatActionLine(e.Action)
			} else {
				line = fmt.Sprintf("Sub-agent · %s → %s", e.Action.TaskName, truncateStr(e.Action.TaskPrompt, 60))
			}
		}
		if line != "" {
			m.appendLine(kind, line, line)
		}
	case harness.EventSubAgentStart:
		m.noteTarget(e)
		m.appendLine("subagent_start", fmt.Sprintf("Sub-agent · %s%s", e.Message, tuiTargetSuffix(e)), e.Detail)
	case harness.EventSubAgentStep:
		m.noteTarget(e)
		m.appendLine("subagent_start", "Sub-agent · "+e.Message+tuiTargetSuffix(e), e.Detail)
	case harness.EventSubAgentAction:
		m.noteTarget(e)
		action := e.Action
		if action != nil && (e.TargetName != "" || e.TargetProtocol != "" || e.TargetHost != "") {
			copyAction := *action
			if strings.TrimSpace(copyAction.TargetProtocol) != "local" {
				if copyAction.TargetName == "" {
					copyAction.TargetName = e.TargetName
				}
				if copyAction.TargetProtocol == "" {
					copyAction.TargetProtocol = e.TargetProtocol
				}
				if copyAction.TargetHost == "" {
					copyAction.TargetHost = e.TargetHost
				}
			}
			action = &copyAction
		}
		line := FormatActionLine(action)
		if line == "" {
			line = e.Message
		}
		m.appendLine("tool", "Sub-agent · "+line+tuiTargetSuffix(e), line)
	case harness.EventSubAgentResult:
		m.noteTarget(e)
		m.appendLine("subagent_result", truncateLines(e.Detail, 3), e.Detail)
	case harness.EventTargetStatus:
		m.noteTarget(e)
		status := e.Status
		if status == "" {
			status = "info"
		}
		m.appendLine("target", fmt.Sprintf("[%s] %s%s %s", status, e.Message, tuiTargetSuffix(e), e.Detail), e.Detail)
	case harness.EventResult:
		if strings.Contains(e.Message, "任务清单") || strings.Contains(e.Detail, "任务清单") {
			// 完整清单已在 EventAction 展示，避免重复
			break
		}
		if strings.Contains(e.Detail, "子 Agent") || strings.Contains(e.Message, "子 Agent") {
			m.appendLine("subagent_result", truncateLines(e.Message, 3), e.Detail)
		} else {
			m.appendLine("result", e.Message, e.Detail)
		}
	case harness.EventCommandOutput:
		if strings.TrimSpace(e.Message) != "" {
			m.appendLine("result", strings.TrimRight(e.Message, "\r\n"), e.Message)
		}
	case harness.EventError, harness.EventCheckpoint:
		m.appendLine("error", e.Message, e.Message)
	case harness.EventAwaitUser:
		prompt := e.Message
		options := []string(nil)
		if e.Action != nil {
			if strings.TrimSpace(e.Action.Question) != "" {
				prompt = e.Action.Question
			}
			options = e.Action.Options
		}
		m.appendAskLine(prompt, options)
	case harness.EventInfo, harness.EventRiskAuto, harness.EventBatchAuto, harness.EventDenied:
		m.appendLine("info", e.Message, e.Message)
	case harness.EventFinish:
		m.appendLine("success", e.Message, e.Message)
		if e.Detail != "" {
			m.appendLine("info", "审计: "+e.Detail, e.Detail)
		}
	}
}

func (m *AgentModel) recordTokenUsage(e harness.UIEvent) {
	total := e.TotalTokens
	if total <= 0 {
		total = e.PromptTokens + e.CompletionTokens
	}
	if total <= 0 {
		return
	}
	m.tokenUsage.PromptTokens += e.PromptTokens
	m.tokenUsage.CompletionTokens += e.CompletionTokens
	m.tokenUsage.TotalTokens += total
	m.tokenUsage.Calls++
}

func (m *AgentModel) noteTarget(e harness.UIEvent) {
	label := targetLabel(e.TargetName, e.TargetProtocol, e.TargetHost)
	if label != "" {
		m.currentTarget = label
	}
}

func tuiTargetSuffix(e harness.UIEvent) string {
	label := targetLabel(e.TargetName, e.TargetProtocol, e.TargetHost)
	if label == "" {
		return ""
	}
	return " @ " + label
}

func targetLabel(name, proto, host string) string {
	if name == "" && host == "" && proto == "" {
		return ""
	}
	label := name
	if label == "" {
		label = host
	}
	if proto != "" && host != "" {
		return fmt.Sprintf("%s (%s %s)", label, proto, host)
	}
	if proto != "" {
		return fmt.Sprintf("%s (%s)", label, proto)
	}
	return label
}

func (m *AgentModel) appendStreamDelta(delta string) {
	if delta == "" {
		return
	}
	if m.streamIdx < 0 || m.streamIdx >= len(m.lines) {
		m.lineID++
		m.lines = append(m.lines, logLine{kind: "stream", content: streamDisplay(delta, false), raw: delta, id: m.lineID, at: time.Now()})
		m.streamIdx = len(m.lines) - 1
	} else {
		ln := &m.lines[m.streamIdx]
		ln.raw += delta
		ln.content = streamDisplay(ln.raw, false)
	}
}

func (m *AgentModel) finalizeStream(full string) {
	if m.streamIdx >= 0 && m.streamIdx < len(m.lines) {
		ln := &m.lines[m.streamIdx]
		if strings.TrimSpace(full) != "" {
			ln.raw = full
		}
		ln.content = streamDisplay(ln.raw, true)
	}
	m.streamIdx = -1
}

func (m *AgentModel) collapseStreamLine(id int) {
	for i := range m.lines {
		if m.lines[i].id == id && m.lines[i].kind == "stream" {
			m.lines[i].collapsed = true
			return
		}
	}
}

func streamDisplay(raw string, done bool) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if done {
			return "AI 思考完成"
		}
		return "AI 正在思考..."
	}

	if action := parseStreamAction(raw); action != nil {
		if strings.TrimSpace(action.Thought) != "" {
			return "思考: " + action.Thought
		}
		switch action.Type {
		case harness.ActionFinish:
			if strings.TrimSpace(action.FinalReport) != "" {
				return "正在整理最终报告..."
			}
			return "准备完成任务..."
		case harness.ActionExecute:
			if action.Command != "" {
				return "准备执行 Shell: " + action.Command
			}
		case harness.ActionTool:
			if action.ToolName != "" {
				return "准备调用工具: " + action.ToolName
			}
		case harness.ActionTask:
			if action.TaskName != "" {
				return "准备委派子 Agent: " + action.TaskName
			}
			if len(action.ParallelTasks) > 0 {
				return fmt.Sprintf("准备并行委派 %d 个子 Agent", len(action.ParallelTasks))
			}
		case harness.ActionTodo:
			return "正在更新任务清单..."
		case harness.ActionAskUser:
			return "需要用户补充信息..."
		case harness.ActionReadFile:
			return "准备读取文件: " + action.Path
		case harness.ActionGrep:
			return "准备搜索: " + action.Pattern
		case harness.ActionLS:
			return "准备列目录: " + action.Path
		}
	}

	if thought := extractJSONStringField(raw, "thought"); thought != "" {
		return "思考: " + thought
	}
	if finalReport := extractJSONStringField(raw, "final_report"); finalReport != "" {
		return "正在整理最终报告..."
	}
	if action := extractJSONStringField(raw, "action"); action != "" {
		return "正在生成动作: " + action
	}
	if done {
		return "AI 思考完成"
	}
	return "AI 正在思考..."
}

func parseStreamAction(raw string) *harness.AgentAction {
	var action harness.AgentAction
	if err := json.Unmarshal([]byte(raw), &action); err == nil {
		return &action
	}
	return nil
}

func extractJSONStringField(raw, field string) string {
	marker := `"` + field + `":`
	idx := strings.Index(raw, marker)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(raw[idx+len(marker):])
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	var b strings.Builder
	escaped := false
	for _, r := range rest {
		if escaped {
			switch r {
			case 'n':
				b.WriteRune('\n')
			case 't':
				b.WriteRune('\t')
			case 'r':
				b.WriteRune('\r')
			default:
				b.WriteRune(r)
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func (m *AgentModel) appendLine(kind, display, raw string) {
	m.lineID++
	m.lines = append(m.lines, logLine{kind: kind, content: display, raw: raw, id: m.lineID, collapsed: kind == "subagent_result", at: time.Now()})
	if len(m.lines) > 500 {
		m.lines = m.lines[len(m.lines)-500:]
		m.streamIdx = -1
	}
}

func (m *AgentModel) appendAskLine(prompt string, options []string) {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return
	}
	if len(m.lines) > 0 {
		last := m.lines[len(m.lines)-1]
		if last.kind == "ask" && strings.TrimSpace(last.raw) == prompt {
			return
		}
	}
	m.appendLine("ask", renderAskPrompt(prompt, options), prompt)
}

func renderAskPrompt(prompt string, options []string) string {
	prompt = strings.TrimSpace(prompt)
	if len(options) == 0 {
		return prompt
	}
	var b strings.Builder
	b.WriteString(prompt)
	for i, opt := range options {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		if i == 0 {
			b.WriteString("\n")
		}
		b.WriteString(fmt.Sprintf("\n%d. %s", i+1, opt))
	}
	return strings.TrimSpace(b.String())
}

func (m *AgentModel) refreshViewport() {
	shouldStick := m.autoScroll || m.viewport.AtBottom()
	var b strings.Builder
	contentW := max(20, m.viewport.Width)
	if !m.startupInfo.isEmpty() {
		b.WriteString(m.cachedWelcomeBanner(contentW))
	}
	for _, ln := range m.lines {
		ts := lineTimestampPlain(ln)
		switch ln.kind {
		case "step":
			b.WriteString(renderWrapped(styleStep, ts+"▸ "+ln.content, contentW) + "\n")
		case "user":
			b.WriteString(renderWrapped(styleAccent, ts+"▸ "+ln.content, contentW) + "\n\n")
		case "thought":
			b.WriteString(renderWrapped(styleThought, ts+"💭 "+ln.content, contentW) + "\n\n")
		case "stream":
			body := ln.content
			if ln.collapsed {
				body = "AI 思考已完成  [e 展开]"
			}
			b.WriteString(renderWrapped(styleStream, ts+"▸ "+truncateLines(body, 6), contentW) + "\n\n")
		case "todo":
			b.WriteString(renderWrapped(styleTodoBox, ts+ln.content, contentW) + "\n\n")
		case "tool":
			b.WriteString(renderWrapped(styleToolBox, ts+"⚡ "+ln.content, contentW) + "\n\n")
		case "target":
			b.WriteString(renderWrapped(styleTargetBox, ts+"📡 "+ln.content, contentW) + "\n\n")
		case "subagent_start":
			b.WriteString(renderWrapped(styleSubAgentBox, ts+"🔀 "+ln.content, contentW) + "\n")
		case "subagent_result":
			body := ln.raw
			if ln.collapsed {
				body = ln.content + "  [e 展开]"
			}
			b.WriteString(renderWrapped(styleSubAgentResult, ts+"📦 "+truncateLines(body, 12), contentW) + "\n\n")
		case "result":
			b.WriteString(renderWrapped(styleResult, ts+"└ "+truncateLines(ln.content, 8), contentW) + "\n\n")
		case "ask":
			b.WriteString(renderWrapped(styleToolBox, ts+"? "+ln.content, contentW) + "\n\n")
		case "error":
			b.WriteString(renderWrapped(styleError, ts+"✗ "+ln.content, contentW) + "\n")
		case "success":
			b.WriteString(renderWrapped(styleSuccess, ts+"✓ 报告", contentW) + "\n")
			b.WriteString(renderMarkdownReport(ln.content, contentW) + "\n\n")
		default:
			b.WriteString(renderWrapped(styleInfo, ts+ln.content, contentW) + "\n")
		}
	}
	if m.thinking {
		b.WriteString("\n" + m.spinner.View() + styleInfo.Render(" Thinking..."))
	}
	m.viewportPlain = stripANSI(b.String())
	m.viewport.SetContent(b.String())
	if shouldStick {
		m.viewport.GotoBottom()
	}
}

func lineTimestampPlain(ln logLine) string {
	if ln.at.IsZero() {
		return ""
	}
	return "[" + ln.at.Format("15:04:05") + "] "
}

func (m AgentModel) renderHeader(w int) string {
	contentW := max(10, w-2)
	left := fmt.Sprintf("DeepSentry Agent  │  %s", m.title)
	rightMax := max(18, contentW/2)
	if contentW >= 100 {
		rightMax = min(contentW-24, (contentW*2)/3)
	}
	right := m.headerStatsText(rightMax)
	if right == "" {
		return styleHeader.Width(w).Render(runewidth.Truncate(left, contentW, "…"))
	}

	right = runewidth.Truncate(right, rightMax, "…")
	leftW := contentW - lipgloss.Width(right) - 1
	if leftW < 12 {
		leftW = 12
	}
	left = runewidth.Truncate(left, leftW, "…")
	gap := contentW - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return styleHeader.Width(w).Render(left + strings.Repeat(" ", gap) + right)
}

func (m AgentModel) headerStatsText(maxWidth int) string {
	if m.ctrl == nil {
		return ""
	}
	stats := m.ctrl.Stats()
	return formatHeaderStats(stats, m.running || stats.Running, m.tokenUsageLabel(stats), maxWidth)
}

func formatHeaderStats(stats SessionStats, running bool, tokenLabel string, maxWidth int) string {
	state := "idle"
	if running {
		state = "run"
	}
	fullSID := headerSessionID(stats.SessionID, 0)
	midSID := headerSessionID(stats.SessionID, 12)
	shortSID := shortSessionID(stats.SessionID)
	if shortSID == "" {
		shortSID = "sid -"
	}
	tokenCompact := strings.TrimSuffix(tokenLabel, " tok")
	candidates := []string{
		fmt.Sprintf("会话 %s · 状态 %s · 轮次 %d · 消息 %d · token %s", fullSID, state, stats.Turns, stats.Messages, tokenCompact),
		fmt.Sprintf("会话 %s · 状态 %s · 轮次 %d · 消息 %d · token %s", midSID, state, stats.Turns, stats.Messages, tokenCompact),
		fmt.Sprintf("%s · %s · 轮次 %d · 消息 %d · %s", midSID, state, stats.Turns, stats.Messages, tokenLabel),
		fmt.Sprintf("%s · %s · 轮%d · 消息%d · %s", shortSID, state, stats.Turns, stats.Messages, tokenLabel),
	}
	for _, text := range candidates {
		if maxWidth <= 0 || lipgloss.Width(text) <= maxWidth {
			return text
		}
	}
	return runewidth.Truncate(candidates[len(candidates)-1], maxWidth, "…")
}

func (m AgentModel) sessionStatsText(verbose bool) string {
	if m.ctrl == nil {
		return "会话统计不可用"
	}
	stats := m.ctrl.Stats()
	if !verbose {
		return fmt.Sprintf("会话=%s · 轮次=%d · 消息=%d · %s", shortSessionID(stats.SessionID), stats.Turns, stats.Messages, m.tokenUsageLabel(stats))
	}
	if m.tokenUsage.TotalTokens > 0 {
		return fmt.Sprintf("会话: %s · 用户轮次: %d · 历史消息: %d · 真实 token: %s total（prompt %s / completion %s / calls %d）",
			firstNonEmpty(stats.SessionID, "-"),
			stats.Turns,
			stats.Messages,
			formatApproxTokens(m.tokenUsage.TotalTokens),
			formatApproxTokens(m.tokenUsage.PromptTokens),
			formatApproxTokens(m.tokenUsage.CompletionTokens),
			m.tokenUsage.Calls,
		)
	}
	return fmt.Sprintf("会话: %s · 用户轮次: %d · 历史消息: %d · 上下文估算: ~%s tok（当前模型响应未返回 usage，按本地历史粗略估算）",
		firstNonEmpty(stats.SessionID, "-"),
		stats.Turns,
		stats.Messages,
		formatApproxTokens(stats.ApproxTokens),
	)
}

func (m AgentModel) statusContextText() string {
	if strings.TrimSpace(m.currentTarget) != "" {
		return m.currentTarget
	}
	switch {
	case m.pendingConfirm != nil:
		return "等待确认"
	case m.pendingAsk != nil:
		return "等待补充"
	case m.stopping:
		return "正在停止"
	case m.running:
		if m.thinking {
			return "模型思考中"
		}
		return "执行中"
	case m.done || m.sessionLive:
		return "就绪/可继续"
	default:
		return "就绪/等待任务"
	}
}

func (m AgentModel) tokenUsageLabel(stats SessionStats) string {
	if m.tokenUsage.TotalTokens > 0 {
		return fmt.Sprintf("%s tok", formatApproxTokens(m.tokenUsage.TotalTokens))
	}
	return fmt.Sprintf("~%s tok", formatApproxTokens(stats.ApproxTokens))
}

func shortSessionID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	parts := strings.Split(id, "_")
	tail := parts[len(parts)-1]
	if len(tail) > 6 {
		tail = tail[len(tail)-6:]
	}
	return "sid " + tail
}

func headerSessionID(id string, maxTail int) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "sid -"
	}
	id = strings.TrimPrefix(id, "session_")
	if maxTail > 0 && len(id) > maxTail {
		id = id[len(id)-maxTail:]
	}
	return "sid " + id
}

func formatApproxTokens(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(n)/1000000)
}

func (m AgentModel) View() string {
	if m.quitting {
		return ""
	}
	w, h := m.width, m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	bodyH := m.viewport.Height
	if bodyH <= 0 {
		bodyH = max(4, h-6)
	}

	header := m.renderHeader(w)
	stepInfo := ""
	if m.currentStep > 0 {
		stepInfo = fmt.Sprintf("Step %d/%d", m.currentStep, m.maxSteps)
	}
	var help string
	if m.copyToast != "" {
		help = m.copyToast
	} else if m.pendingConfirm != nil {
		help = "Y 批准 · N/Esc 拒绝 · Enter 不会批准高风险操作"
	} else if m.pendingAsk != nil {
		help = "输入补充内容或选项编号 · Enter 继续 · Shift+Enter 换行"
	} else {
		help = m.footerHelpText()
	}
	status := styleStatusBar.Width(w).Render(
		fmt.Sprintf("%s  │  %s  │  %s  │  %s", m.statusLine, m.statusContextText(), stepInfo, time.Now().Format("15:04:05")),
	)
	body := lipgloss.NewStyle().
		Width(w).
		Height(bodyH).
		Padding(0, 1).
		Render(m.viewportView())
	inputLine := lipgloss.NewStyle().PaddingLeft(1).Render(m.renderInputLine())
	helpW := ChromeContentWidth(w)
	helpText := runewidth.Truncate(help, helpW, "…")
	var helpLine string
	if m.copyToast != "" {
		helpLine = lipgloss.NewStyle().PaddingLeft(1).Foreground(colorAccent).Render(" " + helpText)
	} else {
		helpLine = styleHelpHint.PaddingLeft(1).Render(" " + helpText)
	}
	footerParts := []string{}
	if suggestions := m.renderSlashSuggestions(); suggestions != "" {
		footerParts = append(footerParts, suggestions)
	}
	footerParts = append(footerParts, status, inputLine, helpLine)
	footer := lipgloss.JoinVertical(lipgloss.Left, footerParts...)
	main := lipgloss.JoinVertical(lipgloss.Left, header, body, footer)
	if m.pendingConfirm != nil {
		main = main + "\n" + m.renderConfirm()
	}
	return styleApp.Width(w).Height(h).Render(main)
}

func (m *AgentModel) renderConfirm() string {
	return styleConfirmBox.Render(ui.TerminalText("⚠️  需要确认\n\n" + m.pendingConfirm.prompt + "\n\nY 批准 · N 拒绝 · Enter 不执行"))
}

func (m *AgentModel) recalcLayout() {
	w, h := m.width, m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	// header(1) + status(1) + input(3) + help(1) + optional slash suggestions.
	chromeLines := 6 + m.slashSuggestionLineCount()
	m.viewport.Width = max(0, w-2)
	m.viewport.Height = max(4, h-chromeLines)
	m.input.Width = ChromeContentWidth(w) - 2
}

func (m AgentModel) slashSuggestionLineCount() int {
	n := len(m.visibleSlashSuggestions())
	if n == 0 {
		return 0
	}
	return n + 2
}

func (m AgentModel) footerHelpText() string {
	if m.pendingAsk != nil {
		return "输入补充内容或选项编号 · Enter 继续 · Shift+Enter 换行 · Ctrl+U 清空"
	}
	if m.inputFocused() {
		if m.running {
			return "Esc 中断任务 · Enter 发送 · Shift+Enter 换行 · ↑↓ 历史 · Ctrl+U 清空 · Esc 退出输入 · Tab 浏览"
		}
		return "Enter 发送 · Shift+Enter 换行 · ↑↓ 历史 · Ctrl+U 清空 · Ctrl+L 清屏 · Esc 退出输入 · Tab 浏览 · /help 命令"
	}
	if m.running {
		return "Tab 输入新指令并 Enter 可中途打断 · Esc 停止 · 鼠标拖选 · ↑↓/jk 滚动 · e 展开 · Y/N 确认"
	}
	return "Tab 输入 · 鼠标拖选 · Ctrl+C 复制 · ↑↓/jk 滚动 · PgUp/PgDn · e 展开 · G 底部 · Ctrl+L 清屏 · q 退出 · /help"
}

func (m AgentModel) inputHintText() string {
	if m.awaitGoal {
		return "> 描述安全任务，Enter 开始..."
	}
	if m.pendingAsk != nil {
		return "> 输入补充信息或选项编号，Enter 继续..."
	}
	if m.sessionLive || m.done {
		return "> 追问上一题或继续排查，Enter 发送..."
	}
	return "> Enter 发送..."
}

func (m AgentModel) inputPlaceholderText() string {
	if m.awaitGoal {
		return "> task, Enter to start..."
	}
	if m.pendingAsk != nil {
		return "> answer, Enter to continue..."
	}
	if m.sessionLive || m.done {
		return "> follow up, Enter to send..."
	}
	return "> Enter to send..."
}

func (m AgentModel) renderInputLine() string {
	w := ChromeContentWidth(m.width)
	border := styleInputBorder
	if m.inputFocused() {
		border = styleInputBorderFocused
	}
	innerW := w - 2

	m.input.Width = innerW
	m.input.Placeholder = m.inputPlaceholderText()

	var content string
	switch {
	case m.inputFocused():
		content = m.renderFocusedInputContent(innerW)
	case m.running && !m.awaitGoal:
		hint := "Agent 执行中..."
		if m.pendingConfirm != nil {
			hint = "等待确认 · Y 批准 / N 拒绝"
		} else if m.pendingAsk != nil {
			hint = "等待补充信息 · Tab 输入"
		}
		content = styleInfo.Render(runewidth.Truncate(hint, innerW, "..."))
	default:
		if m.input.Value() == "" {
			content = styleInfo.Render(runewidth.Truncate(m.inputHintText(), innerW, "..."))
		} else {
			content = m.input.View()
		}
	}
	row := fitStyledLine(content, innerW)
	return renderChromeBox([]string{row}, w, border)
}

func (m AgentModel) visibleSlashSuggestions() []slashCommand {
	suggestions := m.slashSuggestions()
	if len(suggestions) > 5 {
		return suggestions[:5]
	}
	return suggestions
}

func (m AgentModel) renderSlashSuggestions() string {
	suggestions := m.visibleSlashSuggestions()
	if len(suggestions) == 0 {
		return ""
	}
	w := ChromeContentWidth(m.width)
	innerW := w - 2
	if innerW < 12 {
		return ""
	}
	selected := m.slashSelected
	if selected < 0 {
		selected = 0
	}
	if selected >= len(suggestions) {
		selected = len(suggestions) - 1
	}
	nameW := 16
	if innerW < 44 {
		nameW = 12
	}
	descW := innerW - nameW - 4
	if descW < 8 {
		descW = 8
	}
	rows := make([]string, 0, len(suggestions))
	for i, cmd := range suggestions {
		prefix := "  "
		nameStyle := styleInputLine
		descStyle := styleInfo
		if i == selected {
			prefix = "> "
			nameStyle = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
			descStyle = lipgloss.NewStyle().Foreground(colorText)
		}
		name := runewidth.Truncate("/"+cmd.Name, nameW, "…")
		desc := runewidth.Truncate(cmd.Description, descW, "…")
		row := prefix + nameStyle.Render(name+strings.Repeat(" ", max(0, nameW-runewidth.StringWidth(name)))) + "  " + descStyle.Render(desc)
		rows = append(rows, fitStyledLine(row, innerW))
	}
	return lipgloss.NewStyle().PaddingLeft(1).Render(renderChromeBox(rows, w, styleInputBorderFocused))
}

func (m AgentModel) renderFocusedInputContent(width int) string {
	if width <= 0 {
		return ""
	}
	value := m.input.Value()
	if value == "" {
		value = m.inputPlaceholderText()
	}
	pos := m.input.Position()
	runes := []rune(value)
	if pos < 0 {
		pos = 0
	}
	if pos > len(runes) {
		pos = len(runes)
	}
	prefix := string(runes[:pos])
	cursor := " "
	suffix := ""
	if pos < len(runes) {
		cursor = string(runes[pos])
		suffix = string(runes[pos+1:])
	}

	for runewidth.StringWidth(prefix)+runewidth.StringWidth(cursor) > width && len([]rune(prefix)) > 0 {
		prefix = string([]rune(prefix)[1:])
	}
	remaining := width - runewidth.StringWidth(prefix) - runewidth.StringWidth(cursor)
	if remaining < 0 {
		remaining = 0
	}
	suffix = runewidth.Truncate(suffix, remaining, "")

	textStyle := styleInputLine
	if m.input.Value() == "" {
		textStyle = styleInfo.Background(colorSurface)
	}
	return textStyle.Render(prefix) + styleInputCursor.Render(cursor) + textStyle.Render(suffix)
}

func (m AgentModel) inputCursorAnchor() (row, col int, ok bool) {
	if !m.inputFocused() {
		return 0, 0, false
	}
	w, h := m.width, m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	bodyH := m.viewport.Height
	if bodyH <= 0 {
		bodyH = max(4, h-6)
	}
	innerW := ChromeContentWidth(w) - 2
	value := m.input.Value()
	pos := m.input.Position()
	if pos < 0 {
		pos = 0
	}
	runes := []rune(value)
	if pos > len(runes) {
		pos = len(runes)
	}
	prefix := string(runes[:pos])
	cursorCol := runewidth.StringWidth(prefix)
	if cursorCol >= innerW {
		cursorCol = innerW - 1
	}
	if cursorCol < 0 {
		cursorCol = 0
	}
	// 1-based terminal coordinates: header + viewport + status + input top border + content row.
	return 1 + bodyH + 1 + 1 + 1, 1 + 1 + cursorCol + 1, true
}

func (m AgentModel) scheduleInputCursorAnchor() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	row, col, ok := m.inputCursorAnchor()
	if !ok {
		cancelInputCursorAnchor()
		return
	}
	seq := inputCursorAnchorSeq.Add(1)
	go func() {
		for _, d := range []time.Duration{4 * time.Millisecond, 16 * time.Millisecond, 36 * time.Millisecond} {
			time.Sleep(d)
			if inputCursorAnchorSeq.Load() != seq {
				return
			}
			fmt.Fprintf(os.Stdout, "\x1b[%d;%dH", row, col)
		}
	}()
}

func clampInputWidth(w int) int {
	if w < 1 {
		return 1
	}
	return w
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// 兼容旧 Model 别名
type Model = AgentModel

func NewModel(title, status string, maxSteps int) AgentModel {
	return NewAgentModel(nil, title, status, maxSteps, false, false, StartupInfo{})
}

func WaitConfirm(program *tea.Program, action *harness.AgentAction, prompt string) bool {
	ch := make(chan bool, 1)
	program.Send(confirmMsg{action: action, prompt: prompt, respCh: ch})
	return <-ch
}

func WaitUserInput(program *tea.Program, action *harness.AgentAction) (string, bool) {
	if action == nil {
		return "", false
	}
	ch := make(chan string, 1)
	prompt := strings.TrimSpace(action.Question)
	if prompt == "" {
		prompt = "请补充继续任务所需的信息。"
	}
	program.Send(askMsg{action: action, prompt: prompt, options: action.Options, respCh: ch})
	answer := <-ch
	return answer, strings.TrimSpace(answer) != ""
}

func EventCmd(e harness.UIEvent) tea.Cmd {
	return func() tea.Msg { return uiEventMsg(e) }
}

func DoneCmd() tea.Cmd { return func() tea.Msg { return agentDoneMsg{} } }

var styleAccent = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)

func truncateLines(s string, maxLines int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[:maxLines], "\n") + "\n..."
}

func truncateStr(s string, n int) string {
	s = strings.TrimSpace(s)
	if runewidth.StringWidth(s) <= n {
		return s
	}
	return runewidth.Truncate(s, n, "...")
}

func pasteSummary(s string) string {
	lines := strings.Count(s, "\n") + 1
	chars := len([]rune(s))
	return fmt.Sprintf("[已粘贴 %d 行 / %d 字符，Enter 发送完整内容，Ctrl+U 清空]", lines, chars)
}

func summarizeUserText(s string) string {
	lines := strings.Count(s, "\n") + 1
	chars := len([]rune(s))
	first := strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if first == "" {
		first = strings.TrimSpace(s)
	}
	first = truncateStr(first, 80)
	return fmt.Sprintf("[长文本已折叠：%d 行 / %d 字符] %s", lines, chars, first)
}

func renderWrapped(style lipgloss.Style, text string, width int) string {
	if width <= 0 {
		width = 80
	}
	text = ui.TerminalText(text)
	innerW := width - style.GetHorizontalFrameSize()
	if innerW < 1 {
		innerW = 1
	}
	wrapped := wrapDisplay(text, innerW)
	return style.Width(innerW).Render(wrapped)
}

func wrapDisplay(s string, width int) string {
	if width <= 0 {
		return s
	}
	parts := strings.Split(s, "\n")
	for i, part := range parts {
		parts[i] = runewidth.Wrap(part, width)
	}
	return strings.Join(parts, "\n")
}
