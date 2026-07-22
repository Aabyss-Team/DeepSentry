package tui

import (
	"fmt"
	"runtime/debug"
	"strings"
	"sync"

	"ai-edr/internal/analyzer"
	"ai-edr/internal/harness"

	tea "github.com/charmbracelet/bubbletea"
)

// SessionController 驱动 Agent 循环（Claude Code 式多轮追问）
type SessionController struct {
	cfg                  SessionConfig
	sink                 *ChannelSink
	mu                   sync.Mutex
	confirmMu            sync.Mutex
	sessionApprovals     map[string]string
	sudoMu               sync.Mutex
	running              bool
	turn                 int
	program              *tea.Program
	stopCh               chan struct{}
	stopped              bool
	pendingInterruptText string
	cachedStats          SessionStats
}

type SessionStats struct {
	SessionID    string
	Turns        int
	Messages     int
	ApproxTokens int
	Running      bool
}

func newSessionController(cfg SessionConfig) *SessionController {
	return &SessionController{
		cfg:              cfg,
		sink:             NewChannelSink(2048),
		stopCh:           make(chan struct{}),
		sessionApprovals: make(map[string]string),
	}
}

func (c *SessionController) Sink() *ChannelSink { return c.sink }

func (c *SessionController) SetProgram(p *tea.Program) { c.program = p }

func (c *SessionController) Stats() SessionStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The agent owns and mutates History while a run is active. Reading that
	// slice from the renderer at the same time is a data race and can observe a
	// half-written slice header. Serve the last safe snapshot until the run has
	// stopped; real token usage is tracked independently by UI events.
	if !c.running {
		c.refreshStatsLocked()
	}
	stats := c.cachedStats
	stats.Running = c.running
	return stats
}

func (c *SessionController) refreshStatsLocked() {
	stats := SessionStats{
		Turns:    c.turn,
		Messages: 0,
	}
	if c.cfg.Agent != nil {
		stats.SessionID = c.cfg.Agent.SessionID
	}
	if c.cfg.History != nil {
		stats.Messages = len(*c.cfg.History)
		stats.Turns = harness.CountUserTurns(*c.cfg.History)
		stats.ApproxTokens = estimateHistoryTokens(*c.cfg.History)
	}
	c.cachedStats = stats
}

func (c *SessionController) pumpEvents() {
	for {
		select {
		case e := <-c.sink.Events():
			if c.program != nil {
				c.program.Send(uiEventMsg(e))
			}
		case <-c.sink.Done():
			return
		}
	}
}

func (c *SessionController) confirmFn(action *harness.AgentAction) bool {
	if action == nil {
		return false
	}
	if c.cfg.BatchMode || c.program == nil {
		if c.program != nil {
			c.program.Send(uiEventMsg(harness.UIEvent{Kind: harness.EventBatchAuto, Message: "Batch 模式已启用：本次操作自动批准"}))
		}
		return true
	}
	c.confirmMu.Lock()
	defer c.confirmMu.Unlock()
	c.mu.Lock()
	stopped := c.stopped
	c.mu.Unlock()
	if stopped {
		return false
	}
	scopeKey, scopeLabel := action.ApprovalScopeKey, action.ApprovalScopeLabel
	if scopeKey == "" {
		scopeKey, scopeLabel = harness.SessionApprovalScope(action)
	}
	if label, ok := c.sessionApprovals[scopeKey]; ok && scopeKey != "" {
		c.program.Send(uiEventMsg(harness.UIEvent{Kind: harness.EventRiskAuto, Message: "已命中本会话授权：" + label}))
		return true
	}
	prompt := fmt.Sprintf("**操作类型**：`%s`", action.Type)
	if action.Type == harness.ActionExecute {
		prompt = "**高风险命令**\n\n```sh\n" + action.Command + "\n```"
	} else if action.Type == harness.ActionTool {
		prompt = fmt.Sprintf("**工具**：`%s`\n\n**风险等级**：%s", action.ToolName, action.RiskLevel)
	}
	if reason := strings.TrimSpace(action.Reason); reason != "" {
		prompt += "\n\n**确认原因**：" + reason
	}
	if scopeLabel != "" {
		prompt += "\n\n**A 本会话允许**：" + scopeLabel
	}
	decision := WaitConfirm(c.program, action, prompt)
	if decision == approvalAllowSession && scopeKey != "" {
		c.sessionApprovals[scopeKey] = scopeLabel
	}
	return decision != approvalDeny
}

func (c *SessionController) clearSessionApprovals() {
	c.confirmMu.Lock()
	c.sessionApprovals = make(map[string]string)
	c.confirmMu.Unlock()
}

func (c *SessionController) RequestStop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return
	}
	if c.stopCh != nil {
		close(c.stopCh)
	}
	c.stopped = true
}

func (c *SessionController) InterruptWithInput(text string) bool {
	text = trimInput(text)
	if text == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return false
	}
	// Do not append to History while RunLoop is using it. Queue the rewrite and
	// commit it after the current run acknowledges stop, then start the next run.
	c.pendingInterruptText = text
	if !c.stopped {
		if c.stopCh != nil {
			close(c.stopCh)
		}
		c.stopped = true
	}
	return true
}

// beginRun 在后台启动 Agent（禁止在 Update 内 program.Send，由调用方通过 tea.Cmd 触发 UI 状态）
func (c *SessionController) beginRun() bool {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return false
	}
	c.refreshStatsLocked()
	c.running = true
	c.stopCh = make(chan struct{})
	c.stopped = false
	c.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				msg := fmt.Sprintf("⚠️  Agent 异常: %v", r)
				if c.program != nil {
					c.program.Send(uiEventMsg(harness.UIEvent{Kind: harness.EventError, Message: msg}))
				}
				_ = debug.Stack()
			}
			c.mu.Lock()
			c.running = false
			interruptText := c.pendingInterruptText
			c.pendingInterruptText = ""
			if interruptText != "" && c.cfg.History != nil {
				*c.cfg.History = append(*c.cfg.History, analyzer.Message{Role: "user", Content: "【用户中途打断/改写目标】" + interruptText})
			}
			c.refreshStatsLocked()
			c.mu.Unlock()
			if interruptText != "" && c.beginRun() {
				if c.program != nil {
					c.program.Send(agentStartMsg{followUp: true})
				}
				return
			}
			if c.program != nil {
				c.program.Send(agentDoneMsg{})
			}
		}()

		c.cfg.Agent.RunLoop(harness.RunLoopConfig{
			SysCtx:           c.cfg.SysCtx,
			History:          c.cfg.History,
			Reporter:         c.cfg.Reporter,
			ReportPath:       c.cfg.ReportPath,
			BatchMode:        c.cfg.BatchMode,
			MaxSteps:         c.cfg.MaxSteps,
			SubAgentMaxSteps: c.cfg.SubAgentMaxSteps,
			MultiTurn:        c.cfg.MultiTurn,
			PlanMode:         c.cfg.PlanMode,
			CompetitionMode:  c.cfg.CompetitionMode,
			ConfirmFn:        c.confirmFn,
			AwaitUserFn:      c.awaitUserFn,
			SudoAuthFn:       c.sudoAuthFn,
			UI:               c.sink,
			Stop:             c.stopCh,
		})
	}()
	return true
}

func (c *SessionController) awaitUserFn(action *harness.AgentAction) (string, bool) {
	if c.program == nil {
		return "", false
	}
	return WaitUserInput(c.program, action)
}

func (c *SessionController) sudoAuthFn() bool {
	if c.cfg.BatchMode || c.program == nil {
		return false
	}
	c.sudoMu.Lock()
	defer c.sudoMu.Unlock()
	ch := make(chan bool, 1)
	c.program.Send(sudoAuthMsg{respCh: ch})
	c.mu.Lock()
	stop := c.stopCh
	c.mu.Unlock()
	select {
	case ok := <-ch:
		return ok
	case <-stop:
		return false
	}
}

// PrepareFollowUp 追问：写入 history 并启动新一轮
func (c *SessionController) PrepareFollowUp(text string) bool {
	text = trimInput(text)
	if text == "" {
		return false
	}
	c.mu.Lock()
	if c.running || c.cfg.History == nil {
		c.mu.Unlock()
		return false
	}
	c.turn++
	*c.cfg.History = append(*c.cfg.History, analyzer.Message{Role: "user", Content: text})
	c.refreshStatsLocked()
	c.mu.Unlock()
	return c.beginRun()
}

// SetInitialGoal 设置首条用户需求
func (c *SessionController) SetInitialGoal(goal string) {
	goal = trimInput(goal)
	if goal == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.History == nil || c.running {
		return
	}
	*c.cfg.History = append(*c.cfg.History, analyzer.Message{Role: "user", Content: "需求：" + goal})
	c.refreshStatsLocked()
}

// StartNewSession 清空当前 TUI 上下文并创建新的 checkpoint session。
// 若传入 goal，会写入首条用户需求；由调用方在 UI 状态重置后再 beginRun。
func (c *SessionController) StartNewSession(goal string) (string, bool, error) {
	goal = trimInput(goal)
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return "", false, fmt.Errorf("当前任务仍在运行")
	}
	c.mu.Unlock()

	agent, err := harness.NewDeepAgent(harness.Config{
		BatchMode: c.cfg.BatchMode,
	})
	if err != nil {
		return "", false, err
	}

	c.mu.Lock()
	c.cfg.Agent = agent
	if c.cfg.History != nil {
		*c.cfg.History = nil
	}
	c.turn = 0
	c.pendingInterruptText = ""
	c.refreshStatsLocked()
	c.stopped = false
	c.stopCh = make(chan struct{})
	c.mu.Unlock()
	c.clearSessionApprovals()

	if goal == "" {
		return agent.SessionID, false, nil
	}
	c.SetInitialGoal(goal)
	return agent.SessionID, true, nil
}

func (c *SessionController) ResumeSession(sessionID, supplement string) (int, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return 0, fmt.Errorf("session_id 不能为空")
	}
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return 0, fmt.Errorf("当前任务仍在运行")
	}
	c.mu.Unlock()

	cp, err := harness.LoadCheckpoint(sessionID)
	if err != nil {
		return 0, err
	}
	agent, err := harness.NewDeepAgent(harness.Config{
		BatchMode: c.cfg.BatchMode,
		SessionID: sessionID,
	})
	if err != nil {
		return 0, err
	}
	agent.RestoreFromCheckpoint(cp)
	history := append([]analyzer.Message(nil), cp.History...)
	if len(history) == 0 {
		history = []analyzer.Message{{Role: "user", Content: "继续之前的任务"}}
	}
	if strings.TrimSpace(supplement) != "" {
		history = append(history, analyzer.Message{Role: "user", Content: "用户补充：" + strings.TrimSpace(supplement)})
	}

	c.mu.Lock()
	c.cfg.Agent = agent
	if c.cfg.History == nil {
		c.cfg.History = &[]analyzer.Message{}
	}
	*c.cfg.History = history
	c.turn = 0
	c.pendingInterruptText = ""
	c.refreshStatsLocked()
	c.stopped = false
	c.stopCh = make(chan struct{})
	c.mu.Unlock()
	c.clearSessionApprovals()

	return cp.StepNum, nil
}

func trimInput(s string) string {
	return strings.TrimSpace(s)
}

func estimateHistoryTokens(history []analyzer.Message) int {
	totalBytes := 0
	for _, msg := range history {
		totalBytes += len(msg.Role) + len(msg.Content) + 8
	}
	if totalBytes == 0 {
		return 0
	}
	return (totalBytes + 3) / 4
}
