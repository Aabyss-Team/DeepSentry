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
	cfg              SessionConfig
	sink             *ChannelSink
	mu               sync.Mutex
	running          bool
	turn             int
	program          *tea.Program
	stopCh           chan struct{}
	stopped          bool
	pendingInterrupt bool
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
		cfg:    cfg,
		sink:   NewChannelSink(2048),
		stopCh: make(chan struct{}),
	}
}

func (c *SessionController) Sink() *ChannelSink { return c.sink }

func (c *SessionController) SetProgram(p *tea.Program) { c.program = p }

func (c *SessionController) Stats() SessionStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	stats := SessionStats{
		Turns:    c.turn,
		Running:  c.running,
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
	return stats
}

func (c *SessionController) pumpEvents() {
	for e := range c.sink.Events() {
		if c.program != nil {
			c.program.Send(uiEventMsg(e))
		}
	}
}

func (c *SessionController) confirmFn(action *harness.AgentAction) bool {
	if c.cfg.BatchMode || c.program == nil {
		if c.program != nil {
			c.program.Send(uiEventMsg(harness.UIEvent{Kind: harness.EventBatchAuto, Message: "Batch 模式已启用：本次操作自动批准"}))
		}
		return true
	}
	prompt := fmt.Sprintf("确认执行 %s ?", action.Type)
	if action.Type == harness.ActionExecute {
		prompt = fmt.Sprintf("高风险命令: %s", truncateStr(action.Command, 80))
	} else if action.Type == harness.ActionTool {
		prompt = fmt.Sprintf("工具 %s (%s)", action.ToolName, action.RiskLevel)
	}
	return WaitConfirm(c.program, action, prompt)
}

func (c *SessionController) RequestStop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return
	}
	close(c.stopCh)
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
	*c.cfg.History = append(*c.cfg.History, analyzer.Message{Role: "user", Content: "【用户中途打断/改写目标】" + text})
	c.pendingInterrupt = true
	if !c.stopped {
		close(c.stopCh)
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
			restart := c.pendingInterrupt
			c.pendingInterrupt = false
			c.mu.Unlock()
			if restart && c.beginRun() {
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
			ConfirmFn:        c.confirmFn,
			AwaitUserFn:      c.awaitUserFn,
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

// PrepareFollowUp 追问：写入 history 并启动新一轮
func (c *SessionController) PrepareFollowUp(text string) bool {
	text = trimInput(text)
	if text == "" {
		return false
	}
	c.turn++
	*c.cfg.History = append(*c.cfg.History, analyzer.Message{Role: "user", Content: text})
	return c.beginRun()
}

// SetInitialGoal 设置首条用户需求
func (c *SessionController) SetInitialGoal(goal string) {
	goal = trimInput(goal)
	if goal == "" {
		return
	}
	*c.cfg.History = append(*c.cfg.History, analyzer.Message{Role: "user", Content: "需求：" + goal})
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
	c.pendingInterrupt = false
	c.stopped = false
	c.stopCh = make(chan struct{})
	c.mu.Unlock()

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
	c.pendingInterrupt = false
	c.stopped = false
	c.stopCh = make(chan struct{})
	c.mu.Unlock()

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
