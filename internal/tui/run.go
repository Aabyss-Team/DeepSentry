package tui

import (
	"ai-edr/internal/analyzer"
	"ai-edr/internal/collector"
	"ai-edr/internal/config"
	"ai-edr/internal/harness"
	"ai-edr/internal/logger"
	"ai-edr/internal/ui"

	tea "github.com/charmbracelet/bubbletea"
)

// SessionConfig TUI 会话参数
type SessionConfig struct {
	Agent            *harness.DeepAgent
	SysCtx           collector.SystemContext
	History          *[]analyzer.Message
	Reporter         *logger.Reporter
	ReportPath       string
	BatchMode        bool
	MaxSteps         int
	SubAgentMaxSteps int
	ConnInfo         string
	ModelInfo        string
	Startup          StartupInfo
	AwaitGoal        bool
	MultiTurn        bool // Claude Code 式多轮追问（默认开启）
	PlanMode         bool
}

// Run 启动全屏 Agent TUI（支持多轮 follow-up）
func Run(cfg SessionConfig) error {
	ctrl := newSessionController(cfg)
	defer ctrl.Sink().Close()
	defer ui.ResetTerminalState()

	title := cfg.ModelInfo
	if title == "" {
		title = config.GlobalConfig.ModelName
	}
	status := cfg.ConnInfo
	if status == "" {
		status = "本地模式"
	}

	m := NewAgentModel(ctrl, title, status, cfg.MaxSteps, cfg.AwaitGoal, !cfg.AwaitGoal && len(*cfg.History) > 0, cfg.Startup)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseAllMotion())
	ctrl.SetProgram(p)

	go ctrl.pumpEvents()

	_, err := p.Run()
	return err
}
