package harness

import (
	"ai-edr/internal/analyzer"
	"ai-edr/internal/collector"
	"ai-edr/internal/logger"
)

// RunLoopConfig Agent 主循环配置
type RunLoopConfig struct {
	SysCtx           collector.SystemContext
	History          *[]analyzer.Message
	Reporter         *logger.Reporter
	ReportPath       string
	BatchMode        bool
	NonInteractive   bool // WebShell/JSON/quiet 等无法稳定二次交互的 stdout 场景
	PauseOnAskUser   bool // 兼容旧 checkpoint 恢复逻辑；非交互主流程默认不允许 ask_user 阻塞
	MaxSteps         int
	SubAgentMaxSteps int
	MultiTurn        bool // TUI 等多轮会话：finish 后保留上下文，支持追问
	PlanMode         bool // 先澄清/规划，再按计划执行
	ConfirmFn        func(*AgentAction) bool
	AwaitUserFn      func(*AgentAction) (string, bool)
	UI               UISink
	Stop             <-chan struct{}
}
