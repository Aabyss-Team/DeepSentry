package harness

import (
	"ai-edr/internal/analyzer"
	"ai-edr/internal/collector"
	"ai-edr/internal/config"
	"ai-edr/internal/executor"
	"ai-edr/internal/harness/subagent"
	"ai-edr/internal/memory"
	"ai-edr/internal/security"
	"ai-edr/internal/skills"
	"fmt"
	"strings"
)

// SubAgentRunner 子 Agent 运行器（复用 harness middleware，无 sub-sub-agent）
type SubAgentRunner struct {
	Middleware   []Middleware
	State        *AgentState
	Catalog      *skills.SkillCatalog
	MemoryStore  *memory.Store
	UseNative    bool
	UI           UISink
	ConfirmFn    func(*AgentAction) bool
	MaxStepsCap  int
	TaskMaxSteps int
	StepFn       func(analyzer.StepOptions) (analyzer.AgentResponse, error)
	Executor     executor.Executor
	Target       config.TargetConfig
}

type commandRiskReviewer func(collector.SystemContext, string, string) (string, string, bool)

var makeSubAgentRunner = func(parent *DeepAgent) *SubAgentRunner {
	return NewSubAgentRunner(parent)
}

// NewSubAgentRunner 创建子 Agent 运行器
func NewSubAgentRunner(parent *DeepAgent) *SubAgentRunner {
	return &SubAgentRunner{
		Middleware:  SubAgentMiddlewareStack(parent.Catalog, parent.MemoryStore),
		State:       NewAgentStateWithSession(parent.State.WorkspaceDir, parent.SessionID),
		Catalog:     parent.Catalog,
		MemoryStore: parent.MemoryStore,
		UseNative:   parent.UseNativeTools,
	}
}

// Run 在隔离上下文中运行子 Agent
func (r *SubAgentRunner) Run(spec subagent.Spec, taskPrompt string, sysCtx collector.SystemContext, batchMode bool) (string, error) {
	subHistory := []analyzer.Message{
		{Role: "user", Content: taskPrompt},
	}
	if r.Target.Name != "" || r.Target.Host != "" {
		targetPrompt := fmt.Sprintf("【当前子 Agent 目标】name=%s protocol=%s host=%s user=%s\n所有 execute/read_file/grep/ls/tool 的 target 视角都限定在这台机器；不要操作其他目标。",
			r.Target.Name, r.Target.Protocol, r.Target.Host, r.Target.User)
		subHistory = append([]analyzer.Message{{Role: "system", Content: targetPrompt}}, subHistory...)
	}

	maxSteps := resolveSubAgentMaxSteps(spec, taskPrompt, r.TaskMaxSteps, r.MaxStepsCap)

	extraBase := spec.SystemPrompt + `
【子 Agent 模式】
- Shell-first：优先使用 execute 执行目标机原生 Shell 直接排查；原生命令能完成时不要先调用 tool/tool_catalog
- read_file/grep/ls 可用于文件类低风险观察；只有目标机缺少命令、输出格式复杂、需要结构化 Go 原生能力或控制端探测时，才先 tool_catalog 调研，再按需调用具体 tool
- 禁止委派子 Agent (task)
- 完成后 action="finish" 并给出 final_report
`

	var results []string

	for step := 0; step < maxSteps; step++ {
		if r.UI != nil {
			r.UI.Emit(UIEvent{
				Kind:           EventSubAgentStep,
				Message:        fmt.Sprintf("%s step %d/%d", spec.Name, step+1, maxSteps),
				Detail:         taskPrompt,
				TargetName:     r.Target.Name,
				TargetProtocol: r.Target.Protocol,
				TargetHost:     r.Target.Host,
			})
		}
		extraPrompt := extraBase
		for _, mw := range r.Middleware {
			extraPrompt = mw.EnhancePrompt(extraPrompt, r.State)
		}

		stepFn := r.StepFn
		if stepFn == nil {
			stepFn = analyzer.RunAgentStepWithOptions
		}
		resp, err := stepFn(analyzer.StepOptions{
			SysCtx:         sysCtx,
			History:        &subHistory,
			ExtraPrompt:    extraPrompt,
			UseNativeTools: r.UseNative,
		})
		if err != nil {
			return "", fmt.Errorf("子 Agent [%s] 第 %d 步失败: %w", spec.Name, step+1, err)
		}

		action := ParseAction(resp)

		if action.Type == ActionFinish || action.IsFinished {
			if action.FinalReport != "" {
				return action.FinalReport, nil
			}
			if action.Thought != "" {
				return action.Thought, nil
			}
			return "子 Agent 任务完成", nil
		}

		if isEmptyAction(action) {
			subHistory = append(subHistory, analyzer.Message{
				Role:    "assistant",
				Content: actionToJSON(action),
			})
			subHistory = append(subHistory, analyzer.Message{
				Role:    "user",
				Content: "请执行具体 action 或 finish 返回结论。",
			})
			continue
		}
		if r.UI != nil {
			actCopy := action
			enrichActionExecutionTargetFor(&actCopy, r.Target)
			r.UI.Emit(UIEvent{Kind: EventSubAgentAction, Message: spec.Name, Action: &actCopy, TargetName: r.Target.Name, TargetProtocol: r.Target.Protocol, TargetHost: r.Target.Host})
		}

		if action.Type == ActionTask {
			subHistory = append(subHistory, analyzer.Message{
				Role: "user", Content: "子 Agent 不能委派 task，请直接执行。",
			})
			continue
		}
		if action.Type == ActionAskUser {
			question := strings.TrimSpace(action.Question)
			if question == "" {
				question = strings.TrimSpace(action.Thought)
			}
			if question == "" {
				question = "缺少必要信息"
			}
			return fmt.Sprintf("子 Agent [%s] 需要主流程补充信息后才能继续: %s", spec.Name, question), nil
		}

		// 子 Agent execute 风控：与主 Agent 一致，先 AI 复核，再按需人工确认。
		if action.Type == ActionExecute || action.Command != "" {
			allowed, feedback := authorizeSubAgentExecute(&action, sysCtx, batchMode, r.UI, r.ConfirmFn, reviewCommandRiskWithAI)
			if !allowed {
				msg := fmt.Sprintf("[步骤 %d] 高危命令未执行: %s", step+1, action.Command)
				results = append(results, msg)
				subHistory = append(subHistory, analyzer.Message{
					Role: "user", Content: feedback,
				})
				continue
			}
		}

		stepCtx := &StepContext{
			SysCtx:      sysCtx,
			State:       r.State,
			History:     &subHistory,
			BatchMode:   batchMode,
			StepNum:     step + 1,
			MaxSteps:    maxSteps,
			MemoryStore: r.MemoryStore,
			UI:          r.UI,
			ConfirmFn:   r.ConfirmFn,
			Executor:    firstExecutor(r.Executor),
			TargetName:  r.Target.Name,
			TargetProto: r.Target.Protocol,
			TargetHost:  r.Target.Host,
		}

		agent := &DeepAgent{Middleware: r.Middleware, State: r.State, MemoryStore: r.MemoryStore}
		result, err := agent.HandleAction(stepCtx, &action)
		if err != nil {
			return "", err
		}

		if result.ShouldStop {
			return result.FinalReport, nil
		}

		out := result.Output
		if len(out) > 4000 {
			out = out[:4000] + "\n...(输出已截断)..."
		}
		results = append(results, fmt.Sprintf("[步骤 %d] %s\n%s", step+1, action.Type, out))

		subHistory = append(subHistory, analyzer.Message{
			Role:    "assistant",
			Content: actionToJSON(action),
		})
		subHistory = append(subHistory, analyzer.Message{
			Role: "user", Content: fmt.Sprintf("Output:\n%s", result.Output),
		})
	}

	summary := strings.Join(results, "\n---\n")
	if len(summary) > 6000 {
		summary = summary[:6000] + "\n...(子 Agent 输出已截断)..."
	}
	return fmt.Sprintf("子 Agent [%s] 达到最大步数，部分结果:\n%s", spec.Name, summary), nil
}

func resolveSubAgentMaxSteps(spec subagent.Spec, taskPrompt string, requested, cap int) int {
	if cap <= 0 {
		cap = 15
	}
	base := spec.MaxSteps
	if base <= 0 {
		base = 15
	}
	estimated := estimateSubAgentSteps(taskPrompt, base)
	maxSteps := max(base, estimated)
	if requested > 0 {
		maxSteps = max(maxSteps, requested)
	}
	if maxSteps > cap {
		maxSteps = cap
	}
	if maxSteps < 1 {
		maxSteps = 1
	}
	return maxSteps
}

func estimateSubAgentSteps(taskPrompt string, base int) int {
	text := strings.ToLower(taskPrompt)
	estimate := base
	complexHints := []string{"完整", "综合", "所有", "全部", "多", "日志", "时间线", "证据链", "关联", "异常", "webshell", "漏洞", "基线", "横向", "提权", "登录", "auth", "syslog", "nginx", "apache", "access", "error"}
	for _, hint := range complexHints {
		if strings.Contains(text, strings.ToLower(hint)) {
			estimate += 2
		}
	}
	if n := strings.Count(taskPrompt, "\n") + strings.Count(taskPrompt, "；") + strings.Count(taskPrompt, ";"); n > 2 {
		estimate += n
	}
	if len([]rune(taskPrompt)) > 240 {
		estimate += 4
	}
	if estimate > 35 {
		estimate = 35
	}
	return estimate
}

func authorizeSubAgentExecute(action *AgentAction, sysCtx collector.SystemContext, batchMode bool, ui UISink, confirmFn func(*AgentAction) bool, reviewer commandRiskReviewer) (bool, string) {
	if action == nil || strings.TrimSpace(action.Command) == "" {
		return true, ""
	}
	if batchMode {
		if ui != nil {
			ui.Emit(UIEvent{Kind: EventBatchAuto, Message: "Batch 模式已启用：子 Agent 命令自动批准"})
		}
		return true, ""
	}

	risk, reason := security.CheckRisk(action.Command)
	action.RiskLevel = risk
	action.Reason = reason
	if risk != "high" {
		if ui != nil {
			ui.Emit(UIEvent{Kind: EventRiskAuto, Message: "子 Agent 风险: 低 -> 自动执行"})
		}
		return true, ""
	}

	if security.CanReviewHighRiskWithAI(action.Command, reason) {
		if ui != nil {
			ui.Emit(UIEvent{Kind: EventInfo, Message: "子 Agent 规则判高，正在进行 AI 风险复核..."})
		}
		if reviewer == nil {
			reviewer = reviewCommandRiskWithAI
		}
		if reviewedRisk, reviewedReason, ok := reviewer(sysCtx, action.Command, reason); ok {
			action.RiskLevel = reviewedRisk
			action.Reason = reviewedReason
			if reviewedRisk == "low" {
				if ui != nil {
					ui.Emit(UIEvent{Kind: EventRiskAuto, Message: "子 Agent AI 复核: 低风险 -> 自动执行 (" + reviewedReason + ")"})
				}
				return true, ""
			}
		}
	}

	if confirmFn != nil && confirmFn(action) {
		security.RecordApproval(action.Command)
		return true, ""
	}
	if ui != nil {
		ui.Emit(UIEvent{Kind: EventDenied, Message: "子 Agent 高危命令未获授权"})
	}
	return false, fmt.Sprintf("用户未批准子 Agent 高危命令: %s。请改用只读、低风险方式继续。", action.Command)
}

// RunSubAgentLoop 便捷入口
func RunSubAgentLoop(parent *DeepAgent, spec subagent.Spec, taskPrompt string, sysCtx collector.SystemContext, batchMode bool) (string, error) {
	return makeSubAgentRunner(parent).Run(spec, taskPrompt, sysCtx, batchMode)
}

// RunSubAgentLoopWithUI 将子 Agent 内部步骤透传给父级 UI。
func RunSubAgentLoopWithUI(parent *DeepAgent, spec subagent.Spec, taskPrompt string, sysCtx collector.SystemContext, batchMode bool, ui UISink, confirmFn func(*AgentAction) bool, maxStepsCap, taskMaxSteps int) (string, error) {
	r := makeSubAgentRunner(parent)
	r.UI = ui
	r.ConfirmFn = confirmFn
	r.MaxStepsCap = maxStepsCap
	r.TaskMaxSteps = taskMaxSteps
	return r.Run(spec, taskPrompt, sysCtx, batchMode)
}

func RunSubAgentLoopForTarget(parent *DeepAgent, spec subagent.Spec, taskPrompt string, sysCtx collector.SystemContext, batchMode bool, ui UISink, confirmFn func(*AgentAction) bool, maxStepsCap, taskMaxSteps int, target config.TargetConfig) (string, error) {
	ex, err := executor.NewEphemeralExecutor(target)
	if err != nil {
		return "", err
	}
	defer ex.Close()
	r := makeSubAgentRunner(parent)
	r.UI = ui
	r.ConfirmFn = confirmFn
	r.MaxStepsCap = maxStepsCap
	r.TaskMaxSteps = taskMaxSteps
	r.Executor = ex
	r.Target = target
	return r.Run(spec, taskPrompt, sysCtx, batchMode)
}

func firstExecutor(ex executor.Executor) executor.Executor {
	if ex != nil {
		return ex
	}
	return executor.Current
}

func isEmptyAction(action AgentAction) bool {
	if action.Type != "" {
		return false
	}
	if action.Command != "" || action.ToolName != "" {
		return false
	}
	if action.Path != "" || action.TaskName != "" || action.SkillName != "" {
		return false
	}
	if action.MemoryKey != "" || len(action.Todos) > 0 {
		return false
	}
	if action.Question != "" {
		return false
	}
	return !action.IsFinished
}
