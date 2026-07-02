package harness

import (
	"ai-edr/internal/config"
	"ai-edr/internal/executor"
	"ai-edr/internal/harness/subagent"
	"ai-edr/internal/mcp"
	"ai-edr/internal/memory"
	"ai-edr/internal/skills"
	"ai-edr/internal/tools"
	"ai-edr/internal/ui"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MemoryMiddleware 跨会话记忆（对标 deepagents MemoryMiddleware）
type MemoryMiddleware struct {
	Store *memory.Store
}

func NewMemoryMiddleware(store *memory.Store) *MemoryMiddleware {
	return &MemoryMiddleware{Store: store}
}

func (m *MemoryMiddleware) Name() string { return "MemoryMiddleware" }

func (m *MemoryMiddleware) EnhancePrompt(base string, _ *AgentState) string {
	if m.Store == nil {
		return base
	}
	return base + m.Store.FormatPrompt()
}

func (m *MemoryMiddleware) HandleAction(_ *StepContext, action *AgentAction) (*ActionResult, bool, error) {
	if m.Store == nil {
		return nil, false, nil
	}

	switch action.Type {
	case ActionRemember:
		return m.remember(action)
	case ActionForget:
		return m.forget(action)
	default:
		return nil, false, nil
	}
}

func (m *MemoryMiddleware) remember(action *AgentAction) (*ActionResult, bool, error) {
	key := strings.TrimSpace(action.MemoryKey)
	value := strings.TrimSpace(action.MemoryValue)
	if key == "" {
		return &ActionResult{Output: "memory_key 不能为空", SkipApproval: true}, true, nil
	}
	if value == "" {
		return &ActionResult{Output: "memory_value 不能为空", SkipApproval: true}, true, nil
	}

	scope := strings.ToLower(strings.TrimSpace(action.MemoryScope))
	var err error
	if scope == "global" {
		err = m.Store.SetGlobal(key, value, "agent")
	} else {
		err = m.Store.Set(key, value, "agent")
	}
	if err != nil {
		return &ActionResult{Output: fmt.Sprintf("保存失败: %v", err), SkipApproval: true}, true, err
	}

	scopeLabel := "当前目标"
	if scope == "global" {
		scopeLabel = "全局"
	}
	return &ActionResult{
		Output:       fmt.Sprintf("%s已保存记忆 [%s] %s = %s", ui.Prefix("✅", "[OK]"), scopeLabel, key, truncateMem(value, 80)),
		SkipApproval: true,
	}, true, nil
}

func (m *MemoryMiddleware) forget(action *AgentAction) (*ActionResult, bool, error) {
	key := strings.TrimSpace(action.MemoryKey)
	if key == "" {
		return &ActionResult{Output: "memory_key 不能为空", SkipApproval: true}, true, nil
	}

	scope := strings.ToLower(strings.TrimSpace(action.MemoryScope))
	var err error
	if scope == "global" {
		err = m.Store.DeleteGlobal(key)
	} else {
		err = m.Store.Delete(key)
	}
	if err != nil {
		return &ActionResult{Output: fmt.Sprintf("删除失败: %v", err), SkipApproval: true}, true, nil
	}

	return &ActionResult{
		Output:       fmt.Sprintf("%s已删除记忆: %s", ui.Prefix("✅", "[OK]"), key),
		SkipApproval: true,
	}, true, nil
}

func truncateMem(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// SkillsMiddleware 按需加载 Skill（对标 deepagents SkillsMiddleware）
type SkillsMiddleware struct {
	Catalog *skills.SkillCatalog
}

func NewSkillsMiddleware(catalog *skills.SkillCatalog) *SkillsMiddleware {
	return &SkillsMiddleware{Catalog: catalog}
}

func (m *SkillsMiddleware) Name() string { return "SkillsMiddleware" }

func (m *SkillsMiddleware) EnhancePrompt(base string, state *AgentState) string {
	if m.Catalog == nil {
		return base
	}
	prompt := base + m.Catalog.FormatCatalogPrompt()

	if len(state.LoadedSkills) > 0 {
		prompt += "\n【已加载 Skills】\n"
		for name, content := range state.LoadedSkills {
			prompt += fmt.Sprintf("\n--- Skill: %s ---\n%s\n", name, content)
		}
	}
	return prompt
}

func (m *SkillsMiddleware) HandleAction(ctx *StepContext, action *AgentAction) (*ActionResult, bool, error) {
	if action.Type != ActionLoadSkill {
		return nil, false, nil
	}

	if m.Catalog == nil {
		return &ActionResult{Output: "Skill 目录未初始化", SkipApproval: true}, true, nil
	}

	meta, found := m.Catalog.FindSkill(action.SkillName)
	if !found {
		return &ActionResult{Output: fmt.Sprintf("未找到 Skill: %s", action.SkillName), SkipApproval: true}, true, nil
	}

	if _, loaded := ctx.State.LoadedSkills[action.SkillName]; loaded {
		return &ActionResult{Output: fmt.Sprintf("Skill [%s] 已加载", action.SkillName), SkipApproval: true}, true, nil
	}

	content, err := skills.LoadSkillContent(*meta)
	if err != nil {
		return &ActionResult{Output: err.Error(), SkipApproval: true}, true, err
	}

	ctx.State.LoadedSkills[action.SkillName] = content
	return &ActionResult{
		Output:       fmt.Sprintf("%s已加载 Skill [%s] (%d 字符)", ui.Prefix("✅", "[OK]"), action.SkillName, len(content)),
		SkipApproval: true,
	}, true, nil
}

// ToolsMiddleware 内置场景工具（网络/应急）+ MCP
type ToolsMiddleware struct{}

func NewToolsMiddleware() *ToolsMiddleware { return &ToolsMiddleware{} }

func (m *ToolsMiddleware) Name() string { return "ToolsMiddleware" }

func (m *ToolsMiddleware) EnhancePrompt(base string, _ *AgentState) string {
	return base + tools.FormatCatalogPrompt() + mcp.Global().FormatPrompt()
}

func (m *ToolsMiddleware) HandleAction(ctx *StepContext, action *AgentAction) (*ActionResult, bool, error) {
	if action.Type != ActionTool {
		return nil, false, nil
	}

	name := strings.TrimSpace(action.ToolName)
	if name == "" {
		return &ActionResult{Output: "tool_name 不能为空", SkipApproval: true}, true, nil
	}
	if name == "tool_catalog" {
		category := action.ToolArgs["category"]
		if category == "" {
			category = "all"
		}
		return &ActionResult{
			Output:       tools.FormatCatalogDetail(category, action.ToolArgs["query"]),
			SkipApproval: true,
		}, true, nil
	}
	if name == "fleet_exec" {
		return m.fleetExec(ctx, action), true, nil
	}

	// MCP 工具: tool_name 为 mcp:xxx 或直接匹配 MCP 注册名
	if strings.HasPrefix(name, "mcp:") {
		name = strings.TrimPrefix(name, "mcp:")
	}
	if _, handler, ok := mcp.Global().Get(name); ok && handler != nil {
		out, err := mcp.Global().Run(name, action.ToolArgs)
		if err != nil {
			return &ActionResult{Output: fmt.Sprintf("MCP 工具 [%s] 失败: %v", name, err), SkipApproval: true}, true, err
		}
		return &ActionResult{
			Output:       fmt.Sprintf("【MCP 工具 %s 结果】\n%s", name, out),
			SkipApproval: true,
		}, true, nil
	}

	isWindows := strings.Contains(strings.ToLower(ctx.SysCtx.OS), "windows")
	out, risk, err := tools.RunWithExecutor(name, action.ToolArgs, isWindows, ctx.Executor)
	if err != nil {
		return &ActionResult{
			Output:       fmt.Sprintf("工具 [%s] 执行失败: %v\n%s", name, err, out),
			SkipApproval: true,
		}, true, err
	}

	persLabel := "目标机"
	if t, ok := tools.Get(name); ok && t.Perspective == tools.PerspectiveController {
		persLabel = "控制端"
	}
	skip := risk == tools.RiskLow
	return &ActionResult{
		Output:       fmt.Sprintf("【工具 %s | 视角:%s 结果】\n%s", name, persLabel, out),
		SkipApproval: skip,
	}, true, nil
}

func (m *ToolsMiddleware) fleetExec(ctx *StepContext, action *AgentAction) *ActionResult {
	selector := firstToolArg(action.ToolArgs, "selector", "target", "targets")
	command := firstToolArg(action.ToolArgs, "command", "cmd")
	if strings.TrimSpace(command) == "" {
		return &ActionResult{Output: "fleet_exec command 必填", SkipApproval: true}
	}
	concurrency := 5
	if raw := firstToolArg(action.ToolArgs, "concurrency"); raw != "" {
		fmt.Sscanf(raw, "%d", &concurrency)
	}
	results := executor.RunFleetWithProgress(config.GlobalConfig.Targets, selector, command, concurrency, func(p executor.FleetProgress) {
		status := p.Status
		detail := p.Error
		if detail == "" {
			detail = truncate(p.Output, 160)
		}
		emitTargetStatus(ctx.UI, status, "fleet_exec "+command, p.Target, detail)
	})
	var b strings.Builder
	b.WriteString(fmt.Sprintf("【工具 fleet_exec | 视角:控制端 结果】\nFleet Exec selector=%s command=%s\n", emptyDefault(selector, "all"), command))
	b.WriteString(executor.FormatFleetResults(results))
	return &ActionResult{Output: b.String(), SkipApproval: false}
}

func firstToolArg(args map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(args[k]); v != "" {
			return v
		}
	}
	return ""
}

func emptyDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// SubAgentMiddleware 子 Agent 委派（对标 deepagents SubAgentMiddleware）
type SubAgentMiddleware struct {
	Parent *DeepAgent
}

func NewSubAgentMiddleware() *SubAgentMiddleware { return &SubAgentMiddleware{} }

func (m *SubAgentMiddleware) SetParent(a *DeepAgent) { m.Parent = a }

func (m *SubAgentMiddleware) Name() string { return "SubAgentMiddleware" }

func (m *SubAgentMiddleware) EnhancePrompt(base string, _ *AgentState) string {
	return base + subagent.FormatRegistryPrompt()
}

func (m *SubAgentMiddleware) HandleAction(ctx *StepContext, action *AgentAction) (*ActionResult, bool, error) {
	if action.Type != ActionTask {
		return nil, false, nil
	}

	trimSubAgentAction(action)
	if len(action.ParallelTasks) > 0 {
		return m.runParallelSubAgents(ctx, action)
	}

	if msg := validateSingleSubAgentTask(action.TaskName, action.TaskPrompt); msg != "" {
		return &ActionResult{Output: msg, SkipApproval: true}, true, nil
	}

	spec, found := subagent.Find(action.TaskName)
	if !found {
		return &ActionResult{
			Output:       fmt.Sprintf("未知子 Agent: %s。可用: log-analyst, vuln-scanner, webshell-hunter, network-analyst, general-purpose", action.TaskName),
			SkipApproval: true,
		}, true, nil
	}

	if ctx.UI != nil {
		ctx.UI.Emit(UIEvent{Kind: EventSubAgentStart, Message: spec.Name, Detail: action.TaskPrompt, TargetName: action.TargetName, TargetProtocol: action.TargetProtocol, TargetHost: action.TargetHost})
	} else {
		fmt.Printf("%s委派子 Agent [%s]: %s\n", ui.Prefix("🔀", "[SUB]"), spec.Name, mwTruncate(action.TaskPrompt, 80))
	}

	if m.Parent == nil {
		return &ActionResult{Output: "子 Agent harness 未初始化", SkipApproval: true}, true, nil
	}

	if strings.TrimSpace(action.TargetSelector) != "" {
		return m.runTargetSubAgents(ctx, *spec, action)
	}
	result, err := RunSubAgentLoopWithUI(m.Parent, *spec, action.TaskPrompt, ctx.SysCtx, ctx.BatchMode, ctx.UI, ctx.ConfirmFn, ctx.SubAgentMaxSteps, action.TaskMaxSteps)
	if err != nil {
		return &ActionResult{Output: fmt.Sprintf("子 Agent 失败: %v", err), SkipApproval: true}, true, err
	}

	if ctx.UI != nil {
		ctx.UI.Emit(UIEvent{Kind: EventSubAgentResult, Message: spec.Name, Detail: result})
	}

	return &ActionResult{
		Output:       fmt.Sprintf("【子 Agent %s 结果】\n%s", spec.Name, result),
		SkipApproval: true,
	}, true, nil
}

func (m *SubAgentMiddleware) runParallelSubAgents(ctx *StepContext, action *AgentAction) (*ActionResult, bool, error) {
	if m.Parent == nil {
		return &ActionResult{Output: "子 Agent harness 未初始化", SkipApproval: true}, true, nil
	}

	type parallelResult struct {
		idx  int
		task SubAgentTaskAction
		out  string
		err  error
		dur  time.Duration
	}
	tasks := normalizeParallelTasks(action)
	if len(tasks) == 0 {
		return &ActionResult{Output: "parallel_tasks 为空，请提供至少 1 个子 Agent 任务。", SkipApproval: true}, true, nil
	}
	if msg := validateParallelSubAgentTasks(tasks); msg != "" {
		return &ActionResult{Output: msg, SkipApproval: true}, true, nil
	}

	concurrency := 3
	if len(tasks) < concurrency {
		concurrency = len(tasks)
	}
	results := make([]parallelResult, len(tasks))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for i, task := range tasks {
		i, task := i, task
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			spec, found := subagent.Find(task.TaskName)
			if !found {
				results[i] = parallelResult{idx: i, task: task, err: fmt.Errorf("未知子 Agent: %s", task.TaskName), dur: time.Since(start)}
				return
			}
			if ctx.UI != nil {
				ctx.UI.Emit(UIEvent{Kind: EventSubAgentStart, Message: spec.Name + " 并行", Detail: task.TaskPrompt})
			}
			var out string
			var err error
			if strings.TrimSpace(task.TargetSelector) != "" {
				subAction := &AgentAction{
					TaskName:       task.TaskName,
					TaskPrompt:     task.TaskPrompt,
					TargetSelector: task.TargetSelector,
					TaskMaxSteps:   task.TaskMaxSteps,
				}
				result, _, runErr := m.runTargetSubAgents(ctx, *spec, subAction)
				if result != nil {
					out = result.Output
				}
				err = runErr
			} else {
				out, err = RunSubAgentLoopWithUI(m.Parent, *spec, task.TaskPrompt, ctx.SysCtx, ctx.BatchMode, ctx.UI, ctx.ConfirmFn, ctx.SubAgentMaxSteps, task.TaskMaxSteps)
			}
			results[i] = parallelResult{idx: i, task: task, out: out, err: err, dur: time.Since(start)}
			if ctx.UI != nil {
				status := "完成"
				if err != nil {
					status = "失败"
				}
				ctx.UI.Emit(UIEvent{Kind: EventSubAgentResult, Message: spec.Name + " " + status, Detail: out})
			}
		}()
	}
	wg.Wait()

	var b strings.Builder
	b.WriteString(fmt.Sprintf("【并行子 Agent 协作结果】共 %d 个任务，并发 %d，用户步数上限 %d\n\n", len(tasks), concurrency, subAgentCap(ctx.SubAgentMaxSteps)))
	for _, r := range results {
		name := firstNonEmpty(r.task.TaskName, fmt.Sprintf("task-%d", r.idx+1))
		b.WriteString(fmt.Sprintf("## [%d] %s (%s)\n", r.idx+1, name, r.dur.Round(time.Millisecond)))
		if r.err != nil {
			b.WriteString(fmt.Sprintf("状态: 失败\n错误: %v\n\n", r.err))
			continue
		}
		b.WriteString("状态: 完成\n")
		b.WriteString(strings.TrimSpace(r.out))
		b.WriteString("\n\n")
	}
	b.WriteString("协作提示: 请主 Agent 综合以上子 Agent 输出，合并证据链、去重结论、标记冲突点后继续下一步。\n")
	return &ActionResult{Output: b.String(), SkipApproval: true}, true, nil
}

func normalizeParallelTasks(action *AgentAction) []SubAgentTaskAction {
	tasks := make([]SubAgentTaskAction, 0, len(action.ParallelTasks)+1)
	for _, task := range action.ParallelTasks {
		task.TaskName = strings.TrimSpace(task.TaskName)
		task.TaskPrompt = strings.TrimSpace(task.TaskPrompt)
		task.TargetSelector = strings.TrimSpace(task.TargetSelector)
		if strings.TrimSpace(task.TaskName) == "" && strings.TrimSpace(task.TaskPrompt) == "" {
			continue
		}
		tasks = append(tasks, task)
	}
	if len(tasks) == 0 && (strings.TrimSpace(action.TaskName) != "" || strings.TrimSpace(action.TaskPrompt) != "") {
		tasks = append(tasks, SubAgentTaskAction{
			TaskName:       action.TaskName,
			TaskPrompt:     action.TaskPrompt,
			TargetSelector: action.TargetSelector,
			TaskMaxSteps:   action.TaskMaxSteps,
		})
	}
	return tasks
}

func trimSubAgentAction(action *AgentAction) {
	action.TaskName = strings.TrimSpace(action.TaskName)
	action.TaskPrompt = strings.TrimSpace(action.TaskPrompt)
	action.TargetSelector = strings.TrimSpace(action.TargetSelector)
}

func validateSingleSubAgentTask(taskName, taskPrompt string) string {
	if strings.TrimSpace(taskName) == "" {
		return subAgentTaskFormatError("task_name 为空")
	}
	if strings.TrimSpace(taskPrompt) == "" {
		return subAgentTaskFormatError("task_prompt 为空")
	}
	return ""
}

func validateParallelSubAgentTasks(tasks []SubAgentTaskAction) string {
	for i, task := range tasks {
		switch {
		case strings.TrimSpace(task.TaskName) == "":
			return subAgentTaskFormatError(fmt.Sprintf("parallel_tasks[%d].task_name 为空", i))
		case strings.TrimSpace(task.TaskPrompt) == "":
			return subAgentTaskFormatError(fmt.Sprintf("parallel_tasks[%d].task_prompt 为空", i))
		}
	}
	return ""
}

func subAgentTaskFormatError(reason string) string {
	return fmt.Sprintf(`子 Agent 委派参数不完整: %s。
请重新输出合法 action，例如:
{"action":"task","task_name":"log-analyst","task_prompt":"审计今天的登录日志，提取异常登录、失败来源 IP 和证据链","task_max_steps":18}
或:
{"action":"task","parallel_tasks":[{"task_name":"log-analyst","task_prompt":"审计 target-01 今天的登录日志","target_selector":"target-01","task_max_steps":18},{"task_name":"log-analyst","task_prompt":"审计 target-02 今天的登录日志","target_selector":"target-02","task_max_steps":18}]}
可用子 Agent: log-analyst, vuln-scanner, webshell-hunter, network-analyst, general-purpose, ctf-solver, awd-defender, awd-plus-operator`, reason)
}

func subAgentCap(cap int) int {
	if cap <= 0 {
		return 15
	}
	return cap
}

func (m *SubAgentMiddleware) runTargetSubAgents(ctx *StepContext, spec subagent.Spec, action *AgentAction) (*ActionResult, bool, error) {
	targets := executor.MatchTargets(config.GlobalConfig.Targets, action.TargetSelector)
	if len(targets) == 0 {
		return &ActionResult{
			Output:       fmt.Sprintf("target_selector=%s 无匹配目标，请先使用 fleet_inventory 查看 targets。", action.TargetSelector),
			SkipApproval: true,
		}, true, nil
	}

	concurrency := 3
	if len(targets) < concurrency {
		concurrency = len(targets)
	}
	type targetResult struct {
		target config.TargetConfig
		out    string
		err    error
		dur    time.Duration
	}
	results := make([]targetResult, 0, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			emitTargetStatus(ctx.UI, "running", "子 Agent 处理中", target, "")
			prompt := fmt.Sprintf("%s\n\n【目标限定】name=%s protocol=%s host=%s user=%s",
				action.TaskPrompt, target.Name, target.Protocol, target.Host, target.User)
			out, err := RunSubAgentLoopForTarget(m.Parent, spec, prompt, ctx.SysCtx, ctx.BatchMode, ctx.UI, ctx.ConfirmFn, ctx.SubAgentMaxSteps, action.TaskMaxSteps, target)
			status := "ok"
			detail := time.Since(start).Round(time.Millisecond).String()
			if err != nil {
				status = "error"
				detail = err.Error()
			}
			emitTargetStatus(ctx.UI, status, "子 Agent 完成", target, detail)
			mu.Lock()
			results = append(results, targetResult{target: target, out: out, err: err, dur: time.Since(start)})
			mu.Unlock()
		}()
	}
	wg.Wait()

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Target-aware 子 Agent [%s] 完成: %d 个目标\n\n", spec.Name, len(results)))
	for _, r := range results {
		name := executor.TargetDisplayName(r.target)
		if r.err != nil {
			b.WriteString(fmt.Sprintf("[ERR] %s (%s %s) %s\nerror: %v\n\n", name, r.target.Protocol, r.target.Host, r.dur.Round(time.Millisecond), r.err))
			continue
		}
		b.WriteString(fmt.Sprintf("[OK] %s (%s %s) %s\n%s\n\n", name, r.target.Protocol, r.target.Host, r.dur.Round(time.Millisecond), truncate(r.out, 3000)))
	}
	return &ActionResult{
		Output:       b.String(),
		SkipApproval: true,
	}, true, nil
}

func emitTargetStatus(ui UISink, status, msg string, target config.TargetConfig, detail string) {
	if ui == nil {
		return
	}
	ui.Emit(UIEvent{
		Kind:           EventTargetStatus,
		Status:         status,
		Message:        msg,
		Detail:         detail,
		TargetName:     target.Name,
		TargetProtocol: target.Protocol,
		TargetHost:     target.Host,
	})
}

// TodoMiddleware 任务规划（对标 deepagents TodoListMiddleware）
type TodoMiddleware struct{}

func NewTodoMiddleware() *TodoMiddleware { return &TodoMiddleware{} }

func (m *TodoMiddleware) Name() string { return "TodoMiddleware" }

func (m *TodoMiddleware) EnhancePrompt(base string, state *AgentState) string {
	if len(state.Todos) == 0 {
		prompt := base + "\n【任务规划】\n"
		prompt += "对于复杂任务，先用 action=\"todo\" 创建任务清单，再逐步执行。\n"
		prompt += "格式: {\"action\": \"todo\", \"todos\": [{\"id\":\"1\",\"content\":\"...\",\"status\":\"pending\"}]}\n"
		return prompt
	}

	var b strings.Builder
	b.WriteString(base)
	b.WriteString("\n【当前任务清单】\n")
	for _, t := range state.Todos {
		b.WriteString(fmt.Sprintf("%s [%s] %s\n", todoStatusIcon(t.Status), t.ID, t.Content))
	}
	return b.String()
}

func (m *TodoMiddleware) HandleAction(ctx *StepContext, action *AgentAction) (*ActionResult, bool, error) {
	if action.Type != ActionTodo {
		return nil, false, nil
	}

	ctx.State.Todos = action.Todos
	return &ActionResult{
		Output:       FormatTodoList(action.Todos),
		SkipApproval: true,
	}, true, nil
}

// FilesystemMiddleware 文件系统工具（对标 deepagents FilesystemMiddleware）
type FilesystemMiddleware struct {
	MemoryStore *memory.Store
}

func NewFilesystemMiddleware(store *memory.Store) *FilesystemMiddleware {
	return &FilesystemMiddleware{MemoryStore: store}
}

func (m *FilesystemMiddleware) Name() string { return "FilesystemMiddleware" }

func (m *FilesystemMiddleware) EnhancePrompt(base string, _ *AgentState) string {
	return base + `
【文件系统工具 — 读写与精确编辑】
- read_file + path: 读取文件（目标机 SFTP 或控制端 workspace/AGENTS.md）
- write_file + path + content: 写入（需确认；AGENTS.md 写回会热更新记忆）
- edit_file + path + old_string + new_string: 增量编辑（需确认）
- glob + path + glob_pattern: 文件名搜索
- grep + path + pattern: Go 原生搜索（不依赖 grep 命令）
- ls + path: 列出目录
远程排查时 read_file/grep/ls 读的是**目标机**；~/.deepsentry/workspace 读的是**控制端**。
脚本创建/调试默认优先原生 Shell；当需要读取大文件片段、SFTP 精确写入、AGENTS.md 记忆写回或避免目标缺少 grep/ls 时再使用这些文件工具。`
}

func (m *FilesystemMiddleware) HandleAction(ctx *StepContext, action *AgentAction) (*ActionResult, bool, error) {
	switch action.Type {
	case ActionReadFile:
		return m.readFile(ctx, action.Path)
	case ActionWriteFile:
		return m.writeFile(ctx, action.Path, action.Content)
	case ActionEditFile:
		return m.editFile(ctx, action.Path, action.OldString, action.NewString, action.ReplaceAll)
	case ActionGlob:
		return m.glob(action.Path, action.GlobPattern)
	case ActionGrep:
		return m.grep(ctx, action.Path, action.Pattern)
	case ActionLS:
		return m.ls(ctx, action.Path)
	default:
		return nil, false, nil
	}
}

func (m *FilesystemMiddleware) readFile(ctx *StepContext, path string) (*ActionResult, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &ActionResult{Output: "path 不能为空", SkipApproval: true}, true, nil
	}
	if isProtectedPath(path) {
		return &ActionResult{Output: "禁止读取受保护路径", SkipApproval: true}, true, nil
	}

	local := isControllerLocalPath(path)
	data, err := readTargetOrLocalWithExecutor(path, ctx.Executor)
	if err != nil {
		return &ActionResult{Output: fmt.Sprintf("读取失败: %v", err), SkipApproval: true}, true, nil
	}

	content := truncateContent(string(data), len(data))
	pers := fsPerspectiveForExecutor(local, ctx.Executor)
	return &ActionResult{Output: formatFSResult(pers, content), SkipApproval: true}, true, nil
}

func (m *FilesystemMiddleware) writeFile(ctx *StepContext, path, content string) (*ActionResult, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &ActionResult{Output: "path 不能为空", SkipApproval: true}, true, nil
	}
	if isProtectedPath(path) && !memory.IsAgentsMDPath(path) {
		return &ActionResult{Output: "禁止写入受保护路径", SkipApproval: true}, true, nil
	}

	if err := writeTargetOrLocalWithExecutor(path, []byte(content), ctx.Executor); err != nil {
		return &ActionResult{Output: fmt.Sprintf("写入失败: %v", err), SkipApproval: true}, true, err
	}

	maybeReloadAgentsMD(m.MemoryStore, path, []byte(content))
	pers := fsPerspectiveForExecutor(isControllerLocalPath(path), ctx.Executor)
	return &ActionResult{
		Output:       formatFSResult(pers, fmt.Sprintf("%s已写入 %s (%d 字节)", ui.Prefix("✅", "[OK]"), path, len(content))),
		SkipApproval: false,
	}, true, nil
}

func (m *FilesystemMiddleware) editFile(ctx *StepContext, path, oldStr, newStr string, replaceAll bool) (*ActionResult, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &ActionResult{Output: "path 不能为空", SkipApproval: true}, true, nil
	}
	if isProtectedPath(path) && !memory.IsAgentsMDPath(path) {
		return &ActionResult{Output: "禁止编辑受保护路径", SkipApproval: true}, true, nil
	}

	msg, err := editFileContentWithExecutor(path, oldStr, newStr, replaceAll, ctx.Executor)
	if err != nil {
		return &ActionResult{Output: err.Error(), SkipApproval: true}, true, nil
	}

	data, _ := readTargetOrLocalWithExecutor(path, ctx.Executor)
	maybeReloadAgentsMD(m.MemoryStore, path, data)
	pers := fsPerspectiveForExecutor(isControllerLocalPath(path), ctx.Executor)
	return &ActionResult{Output: formatFSResult(pers, msg), SkipApproval: false}, true, nil
}

func (m *FilesystemMiddleware) glob(root, pattern string) (*ActionResult, bool, error) {
	if pattern == "" {
		return &ActionResult{Output: "glob_pattern 不能为空", SkipApproval: true}, true, nil
	}
	matches, err := executor.GlobTarget(root, pattern, 200)
	if err != nil {
		return &ActionResult{Output: fmt.Sprintf("glob 失败: %v", err), SkipApproval: true}, true, nil
	}
	if len(matches) == 0 {
		return &ActionResult{Output: "(无匹配)", SkipApproval: true}, true, nil
	}
	local := isControllerLocalPath(root)
	return &ActionResult{
		Output:       formatFSResult(fsPerspective(local), strings.Join(matches, "\n")),
		SkipApproval: true,
	}, true, nil
}

func (m *FilesystemMiddleware) grep(ctx *StepContext, path, pattern string) (*ActionResult, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" || pattern == "" {
		return &ActionResult{Output: "path 和 pattern 不能为空", SkipApproval: true}, true, nil
	}
	if isProtectedPath(path) {
		return &ActionResult{Output: "禁止搜索受保护路径", SkipApproval: true}, true, nil
	}

	local := isControllerLocalPath(path)
	var output string
	var err error
	if local {
		data, rerr := executor.ReadLocalFile(expandUserPath(path))
		if rerr != nil {
			return &ActionResult{Output: fmt.Sprintf("grep 失败: %v", rerr), SkipApproval: true}, true, nil
		}
		output, err = grepLocalContent(string(data), pattern, 100)
	} else {
		output, err = executor.GrepFileWithExecutor(ctx.Executor, path, pattern, 100)
	}
	if err != nil {
		return &ActionResult{Output: fmt.Sprintf("grep 失败: %v", err), SkipApproval: true}, true, nil
	}
	return &ActionResult{Output: formatFSResult(fsPerspectiveForExecutor(local, ctx.Executor), output), SkipApproval: true}, true, nil
}

func grepLocalContent(content, pattern string, maxLines int) (string, error) {
	var matches []string
	for i, line := range strings.Split(content, "\n") {
		if strings.Contains(line, pattern) {
			matches = append(matches, fmt.Sprintf("%d:%s", i+1, line))
			if len(matches) >= maxLines {
				break
			}
		}
	}
	if len(matches) == 0 {
		return "(无匹配)", nil
	}
	return strings.Join(matches, "\n"), nil
}

func (m *FilesystemMiddleware) ls(ctx *StepContext, path string) (*ActionResult, bool, error) {
	if path == "" {
		path = "."
	}
	local := isControllerLocalPath(path)
	var output string
	if local {
		entries, err := os.ReadDir(expandUserPath(path))
		if err != nil {
			return &ActionResult{Output: fmt.Sprintf("ls 失败: %v", err), SkipApproval: true}, true, nil
		}
		var des []executor.DirEntry
		for _, e := range entries {
			info, _ := e.Info()
			de := executor.DirEntry{Name: e.Name(), IsDir: e.IsDir()}
			if info != nil {
				de.Size = info.Size()
			}
			des = append(des, de)
		}
		output = formatDirListing(path, des)
	} else {
		entries, err := executor.ReadEntriesWithExecutor(ctx.Executor, path)
		if err != nil {
			return &ActionResult{Output: fmt.Sprintf("ls 失败: %v", err), SkipApproval: true}, true, nil
		}
		output = formatDirListing(path, entries)
	}
	return &ActionResult{Output: formatFSResult(fsPerspectiveForExecutor(local, ctx.Executor), output), SkipApproval: true}, true, nil
}

// ContextMiddleware 上下文管理（对标 deepagents SummarizationMiddleware）
type ContextMiddleware struct {
	OutputThreshold int
}

func NewContextMiddleware() *ContextMiddleware {
	return &ContextMiddleware{OutputThreshold: 8000}
}

func (m *ContextMiddleware) Name() string { return "ContextMiddleware" }

func (m *ContextMiddleware) EnhancePrompt(base string, _ *AgentState) string {
	return base
}

func (m *ContextMiddleware) HandleAction(_ *StepContext, _ *AgentAction) (*ActionResult, bool, error) {
	return nil, false, nil
}

// OffloadOutput 将超大工具输出卸载到 workspace 文件
func (m *ContextMiddleware) OffloadOutput(state *AgentState, label, output string) string {
	if len(output) <= m.OutputThreshold {
		return output
	}

	if state.WorkspaceDir == "" {
		return output[:m.OutputThreshold] + "\n...(输出过长已截断)..."
	}

	outputDir := sessionOutputDir(state)
	_ = os.MkdirAll(outputDir, 0755)
	filename := fmt.Sprintf("output_%s.txt", label)
	fullPath := filepath.Join(outputDir, filename)

	if err := os.WriteFile(fullPath, []byte(output), 0644); err != nil {
		return output[:m.OutputThreshold] + "\n...(输出过长已截断)..."
	}

	previewLen := 500
	if len(output) < previewLen {
		previewLen = len(output)
	}
	preview := output[:previewLen]
	absPath, _ := filepath.Abs(fullPath)
	return fmt.Sprintf("%s\n\n...(完整输出 %d 字节已保存至 %s，可用 read_file 查看)...",
		preview, len(output), absPath)
}

func sessionOutputDir(state *AgentState) string {
	if state == nil || strings.TrimSpace(state.WorkspaceDir) == "" {
		return ""
	}
	sessionID := sanitizeSessionID(state.SessionID)
	if sessionID == "" {
		return state.WorkspaceDir
	}
	return filepath.Join(state.WorkspaceDir, "sessions", sessionID)
}

func sanitizeSessionID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '_' || r == '-' || r == '.':
			return r
		default:
			return '_'
		}
	}, id)
}

func isProtectedPath(path string) bool {
	path = expandUserPath(path)
	if memory.IsAgentsMDPath(path) {
		return false
	}
	// workspace 为控制端可读写区域，不应被 deepsentry 关键字误伤
	if isControllerLocalPath(path) {
		return false
	}
	protected := []string{"config.yaml", "reports/"}
	lower := strings.ToLower(path)
	for _, p := range protected {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	// 精确拦截 ~/.deepsentry/config.yaml，而非整个 .deepsentry 目录
	home, _ := os.UserHomeDir()
	cfgCandidates := []string{
		filepath.Join(home, ".deepsentry", "config.yaml"),
		filepath.Join(home, ".deepsentry", "config.yml"),
	}
	if abs, err := filepath.Abs(path); err == nil {
		for _, cfg := range cfgCandidates {
			if cfgAbs, _ := filepath.Abs(cfg); abs == cfgAbs {
				return true
			}
		}
	}
	return false
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func mwTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
