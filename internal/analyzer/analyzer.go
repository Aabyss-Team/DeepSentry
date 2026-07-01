package analyzer

import (
	"ai-edr/internal/collector"
	"ai-edr/internal/config"
	"ai-edr/internal/security"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	Model         string           `json:"model"`
	Messages      []Message        `json:"messages"`
	Stream        bool             `json:"stream"`
	Temperature   float64          `json:"temperature"`
	Tools         []ToolDefinition `json:"tools,omitempty"`
	ToolChoice    interface{}      `json:"tool_choice,omitempty"`
	StreamOptions *StreamOptions   `json:"stream_options,omitempty"`
}

type StreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type ChatResponse struct {
	Choices []struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage TokenUsage `json:"usage"`
}

type AgentResponse struct {
	Thought     string   `json:"thought"`
	Command     string   `json:"command"`
	RiskLevel   string   `json:"risk_level"`
	Reason      string   `json:"reason"`
	IsFinished  bool     `json:"is_finished"`
	FinalReport string   `json:"final_report"`
	Question    string   `json:"question"`
	Options     []string `json:"options"`

	// Deep Agent Harness 扩展字段（对标 deepagents 多工具协议）
	Action         string     `json:"action"`
	TaskName       string     `json:"task_name"`
	TaskPrompt     string     `json:"task_prompt"`
	TaskMaxSteps   int        `json:"task_max_steps"`
	ParallelTasks  []TaskSpec `json:"parallel_tasks"`
	TargetSelector string     `json:"target_selector"`
	TargetName     string     `json:"target_name"`
	TargetProtocol string     `json:"target_protocol"`
	TargetHost     string     `json:"target_host"`
	SkillName      string     `json:"skill_name"`
	Path           string     `json:"path"`
	Content        string     `json:"content"`
	Pattern        string     `json:"pattern"`
	Todos          []TodoItem `json:"todos"`

	// memory
	MemoryKey   string `json:"memory_key"`
	MemoryValue string `json:"memory_value"`
	MemoryScope string `json:"memory_scope"`

	// tool
	ToolName string            `json:"tool_name"`
	ToolArgs map[string]string `json:"tool_args"`

	// edit_file / glob
	OldString   string `json:"old_string"`
	NewString   string `json:"new_string"`
	ReplaceAll  bool   `json:"replace_all"`
	GlobPattern string `json:"glob_pattern"`
}

// TodoItem 任务清单项
type TodoItem struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Status  string `json:"status"`
}

type TaskSpec struct {
	TaskName       string `json:"task_name"`
	TaskPrompt     string `json:"task_prompt"`
	TargetSelector string `json:"target_selector"`
	TaskMaxSteps   int    `json:"task_max_steps"`
}

func (t *TodoItem) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	t.ID = stringifyTodoField(raw["id"])
	t.Content = firstNonEmptyString(
		stringifyTodoField(raw["content"]),
		stringifyTodoField(raw["title"]),
		stringifyTodoField(raw["detail"]),
		stringifyTodoField(raw["description"]),
	)
	if detail := stringifyTodoField(raw["detail"]); detail != "" && t.Content != "" && detail != t.Content {
		t.Content = t.Content + " - " + detail
	}
	t.Status = stringifyTodoField(raw["status"])
	return nil
}

func stringifyTodoField(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	case bool:
		return fmt.Sprintf("%v", x)
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", x))
	}
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// 兼容性结构体：用于解析 AI 可能返回的多种格式
type CompatibilityResponse struct {
	Thought        string                 `json:"thought"`
	Command        string                 `json:"command"`
	RiskLevel      string                 `json:"risk_level"`
	IsFinished     bool                   `json:"is_finished"`
	FinalReport    interface{}            `json:"final_report"`
	Question       string                 `json:"question"`
	Options        []string               `json:"options"`
	CmdArray       []string               `json:"cmd"`
	Explanation    string                 `json:"explanation"`
	Action         string                 `json:"action"`
	TaskName       string                 `json:"task_name"`
	TaskPrompt     string                 `json:"task_prompt"`
	TaskMaxSteps   int                    `json:"task_max_steps"`
	ParallelTasks  []TaskSpec             `json:"parallel_tasks"`
	TargetSelector string                 `json:"target_selector"`
	TargetName     string                 `json:"target_name"`
	TargetProtocol string                 `json:"target_protocol"`
	TargetHost     string                 `json:"target_host"`
	SkillName      string                 `json:"skill_name"`
	Path           string                 `json:"path"`
	Content        string                 `json:"content"`
	Pattern        string                 `json:"pattern"`
	Todos          []TodoItem             `json:"todos"`
	MemoryKey      string                 `json:"memory_key"`
	MemoryValue    string                 `json:"memory_value"`
	MemoryScope    string                 `json:"memory_scope"`
	ToolName       string                 `json:"tool_name"`
	ToolArgs       map[string]interface{} `json:"tool_args"`
	OldString      string                 `json:"old_string"`
	NewString      string                 `json:"new_string"`
	ReplaceAll     bool                   `json:"replace_all"`
	GlobPattern    string                 `json:"glob_pattern"`
}

// StepOptions Agent 单步选项
type StepOptions struct {
	SysCtx         collector.SystemContext
	History        *[]Message
	ExtraPrompt    string
	UseNativeTools bool
	OnStream       func(delta string) // 非 nil 且模型支持时启用 SSE 流式输出
	OnUsage        func(TokenUsage)   // 模型返回真实 usage 时回调
}

// RunAgentStep 执行 Agent 的单步思考
func RunAgentStep(sysCtx collector.SystemContext, history *[]Message) (AgentResponse, error) {
	return RunAgentStepWithPrompt(sysCtx, history, "")
}

// RunAgentStepWithPrompt 支持额外 system prompt 注入（供 Deep Agent Harness 使用）
func RunAgentStepWithPrompt(sysCtx collector.SystemContext, history *[]Message, extraPrompt string) (AgentResponse, error) {
	return RunAgentStepWithOptions(StepOptions{
		SysCtx:         sysCtx,
		History:        history,
		ExtraPrompt:    extraPrompt,
		UseNativeTools: config.GlobalConfig.UseNativeTools,
	})
}

// RunAgentStepWithOptions 完整单步选项
func RunAgentStepWithOptions(opts StepOptions) (AgentResponse, error) {
	sysCtx := opts.SysCtx
	history := opts.History
	extraPrompt := opts.ExtraPrompt

	// 1. 获取基础 System Prompt (来自 collector)
	basePrompt := sysCtx.GenerateSystemPrompt()
	if extraPrompt != "" {
		basePrompt = basePrompt + extraPrompt
	}

	// 增强 Windows 路径操作指南 & JSON 约束
	selfProtectionPrompt := `
【⛔ 核心自我保护守则】
1. 绝对禁止删除/移动 config.yaml, deepsentry.exe, reports/ 目录。

【🪟 Windows 文件操作专家模式】
1. **中文路径与乱码**：如果 'dir' 显示乱码，请使用通配符 (*.pdf) 操作，不要直接复制乱码文件名。
2. **路径变量**：使用 PowerShell 时可直接用 $HOME。

【⚠️ JSON 严格语法】
1. 在 JSON 字符串值中，**双引号 (") 必须转义为 (\\")**。
2. **反斜杠 (\\) 必须转义为 (\\\\)**。
3. **严禁** Markdown 代码块或与 JSON 混排；说明只能放 thought 字段。
4. 响应必须是纯 JSON 对象，以 { 开头、以 } 结尾。
`
	systemPrompt := basePrompt + selfProtectionPrompt

	// Context 自动管理：防止 Token 超限，同时保留前情提要和最近步骤。
	if compacted, err := ManageHistoryContext(history); err != nil {
		TruncateHistoryFallback(history, 8)
	} else if compacted {
		// harness 会在调用前主动提示；这里保持兼容旧调用路径。
	}

	messages := []Message{
		{Role: "system", Content: systemPrompt},
	}
	messages = append(messages, *history...)

	llmResult, err := CallLLMWithRetry(messages, opts.UseNativeTools, opts.OnStream)
	if err != nil {
		return AgentResponse{}, err
	}
	if opts.OnUsage != nil && llmResult.Usage.HasAny() {
		opts.OnUsage(llmResult.Usage)
	}
	rawResp := llmResult.Content
	toolCallArgs := llmResult.ToolCallArgs

	if toolCallArgs != "" {
		resp, perr := ParseToolCallResponse(toolCallArgs)
		if perr == nil {
			return finalizeResponse(resp), nil
		}
		// fallback to JSON content parse
	}

	// 2. 清洗 JSON（支持 Markdown 代码块 + 前置说明文字）
	cleanResp, prose := cleanJSON(rawResp)
	var compat CompatibilityResponse

	// 3. 尝试标准解析
	err = json.Unmarshal([]byte(cleanResp), &compat)

	// 🟢 JSON 解析失败时的智能兜底
	if err != nil {
		fixTry := cleanResp
		if !strings.HasSuffix(strings.TrimSpace(fixTry), "}") {
			fixTry += "}"
		}

		if err2 := json.Unmarshal([]byte(fixTry), &compat); err2 != nil {
			// 再次从原始响应提取 JSON
			if retry, _ := extractJSONPayload(rawResp); retry != "" && retry != cleanResp {
				if err3 := json.Unmarshal([]byte(retry), &compat); err3 == nil {
					err = nil
					cleanResp = retry
				}
			}
		} else {
			err = nil
		}
	}

	if err != nil {
		extractedCmd, found := extractCommandString(cleanResp)
		if !found {
			extractedCmd, found = extractCommandString(rawResp)
		}

		if found && extractedCmd != "" {
			compat.Command = decodeJSONUnicodeEscapes(extractedCmd)
			compat.Thought = "JSON 格式异常(转义错误)，已启用【字符级扫描】精确提取命令。"
			compat.RiskLevel = "high"
			err = nil
		} else {
			if question := extractClarificationQuestion(rawResp); question != "" {
				return AgentResponse{
					Thought:   "需要用户补充信息后继续任务",
					Action:    "ask_user",
					Question:  question,
					RiskLevel: "low",
				}, nil
			}
			return AgentResponse{
				Thought:     "AI 响应格式完全不可读",
				FinalReport: fmt.Sprintf("❌ 解析失败: %v\n原始响应:\n%s", err, rawResp),
				IsFinished:  true,
				RiskLevel:   "low",
			}, nil
		}
	}

	if compat.Thought == "" && prose != "" {
		compat.Thought = normalizeProseThought(prose)
	} else if compat.Thought == "" {
		if p := normalizeProseThought(prose); p != "" {
			compat.Thought = p
		}
	}

	resp := AgentResponse{
		RiskLevel:      compat.RiskLevel,
		IsFinished:     compat.IsFinished,
		Question:       compat.Question,
		Options:        compat.Options,
		Action:         compat.Action,
		TaskName:       compat.TaskName,
		TaskPrompt:     compat.TaskPrompt,
		TargetSelector: compat.TargetSelector,
		TargetName:     compat.TargetName,
		TargetProtocol: compat.TargetProtocol,
		TargetHost:     compat.TargetHost,
		SkillName:      compat.SkillName,
		Path:           compat.Path,
		Content:        compat.Content,
		Pattern:        compat.Pattern,
		Todos:          compat.Todos,
		MemoryKey:      compat.MemoryKey,
		MemoryValue:    compat.MemoryValue,
		MemoryScope:    compat.MemoryScope,
		ToolName:       compat.ToolName,
		ToolArgs:       parseToolArgs(compat.ToolArgs),
		OldString:      compat.OldString,
		NewString:      compat.NewString,
		ReplaceAll:     compat.ReplaceAll,
		GlobPattern:    compat.GlobPattern,
	}

	// 适配 Command (兼容 string 或 []string)
	if compat.Command != "" {
		resp.Command = decodeJSONUnicodeEscapes(compat.Command)
	} else if len(compat.CmdArray) > 0 {
		resp.Command = decodeJSONUnicodeEscapes(compat.CmdArray[len(compat.CmdArray)-1])
	}

	// 适配 Thought
	if compat.Thought != "" {
		resp.Thought = compat.Thought
	} else if compat.Explanation != "" {
		resp.Thought = compat.Explanation
	} else {
		resp.Thought = inferThoughtFromCommand(resp.Command)
	}

	// 适配 Report
	switch v := compat.FinalReport.(type) {
	case string:
		resp.FinalReport = v
	case map[string]interface{}, []interface{}:
		prettyBytes, _ := json.MarshalIndent(v, "", "  ")
		resp.FinalReport = string(prettyBytes)
	default:
		if v != nil {
			resp.FinalReport = fmt.Sprintf("%v", v)
		}
	}

	return finalizeResponse(resp), nil
}

func extractClarificationQuestion(raw string) string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	needles := []string{
		"请提供", "请告诉", "需要您", "需要你", "我需要", "需要确认", "请确认",
		"webhook", "url", "token", "地址", "选项", "选择", "？", "?",
	}
	for _, n := range needles {
		if strings.Contains(text, n) || strings.Contains(lower, n) {
			if len([]rune(text)) > 4000 {
				return string([]rune(text)[:4000]) + "\n...(内容过长已截断)..."
			}
			return text
		}
	}
	return ""
}

func finalizeResponse(resp AgentResponse) AgentResponse {
	if resp.Command != "" {
		realRisk, realReason := security.CheckRisk(resp.Command)
		resp.RiskLevel = realRisk
		resp.Reason = realReason
	}
	if resp.IsFinished {
		if strings.TrimSpace(resp.FinalReport) == "" || resp.FinalReport == "任务完成" {
			if resp.Thought != "" {
				resp.FinalReport = fmt.Sprintf("📋 任务总结: %s", resp.Thought)
			} else {
				resp.FinalReport = "任务已结束 (详细结果请向上翻阅执行日志)"
			}
		}
	}
	return resp
}

const (
	contextCompactMessageThreshold = 24
	contextCompactCharBudget       = 60000
	contextCompactKeepRecent       = 10
)

// ManageHistoryContext 自动压缩历史上下文，提供接近“无限上下文”的滚动体验。
func ManageHistoryContext(history *[]Message) (bool, error) {
	if history == nil || len(*history) == 0 {
		return false, nil
	}
	if len(*history) <= contextCompactMessageThreshold && estimateHistoryChars(*history) <= contextCompactCharBudget {
		return false, nil
	}
	if len(*history) <= contextCompactKeepRecent {
		return false, nil
	}
	if err := compressHistory(history); err != nil {
		return false, err
	}
	return true, nil
}

func estimateHistoryChars(history []Message) int {
	n := 0
	for _, m := range history {
		n += len(m.Role) + len(m.Content) + 8
	}
	return n
}

// compressHistory 压缩历史记录
func compressHistory(history *[]Message) error {
	keepRecent := contextCompactKeepRecent
	if keepRecent < 4 {
		keepRecent = 4
	}
	if len(*history) <= keepRecent {
		return nil
	}
	cutIndex := len(*history) - keepRecent
	toSummarize := (*history)[:cutIndex]
	remaining := (*history)[cutIndex:]
	summaryPrompt := []Message{
		{Role: "system", Content: "你是 DeepSentry 的上下文压缩器。请将以下历史压缩成可继续执行任务的【前情提要】。必须保留：用户目标、已确认配置/凭证占位说明、已执行命令、关键输出结论、已创建/修改的文件路径、未完成 TODO、失败原因、下一步。不要编造。"},
	}
	summaryPrompt = append(summaryPrompt, toSummarize...)
	summaryPrompt = append(summaryPrompt, Message{Role: "user", Content: "请生成紧凑但可续跑的前情提要。"})

	summaryText, err := compressCallLLM(summaryPrompt)
	if err != nil {
		return err
	}
	newHistory := []Message{
		{Role: "system", Content: fmt.Sprintf("【前情提要】:\n%s", summaryText)},
	}
	newHistory = append(newHistory, remaining...)
	*history = newHistory
	return nil
}

func inferThoughtFromCommand(cmd string) string {
	if strings.HasPrefix(cmd, "upload") {
		return "正在上传文件到目标主机..."
	}
	if strings.HasPrefix(cmd, "download") {
		return "正在下载文件到本地分析..."
	}
	if cmd == "" {
		return "分析中..."
	}
	return fmt.Sprintf("执行: %s", cmd)
}

// cleanJSON 从 LLM 响应中提取并清洗 JSON，返回 (json, 前置说明文字)
func cleanJSON(s string) (string, string) {
	jsonPart, prose := extractJSONPayload(s)
	s = strings.TrimSpace(jsonPart)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)

	if strings.Contains(s, `\|`) {
		s = strings.ReplaceAll(s, `\|`, `\\|`)
	}
	return s, prose
}

// 🟢 [核心新增] extractCommandString 手动扫描字符串，提取 "command": "..." 中的值
// 能够完美处理转义引号 (\") 和转义反斜杠 (\\)，不依赖正则
func extractCommandString(jsonStr string) (string, bool) {
	// 1. 定位 key
	key := `"command"`
	idx := strings.Index(jsonStr, key)
	if idx == -1 {
		return "", false
	}

	// 2. 从 key 后面开始找第一个冒号
	cursor := idx + len(key)
	// 跳过冒号前的空白
	for cursor < len(jsonStr) && (jsonStr[cursor] == ' ' || jsonStr[cursor] == ':' || jsonStr[cursor] == '\n' || jsonStr[cursor] == '\r') {
		cursor++
	}

	// 3. 找值的起始引号
	startQuote := -1
	for i := cursor; i < len(jsonStr); i++ {
		if jsonStr[i] == '"' {
			startQuote = i
			break
		}
	}
	if startQuote == -1 {
		return "", false
	}

	// 4. 逐字符扫描，寻找结束引号（注意跳过转义字符）
	var resultBuilder strings.Builder
	inEscape := false // 是否处于转义状态

	for i := startQuote + 1; i < len(jsonStr); i++ {
		char := jsonStr[i]

		if inEscape {
			// 上一个字符是反斜杠，当前字符是转义后的字符
			// JSON 规范中，\" 代表 "，\\ 代表 \

			// 我们需要还原出“原始的Shell命令字符串”
			// 如果 JSON 里写的是 \" (即Shell里的 ")，我们需要写入 "
			// 如果 JSON 里写的是 \\ (即Shell里的 \)，我们需要写入 \

			switch char {
			case '"', '\\', '/':
				resultBuilder.WriteByte(char)
			case 'n':
				resultBuilder.WriteByte('\n')
			case 'r':
				resultBuilder.WriteByte('\r')
			case 't':
				resultBuilder.WriteByte('\t')
			default:
				// 其他情况，保留反斜杠和字符 (比如正则里的 \d，AI可能写成了 \\d)
				// 既然是手动提取，我们尽量保留原意
				resultBuilder.WriteByte('\\')
				resultBuilder.WriteByte(char)
			}
			inEscape = false
		} else {
			if char == '\\' {
				inEscape = true
			} else if char == '"' {
				// 找到了未转义的结束引号，提取结束！
				return resultBuilder.String(), true
			} else {
				resultBuilder.WriteByte(char)
			}
		}
	}

	return "", false
}

func decodeJSONUnicodeEscapes(s string) string {
	if !strings.Contains(s, `\u`) && !strings.Contains(s, `\U`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+5 >= len(s) || (s[i+1] != 'u' && s[i+1] != 'U') {
			b.WriteByte(s[i])
			continue
		}
		hex := s[i+2 : i+6]
		v, err := strconv.ParseInt(hex, 16, 32)
		if err != nil {
			b.WriteByte(s[i])
			continue
		}
		b.WriteRune(rune(v))
		i += 5
	}
	return b.String()
}

func compressCallLLM(messages []Message) (string, error) {
	res, err := CallLLMWithRetry(messages, false, nil)
	if err != nil {
		return "", err
	}
	return res.Content, nil
}

// callLLM 兼容旧调用（摘要等）
func callLLM(_ string, messages []Message) (string, error) {
	return compressCallLLM(messages)
}

func parseToolArgs(raw map[string]interface{}) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch val := v.(type) {
		case string:
			out[k] = val
		case float64:
			out[k] = fmt.Sprintf("%.0f", val)
		case bool:
			out[k] = fmt.Sprintf("%v", val)
		default:
			out[k] = fmt.Sprintf("%v", v)
		}
	}
	return out
}
