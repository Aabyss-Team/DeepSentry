package analyzer

import (
	"ai-edr/internal/mcp"
	deepsentrytools "ai-edr/internal/tools"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ToolDefinition OpenAI 兼容 tools schema
type ToolDefinition struct {
	Type     string      `json:"type"`
	Function FunctionDef `json:"function"`
}

type FunctionDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// AgentToolDefinitions 返回 Deep Agent 原生 tool calling schema
func AgentToolDefinitions() []ToolDefinition {
	return AgentToolDefinitionsForContext(0, "")
}

// AgentToolDefinitionsForContext limits schema fan-out for smaller models and
// ranks task-relevant tools first. agent_action and tool_catalog are always
// present, so omitted tools remain discoverable/invokable via the compatibility
// path after tool_catalog describes them.
func AgentToolDefinitionsForContext(limit int, contextText string) []ToolDefinition {
	return agentToolDefinitionsForContext(limit, contextText, nil)
}

// AgentToolDefinitionsForContextWithPinned implements the Runtime v3 deferred
// tool contract. Tools already discovered or successfully invoked remain
// visible even when the per-turn candidate set changes. This cumulative
// behavior prevents a verified schema from falling out of the next request
// after context compaction.
func AgentToolDefinitionsForContextWithPinned(limit int, contextText string, pinned []string) []ToolDefinition {
	return agentToolDefinitionsForContext(limit, contextText, pinned)
}

func agentToolDefinitionsForContext(limit int, contextText string, pinned []string) []ToolDefinition {
	definitions := []ToolDefinition{
		{
			Type: "function",
			Function: FunctionDef{
				Name:        "agent_action",
				Description: "Execute a DeepSentry action that is not already exposed as a direct native function. Never wrap a visible built-in in agent_action; call that native function directly. Prefer action=execute for ordinary shell work.",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"thought": map[string]string{"type": "string", "description": "Reasoning"},
						"action": map[string]interface{}{
							"type":        "string",
							"description": "execute|task|load_skill|todo|ask_user|read_file|write_file|edit_file|glob|grep|ls|remember|forget|tool|finish. Do not use upload/download as action; use action=execute with command upload/download if file transfer is needed.",
							"enum":        []string{"execute", "task", "load_skill", "todo", "ask_user", "read_file", "write_file", "edit_file", "glob", "grep", "ls", "remember", "forget", "tool", "finish"},
						},
						"command":        map[string]string{"type": "string", "description": "Native shell command to run. This is the default path for system status, logs, scripts, chmod, crontab/systemd, curl notifications, etc."},
						"task_name":      map[string]string{"type": "string", "description": "Required when action=task and parallel_tasks is not used. Must be one of: log-analyst, vuln-scanner, webshell-hunter, network-analyst, general-purpose, ctf-solver, awd-defender, awd-plus-operator. Never leave empty."},
						"task_prompt":    map[string]string{"type": "string", "description": "Required when action=task and parallel_tasks is not used. Give the sub-agent a concrete standalone task. Never leave empty."},
						"task_max_steps": map[string]string{"type": "integer", "description": "AI-estimated max steps for this sub-agent task. The runtime caps it by user-configured subagent_max_steps."},
						"parallel_tasks": map[string]interface{}{
							"type":        "array",
							"description": "Run multiple independent sub-agents concurrently and return a combined collaboration report. Use this for multiple targets or directions. Each item must include non-empty task_name and task_prompt.",
							"items": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"task_name":       map[string]string{"type": "string", "description": "Required. Must be a registered sub-agent name; never leave empty."},
									"task_prompt":     map[string]string{"type": "string", "description": "Required. Concrete standalone task for this sub-agent; never leave empty."},
									"target_selector": map[string]string{"type": "string"},
									"task_max_steps":  map[string]string{"type": "integer"},
								},
								"required": []string{"task_name", "task_prompt"},
							},
						},
						"target_selector": map[string]string{"type": "string", "description": "Optional targets selector for multi-server task delegation, e.g. all, prod, ssh, web-01"},
						"target_name":     map[string]string{"type": "string"},
						"target_protocol": map[string]string{"type": "string"},
						"target_host":     map[string]string{"type": "string"},
						"skill_name":      map[string]string{"type": "string"},
						"path":            map[string]string{"type": "string"},
						"content":         map[string]string{"type": "string"},
						"pattern":         map[string]string{"type": "string"},
						"old_string":      map[string]string{"type": "string"},
						"new_string":      map[string]string{"type": "string"},
						"replace_all":     map[string]string{"type": "boolean"},
						"glob_pattern":    map[string]string{"type": "string"},
						"memory_key":      map[string]string{"type": "string"},
						"memory_value":    map[string]string{"type": "string"},
						"memory_scope":    map[string]string{"type": "string"},
						"tool_name":       map[string]string{"type": "string", "description": "MCP tool name, or a built-in name only when direct native functions are unavailable. Prefer the separately exposed built-in native functions because their parameters are validated."},
						"tool_args":       map[string]interface{}{"type": "object", "description": "MCP arguments, or documented built-in arguments on compatibility paths.", "additionalProperties": map[string]string{"type": "string"}},
						"question":        map[string]string{"type": "string", "description": "Question to ask the user when required information is missing. Use with action=ask_user."},
						"options":         map[string]interface{}{"type": "array", "description": "Optional short answer choices for action=ask_user.", "items": map[string]string{"type": "string"}},
						"final_report":    map[string]string{"type": "string"},
						"is_finished":     map[string]string{"type": "boolean"},
						"todos": map[string]interface{}{
							"type": "array",
							"items": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"id":      map[string]string{"type": "string", "description": "String id, e.g. \"1\". Do not use a JSON number."},
									"content": map[string]string{"type": "string", "description": "Task content. Do not use title/detail instead."},
									"status":  map[string]string{"type": "string", "description": "pending|in_progress|completed"},
								},
							},
						},
					},
					"required": []string{"thought", "action"},
				},
			},
		},
	}

	// Expose every enabled built-in as a real native function. This gives the
	// provider the exact argument names/types/enums instead of asking the model
	// to guess inside agent_action.tool_args.
	definitions = append(definitions, ToolDefinition{
		Type: "function",
		Function: FunctionDef{
			Name:        "tool_catalog",
			Description: "Discover a DeepSentry built-in only when no currently exposed specialized function matches. Never repeat the same catalog search; after discovery invoke the returned exact tool instead of searching again.",
			Parameters:  deepsentrytools.JSONSchema("tool_catalog"),
		},
	})
	names := selectNativeToolNamesWithPinned(deepsentrytools.ListNames(), limit, contextText, pinned)
	for _, name := range names {
		tool, ok := deepsentrytools.Get(name)
		if !ok {
			continue
		}
		description := fmt.Sprintf("DeepSentry built-in [%s, %s]. %s", tool.Category, tool.Perspective, tool.Description)
		if help := deepsentrytools.FormatToolHelp(name); help != "" {
			description += "\n" + truncateToolDescription(help, 800)
		}
		if aliases := deepsentrytools.SearchAliases(name); len(aliases) > 0 {
			description += "\nTypical intents / 常见意图: " + strings.Join(aliases, ", ")
		}
		definitions = append(definitions, ToolDefinition{
			Type: "function",
			Function: FunctionDef{
				Name:        name,
				Description: description,
				Parameters:  deepsentrytools.JSONSchema(name),
			},
		})
	}
	// Full native-tool profiles expose MCP tools with the server-provided JSON
	// schema, matching first-class MCP clients. Limited profiles keep the
	// compact agent_action compatibility path to stay within provider limits.
	if limit <= 0 {
		for _, tool := range mcp.Global().ListTools() {
			parameters := tool.InputSchema
			if parameters == nil {
				parameters = map[string]interface{}{"type": "object", "additionalProperties": true}
			}
			description := truncateToolDescription(tool.Description, 800)
			if description == "" {
				description = "MCP tool exposed by server " + tool.Server
			}
			definitions = append(definitions, ToolDefinition{
				Type: "function",
				Function: FunctionDef{
					Name:        tool.Name,
					Description: description,
					Parameters:  parameters,
				},
			})
		}
	}
	return definitions
}

func selectNativeToolNamesWithPinned(names []string, limit int, contextText string, pinned []string) []string {
	sort.Strings(names)
	if limit <= 0 || len(names) <= limit {
		return names
	}
	query := strings.ToLower(contextText)
	selected := make([]string, 0, limit)
	seen := map[string]bool{}
	// Previously selected tools have the strongest claim on the bounded native
	// schema budget. Ignore stale/disabled names and preserve deterministic
	// order so provider prompt caching remains as stable as possible.
	pinned = append([]string(nil), pinned...)
	sort.Strings(pinned)
	for _, name := range pinned {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || !containsToolName(names, name) || len(selected) >= limit {
			continue
		}
		selected = append(selected, name)
		seen[name] = true
	}
	type scoredTool struct {
		name  string
		score int
	}
	var scored []scoredTool
	for _, name := range names {
		if seen[name] {
			continue
		}
		if name == "config_manage" && !explicitDeepSentryConfigIntent(query) {
			continue
		}
		tool, ok := deepsentrytools.Get(name)
		if !ok {
			continue
		}
		score := deepsentrytools.SearchRelevance(tool, query)
		scored = append(scored, scoredTool{name: name, score: score})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].name < scored[j].name
		}
		return scored[i].score > scored[j].score
	})
	for _, item := range scored {
		if len(selected) >= limit {
			break
		}
		// Runtime v3 uses true deferred exposure: zero-relevance tools remain
		// hidden and are available through tool_catalog. Alphabetically filling
		// the remaining budget made config_manage and other unrelated tools look
		// like recommendations, which measurably reduced long-tail selection.
		if item.score <= 0 {
			continue
		}
		selected = append(selected, item.name)
	}
	return selected
}

func explicitDeepSentryConfigIntent(query string) bool {
	query = strings.ToLower(query)
	for _, marker := range []string{
		"deepsentry", "config.yaml", "agent_runtime", "添加目标", "新增目标", "修改目标",
		"fleet目标", "mcp server", "mcp_server", "skill来源", "启用skill", "禁用skill",
		"enable skill", "disable skill", "show config", "config status", "manage config", "配置状态",
	} {
		if strings.Contains(query, marker) {
			return true
		}
	}
	return false
}

func containsToolName(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

func truncateToolDescription(text string, maxRunes int) string {
	runes := []rune(text)
	if maxRunes <= 0 || len(runes) <= maxRunes {
		return text
	}
	return string(runes[:maxRunes]) + "..."
}

// ParseToolCallResponse 从 native tool_calls 解析 AgentResponse
func ParseToolCallResponse(toolCallArgs string) (AgentResponse, error) {
	var compat CompatibilityResponse
	if err := json.Unmarshal([]byte(toolCallArgs), &compat); err != nil {
		return AgentResponse{}, err
	}
	resp := AgentResponse{
		Thought:        compat.Thought,
		Command:        decodeJSONUnicodeEscapes(compat.Command),
		RiskLevel:      compat.RiskLevel,
		IsFinished:     compat.IsFinished,
		Question:       compat.Question,
		Options:        compat.Options,
		Action:         compat.Action,
		TaskName:       compat.TaskName,
		TaskPrompt:     compat.TaskPrompt,
		TaskMaxSteps:   compat.TaskMaxSteps,
		ParallelTasks:  compat.ParallelTasks,
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
	if v, ok := compat.FinalReport.(string); ok {
		resp.FinalReport = v
	}
	// edit_file / glob fields via json unmarshal into compat — copy manually from raw if needed
	return resp, nil
}

// ParseNamedToolCall maps a directly exposed built-in native function back to
// the existing harness action protocol so risk review and approvals remain in
// one place.
func ParseNamedToolCall(name, toolCallArgs string) (AgentResponse, error) {
	if name == "" || name == "agent_action" {
		return ParseToolCallResponse(toolCallArgs)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(toolCallArgs), &raw); err != nil {
		return AgentResponse{}, err
	}
	if name != "tool_catalog" {
		if _, ok := deepsentrytools.Get(name); !ok {
			if _, _, mcpOK := mcp.Global().Get(name); !mcpOK {
				return AgentResponse{}, fmt.Errorf("unknown native tool: %s", name)
			}
			return AgentResponse{
				Thought:  "调用已连接的 MCP 工具 " + name,
				Action:   "tool",
				ToolName: name,
				ToolArgs: parseToolArgs(raw),
			}, nil
		}
	}
	return AgentResponse{
		Thought:  "调用已校验的内置工具 " + name,
		Action:   "tool",
		ToolName: name,
		ToolArgs: parseToolArgs(raw),
	}, nil
}
