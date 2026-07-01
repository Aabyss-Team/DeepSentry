package analyzer

import (
	"encoding/json"
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
	return []ToolDefinition{
		{
			Type: "function",
			Function: FunctionDef{
				Name:        "agent_action",
				Description: "Execute a DeepSentry agent action. Prefer action=execute with native shell first; use action=tool only when shell is insufficient or a specialized DeepSentry tool is required.",
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
						"tool_name":       map[string]string{"type": "string", "description": "Built-in/MCP tool name. Use only after native shell is insufficient; use tool_catalog first to discover built-in tools when unsure."},
						"tool_args":       map[string]interface{}{"type": "object", "description": "For tool_catalog use category/query filters; for discovered tools use their documented args.", "additionalProperties": map[string]string{"type": "string"}},
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
