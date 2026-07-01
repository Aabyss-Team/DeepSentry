package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ExternalTool MCP 发现的外部工具
type ExternalTool struct {
	Name        string
	Description string
	Server      string
	InputSchema map[string]interface{}
}

// ToolHandler 外部工具执行回调
type ToolHandler func(args map[string]string) (string, error)

// Registry MCP 工具注册表（对标 deepagents MCP 扩展）
type Registry struct {
	mu       sync.RWMutex
	tools    map[string]*ExternalTool
	handlers map[string]ToolHandler
}

var globalRegistry = &Registry{
	tools:    make(map[string]*ExternalTool),
	handlers: make(map[string]ToolHandler),
}

// Global 返回全局 MCP 注册表
func Global() *Registry {
	return globalRegistry
}

// RegisterHandler 注册 MCP 工具处理器
func (r *Registry) RegisterHandler(name string, tool ExternalTool, handler ToolHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[name] = &tool
	r.handlers[name] = handler
}

// Get 获取 MCP 工具
func (r *Registry) Get(name string) (*ExternalTool, ToolHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	h := r.handlers[name]
	return t, h, ok && h != nil
}

// ListNames 列出已注册 MCP 工具名
func (r *Registry) ListNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	return names
}

// FormatPrompt 生成 MCP 工具 prompt 片段
func (r *Registry) FormatPrompt() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.tools) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n【MCP 扩展工具】\n")
	b.WriteString("格式: {\"action\":\"tool\",\"tool_name\":\"mcp:<name>\",\"tool_args\":{...}}\n\n")
	for name, t := range r.tools {
		b.WriteString(fmt.Sprintf("- **mcp:%s** (%s): %s\n", name, t.Server, t.Description))
	}
	return b.String()
}

// Run 执行 MCP 工具
func (r *Registry) Run(name string, args map[string]string) (string, error) {
	_, handler, ok := r.Get(name)
	if !ok {
		return "", fmt.Errorf("未注册 MCP 工具: %s", name)
	}
	return handler(args)
}

// ServerConfig MCP 服务器启动配置
type ServerConfig struct {
	Name     string            `json:"name" yaml:"name"`
	Type     string            `json:"type" yaml:"type"`
	Command  string            `json:"command" yaml:"command"`
	Args     []string          `json:"args" yaml:"args"`
	Env      map[string]string `json:"env" yaml:"env"`
	CWD      string            `json:"cwd" yaml:"cwd"`
	URL      string            `json:"url" yaml:"url"`
	Disabled bool              `json:"disabled" yaml:"disabled"`
}

// ConnectStdio 连接 stdio MCP 服务器并发现 tools（简化 JSON-RPC 2.0）
func ConnectStdio(cfg ServerConfig) error {
	if cfg.Disabled {
		return nil
	}
	if cfg.Type != "" && cfg.Type != "stdio" {
		return fmt.Errorf("MCP server %s 类型 %s 暂不支持运行，当前仅支持 stdio", cfg.Name, cfg.Type)
	}
	if cfg.Command == "" {
		return fmt.Errorf("MCP server command 不能为空")
	}
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Env = os.Environ()
	for k, v := range cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if strings.TrimSpace(cfg.CWD) != "" {
		cmd.Dir = cfg.CWD
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 MCP 服务器 %s 失败: %w", cfg.Name, err)
	}

	// initialize
	initReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]string{"name": "deepsentry", "version": "1.0"},
		},
	}
	if err := writeJSONRPC(stdin, initReq); err != nil {
		return err
	}
	reader := bufio.NewReader(stdout)
	_, _ = readJSONRPCLine(reader)

	// tools/list
	listReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}
	if err := writeJSONRPC(stdin, listReq); err != nil {
		return err
	}
	respRaw, err := readJSONRPCLine(reader)
	if err != nil {
		return err
	}

	var listResp struct {
		Result struct {
			Tools []struct {
				Name        string                 `json:"name"`
				Description string                 `json:"description"`
				InputSchema map[string]interface{} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respRaw, &listResp); err != nil {
		return fmt.Errorf("解析 MCP tools/list 失败: %w", err)
	}

	serverName := cfg.Name
	if serverName == "" {
		serverName = cfg.Command
	}

	for _, t := range listResp.Result.Tools {
		toolName := t.Name
		desc := t.Description
		schema := t.InputSchema
		globalRegistry.RegisterHandler(toolName, ExternalTool{
			Name:        toolName,
			Description: desc,
			Server:      serverName,
			InputSchema: schema,
		}, makeStdioHandler(cmd, stdin, reader, toolName))
	}

	go func() { _ = cmd.Wait() }()
	return nil
}

func makeStdioHandler(cmd *exec.Cmd, stdin interface{ Write([]byte) (int, error) }, reader *bufio.Reader, toolName string) ToolHandler {
	return func(args map[string]string) (string, error) {
		callReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      3,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      toolName,
				"arguments": args,
			},
		}
		if err := writeJSONRPC(stdin, callReq); err != nil {
			return "", err
		}
		raw, err := readJSONRPCLine(reader)
		if err != nil {
			return "", err
		}
		var callResp struct {
			Result struct {
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &callResp); err != nil {
			return string(raw), nil
		}
		if callResp.Error != nil {
			return "", fmt.Errorf("MCP 错误: %s", callResp.Error.Message)
		}
		var parts []string
		for _, c := range callResp.Result.Content {
			if c.Text != "" {
				parts = append(parts, c.Text)
			}
		}
		if len(parts) == 0 {
			return "(MCP 无文本输出)", nil
		}
		return strings.Join(parts, "\n"), nil
	}
}

func writeJSONRPC(w interface{ Write([]byte) (int, error) }, payload map[string]interface{}) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	line := append(raw, '\n')
	_, err = w.Write(line)
	return err
}

func readJSONRPCLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	return line, nil
}

// LoadServersFromConfig 从配置加载 MCP 服务器
func LoadServersFromConfig(servers []ServerConfig) error {
	for _, s := range servers {
		if err := ConnectStdio(s); err != nil {
			return fmt.Errorf("MCP [%s]: %w", s.Name, err)
		}
	}
	return nil
}
