package mcp

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ExternalTool MCP 发现的外部工具
type ExternalTool struct {
	Name         string
	OriginalName string
	Description  string
	Server       string
	InputSchema  map[string]interface{}
}

// ToolHandler 外部工具执行回调
type ToolHandler func(args map[string]string) (string, error)

// Registry MCP 工具注册表（对标 deepagents MCP 扩展）
type Registry struct {
	mu        sync.RWMutex
	tools     map[string]*ExternalTool
	handlers  map[string]ToolHandler
	aliases   map[string]string
	ambiguous map[string]bool
}

var globalRegistry = &Registry{
	tools:     make(map[string]*ExternalTool),
	handlers:  make(map[string]ToolHandler),
	aliases:   make(map[string]string),
	ambiguous: make(map[string]bool),
}

type stdioConnection struct {
	mu          sync.Mutex
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	reader      *bufio.Reader
	serverName  string
	fingerprint string
	nextID      int
}

var stdioConnections = struct {
	sync.Mutex
	byName map[string]*stdioConnection
}{byName: make(map[string]*stdioConnection)}

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

func (r *Registry) registerServerHandler(server string, tool ExternalTool, handler ToolHandler) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registerServerHandlerLocked(server, tool, handler)
}

func (r *Registry) registerServerHandlerLocked(server string, tool ExternalTool, handler ToolHandler) string {
	original := strings.TrimSpace(tool.OriginalName)
	if original == "" {
		original = strings.TrimSpace(tool.Name)
	}
	canonical := canonicalToolName(server, original)
	tool.Name = canonical
	tool.OriginalName = original
	r.tools[canonical] = &tool
	r.handlers[canonical] = handler
	if previous, exists := r.aliases[original]; !exists && !r.ambiguous[original] {
		r.aliases[original] = canonical
	} else if exists && previous != canonical {
		delete(r.aliases, original)
		r.ambiguous[original] = true
	}
	return canonical
}

type serverToolHandler struct {
	tool    ExternalTool
	handler ToolHandler
}

// replaceServerHandlers swaps one server's complete tool set under one lock so
// list_changed refreshes never expose a half-empty registry to concurrent calls.
func (r *Registry) replaceServerHandlers(server string, discovered []serverToolHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, tool := range r.tools {
		if tool != nil && tool.Server == server {
			delete(r.tools, name)
			delete(r.handlers, name)
		}
	}
	for _, item := range discovered {
		original := strings.TrimSpace(item.tool.OriginalName)
		if original == "" {
			original = strings.TrimSpace(item.tool.Name)
		}
		canonical := canonicalToolName(server, original)
		item.tool.Name = canonical
		item.tool.OriginalName = original
		r.tools[canonical] = &item.tool
		r.handlers[canonical] = item.handler
	}
	r.rebuildAliasesLocked()
}

func (r *Registry) unregisterServer(server string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, tool := range r.tools {
		if tool != nil && tool.Server == server {
			delete(r.tools, name)
			delete(r.handlers, name)
		}
	}
	r.rebuildAliasesLocked()
}

func (r *Registry) rebuildAliasesLocked() {
	r.aliases = make(map[string]string)
	r.ambiguous = make(map[string]bool)
	for canonical, tool := range r.tools {
		if tool == nil || tool.Server == "" {
			continue
		}
		original := tool.OriginalName
		if strings.TrimSpace(original) == "" {
			original = tool.Name
		}
		if previous, exists := r.aliases[original]; !exists && !r.ambiguous[original] {
			r.aliases[original] = canonical
		} else if exists && previous != canonical {
			delete(r.aliases, original)
			r.ambiguous[original] = true
		}
	}
}

// Get 获取 MCP 工具
func (r *Registry) Get(name string) (*ExternalTool, ToolHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if canonical, ok := r.aliases[name]; ok {
		name = canonical
	}
	t, ok := r.tools[name]
	h := r.handlers[name]
	return t, h, ok && h != nil
}

func canonicalToolName(server, tool string) string {
	clean := func(value string) string {
		original := strings.TrimSpace(value)
		var b strings.Builder
		changed := false
		for _, r := range original {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
				b.WriteRune(r)
			} else {
				b.WriteByte('_')
				changed = true
			}
		}
		value = strings.Trim(b.String(), "_")
		if value == "" {
			value = "tool"
			changed = true
		}
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(original)))[:8]
		if changed || len(value) > 30 {
			if len(value) > 21 {
				value = value[:21]
			}
			value = strings.TrimRight(value, "_-") + "_" + hash
		}
		return value
	}
	server, tool = clean(server), clean(tool)
	if server == "" {
		return tool
	}
	return server + "__" + tool
}

// ListTools returns immutable copies for native tool-schema generation.
func (r *Registry) ListTools() []ExternalTool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ExternalTool, 0, len(r.tools))
	for _, tool := range r.tools {
		if tool != nil {
			out = append(out, *tool)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ListNames 列出已注册 MCP 工具名
func (r *Registry) ListNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)
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
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	const promptBudget = 12000
	omitted := 0
	for _, name := range names {
		t := r.tools[name]
		line := fmt.Sprintf("- **mcp:%s** (%s): %s\n", name, t.Server, truncateMCPText(t.Description, 600))
		if b.Len()+len(line) > promptBudget {
			omitted++
			continue
		}
		b.WriteString(line)
	}
	if omitted > 0 {
		b.WriteString(fmt.Sprintf("… 另有 %d 个 MCP 工具因 prompt 预算未列出。\n", omitted))
	}
	b.WriteString(FormatServerInstructions())
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
	Name              string            `json:"name" yaml:"name"`
	Type              string            `json:"type" yaml:"type"`
	Command           string            `json:"command" yaml:"command"`
	Args              []string          `json:"args" yaml:"args"`
	Env               map[string]string `json:"env" yaml:"env"`
	CWD               string            `json:"cwd" yaml:"cwd"`
	URL               string            `json:"url" yaml:"url"`
	Headers           map[string]string `json:"headers" yaml:"headers"`
	BearerTokenEnvVar string            `json:"bearer_token_env_var" yaml:"bearer_token_env_var"`
	EnabledTools      []string          `json:"enabled_tools" yaml:"enabled_tools"`
	DisabledTools     []string          `json:"disabled_tools" yaml:"disabled_tools"`
	StartupTimeoutSec int               `json:"startup_timeout_sec" yaml:"startup_timeout_sec"`
	ToolTimeoutSec    int               `json:"tool_timeout_sec" yaml:"tool_timeout_sec"`
	Required          bool              `json:"required" yaml:"required"`
	Disabled          bool              `json:"disabled" yaml:"disabled"`
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
	serverName := strings.TrimSpace(cfg.Name)
	if serverName == "" {
		serverName = cfg.Command
	}
	fingerprintRaw, _ := json.Marshal(cfg)
	fingerprint := string(fingerprintRaw)

	stdioConnections.Lock()
	defer stdioConnections.Unlock()
	if existing := stdioConnections.byName[serverName]; existing != nil {
		if existing.fingerprint == fingerprint {
			return nil
		}
		existing.close()
		delete(stdioConnections.byName, serverName)
		globalRegistry.unregisterServer(serverName)
	}

	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Env = mcpProcessEnvironment(os.Environ(), cfg.Env)
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
	conn := &stdioConnection{
		cmd:         cmd,
		stdin:       stdin,
		reader:      bufio.NewReader(stdout),
		serverName:  serverName,
		fingerprint: fingerprint,
		nextID:      2,
	}
	connected := false
	defer func() {
		if !connected {
			conn.close()
		}
	}()

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
	initRaw, err := readJSONRPCResponse(conn.reader, 1, 15*time.Second)
	if err != nil {
		return fmt.Errorf("MCP server %s initialize 失败: %w", serverName, err)
	}
	if err := jsonRPCResponseError(initRaw); err != nil {
		return fmt.Errorf("MCP server %s initialize 失败: %w", serverName, err)
	}
	if err := writeJSONRPC(stdin, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]interface{}{},
	}); err != nil {
		return err
	}

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
	respRaw, err := readJSONRPCResponse(conn.reader, 2, 15*time.Second)
	if err != nil {
		return err
	}
	if err := jsonRPCResponseError(respRaw); err != nil {
		return fmt.Errorf("MCP server %s tools/list 失败: %w", serverName, err)
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

	for _, t := range listResp.Result.Tools {
		toolName := t.Name
		desc := t.Description
		schema := t.InputSchema
		globalRegistry.RegisterHandler(toolName, ExternalTool{
			Name:        toolName,
			Description: desc,
			Server:      serverName,
			InputSchema: schema,
		}, makeStdioHandler(conn, toolName, schema))
	}

	stdioConnections.byName[serverName] = conn
	connected = true
	go monitorStdioConnection(conn, cmd)
	return nil
}

// mcpProcessEnvironment applies least privilege to third-party MCP servers.
// Credentials are never inherited implicitly; a server receives secrets only
// when the user explicitly places them in that server's env configuration.
func mcpProcessEnvironment(parent []string, explicit map[string]string) []string {
	allowed := map[string]bool{
		"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
		"TMPDIR": true, "TMP": true, "TEMP": true, "LANG": true, "TZ": true,
		"SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true, "PATHEXT": true,
		"APPDATA": true, "LOCALAPPDATA": true, "PROGRAMDATA": true,
	}
	values := make(map[string]string, len(allowed)+len(explicit))
	for _, item := range parent {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		upper := strings.ToUpper(key)
		if allowed[upper] || strings.HasPrefix(upper, "LC_") || strings.HasPrefix(upper, "XDG_") {
			values[key] = value
		}
	}
	for key, value := range explicit {
		if strings.TrimSpace(key) != "" && !strings.ContainsAny(key, "=\x00") && !strings.ContainsRune(value, '\x00') {
			values[key] = value
		}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+values[key])
	}
	return out
}

func makeStdioHandler(conn *stdioConnection, toolName string, schema map[string]interface{}) ToolHandler {
	return func(args map[string]string) (string, error) {
		coerced, err := validateAndCoerceMCPArgs(schema, args)
		if err != nil {
			return "", fmt.Errorf("MCP 工具 %s 参数无效: %w", toolName, err)
		}
		conn.mu.Lock()
		defer conn.mu.Unlock()
		if conn.cmd == nil || conn.cmd.Process == nil {
			return "", fmt.Errorf("MCP server %s 已断开", conn.serverName)
		}
		conn.nextID++
		callReq := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      conn.nextID,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      toolName,
				"arguments": coerced,
			},
		}
		if err := writeJSONRPC(conn.stdin, callReq); err != nil {
			conn.closeLocked()
			return "", err
		}
		raw, err := readJSONRPCResponse(conn.reader, conn.nextID, 10*time.Minute)
		if err != nil {
			conn.closeLocked()
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

func (c *stdioConnection) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

func (c *stdioConnection) closeLocked() {
	if c.stdin != nil {
		_ = c.stdin.Close()
		c.stdin = nil
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	c.cmd = nil
}

func monitorStdioConnection(conn *stdioConnection, cmd *exec.Cmd) {
	_ = cmd.Wait()
	stdioConnections.Lock()
	defer stdioConnections.Unlock()
	if stdioConnections.byName[conn.serverName] == conn {
		delete(stdioConnections.byName, conn.serverName)
		globalRegistry.unregisterServer(conn.serverName)
	}
}

// CloseAll stops every stdio MCP child process. It is safe to call repeatedly.
func CloseAll() {
	closeSDKConnections()
	stdioConnections.Lock()
	connections := make([]*stdioConnection, 0, len(stdioConnections.byName))
	for name, conn := range stdioConnections.byName {
		connections = append(connections, conn)
		delete(stdioConnections.byName, name)
		globalRegistry.unregisterServer(name)
	}
	stdioConnections.Unlock()
	for _, conn := range connections {
		conn.close()
	}
}

func jsonRPCResponseError(raw []byte) error {
	var envelope struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("无效 JSON-RPC 响应: %w", err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("JSON-RPC %d: %s", envelope.Error.Code, envelope.Error.Message)
	}
	return nil
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
	const maxMCPMessageBytes = 16 << 20
	var out bytes.Buffer
	for {
		part, err := r.ReadSlice('\n')
		if out.Len()+len(part) > maxMCPMessageBytes {
			return nil, fmt.Errorf("MCP JSON-RPC 消息超过上限 %d 字节", maxMCPMessageBytes)
		}
		_, _ = out.Write(part)
		if err == nil {
			return out.Bytes(), nil
		}
		if err != bufio.ErrBufferFull {
			return nil, err
		}
	}
}

func validateAndCoerceMCPArgs(schema map[string]interface{}, args map[string]string) (map[string]interface{}, error) {
	if args == nil {
		args = map[string]string{}
	}
	properties, _ := schema["properties"].(map[string]interface{})
	required, _ := schema["required"].([]interface{})
	for _, item := range required {
		name, _ := item.(string)
		if name == "" {
			continue
		}
		if _, ok := args[name]; !ok {
			return nil, fmt.Errorf("缺少必填参数 %s", name)
		}
	}
	if allow, ok := schema["additionalProperties"].(bool); ok && !allow {
		for name := range args {
			if _, exists := properties[name]; !exists {
				return nil, fmt.Errorf("未知参数 %s", name)
			}
		}
	}

	out := make(map[string]interface{}, len(args))
	for name, raw := range args {
		spec, _ := properties[name].(map[string]interface{})
		value, err := coerceMCPValue(raw, spec)
		if err != nil {
			return nil, fmt.Errorf("参数 %s: %w", name, err)
		}
		if enum, ok := spec["enum"].([]interface{}); ok && len(enum) > 0 {
			matched := false
			for _, allowed := range enum {
				if fmt.Sprint(value) == fmt.Sprint(allowed) {
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("参数 %s=%q 不在 enum 可选值中", name, raw)
			}
		}
		out[name] = value
	}
	return out, nil
}

func coerceMCPValue(raw string, spec map[string]interface{}) (interface{}, error) {
	typeName, _ := spec["type"].(string)
	switch typeName {
	case "integer":
		value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("需要 integer，收到 %q", raw)
		}
		return value, nil
	case "number":
		value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil {
			return nil, fmt.Errorf("需要 number，收到 %q", raw)
		}
		return value, nil
	case "boolean":
		value, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("需要 boolean，收到 %q", raw)
		}
		return value, nil
	case "array":
		var value []interface{}
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return nil, fmt.Errorf("需要 JSON array，收到 %q", raw)
		}
		return value, nil
	case "object":
		var value map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return nil, fmt.Errorf("需要 JSON object，收到 %q", raw)
		}
		return value, nil
	default:
		return raw, nil
	}
}

func readJSONRPCLineWithTimeout(r *bufio.Reader, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		return readJSONRPCLine(r)
	}
	type result struct {
		raw []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		raw, err := readJSONRPCLine(r)
		ch <- result{raw: raw, err: err}
	}()
	select {
	case res := <-ch:
		return res.raw, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("等待 JSON-RPC 响应超时 (%s)", timeout)
	}
}

func readJSONRPCResponse(r *bufio.Reader, wantID int, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("等待 JSON-RPC id=%d 响应超时 (%s)", wantID, timeout)
		}
		raw, err := readJSONRPCLineWithTimeout(r, remaining)
		if err != nil {
			return nil, err
		}
		var envelope struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(raw, &envelope) != nil || len(envelope.ID) == 0 || string(envelope.ID) == "null" {
			// Servers may emit notifications/log messages between responses.
			continue
		}
		var numericID int
		if json.Unmarshal(envelope.ID, &numericID) == nil && numericID == wantID {
			return raw, nil
		}
	}
}

// LoadServersFromConfig 从配置加载 MCP 服务器
func LoadServersFromConfig(servers []ServerConfig) error {
	for _, s := range servers {
		if err := Connect(s); err != nil {
			return fmt.Errorf("MCP [%s]: %w", s.Name, err)
		}
	}
	return nil
}
