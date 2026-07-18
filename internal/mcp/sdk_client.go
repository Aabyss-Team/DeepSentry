package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type ServerStatus struct {
	Name         string
	Transport    string
	State        string
	Error        string
	Protocol     string
	Instructions string
	Tools        int
	Resources    int
	Templates    int
	Prompts      int
	Auth         string
}

type ExternalResource struct {
	Server      string
	URI         string
	Name        string
	Title       string
	Description string
	MIMEType    string
	Size        int64
}

type ExternalPrompt struct {
	Server      string
	Name        string
	Title       string
	Description string
	Arguments   []*sdkmcp.PromptArgument
}

type ExternalResourceTemplate struct {
	Server      string
	URITemplate string
	Name        string
	Title       string
	Description string
	MIMEType    string
}

type sdkConnection struct {
	mu          sync.RWMutex
	refreshMu   sync.Mutex
	serverName  string
	transport   string
	fingerprint string
	session     *sdkmcp.ClientSession
	cancel      context.CancelFunc
	toolTimeout time.Duration
	status      ServerStatus
	resources   []ExternalResource
	templates   []ExternalResourceTemplate
	prompts     []ExternalPrompt
	config      ServerConfig
}

var sdkConnections = struct {
	sync.RWMutex
	byName map[string]*sdkConnection
}{byName: make(map[string]*sdkConnection)}

// Connect uses the official Tier-1 MCP Go SDK for stdio and Streamable HTTP.
// It supports protocol negotiation, pagination and list_changed notifications.
func Connect(cfg ServerConfig) error {
	return connectWithOAuthHandler(cfg, nil)
}

// ConnectOAuth performs an interactive MCP Authorization Code + PKCE flow.
// It is intentionally separate from Connect so startup never opens a browser
// without a user's explicit `/mcp login` request. Tokens remain in memory.
func ConnectOAuth(cfg ServerConfig) error {
	if err := validateRemoteMCPURL(cfg.URL); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("启动 MCP OAuth 回调失败: %w", err)
	}
	defer listener.Close()
	redirectURL := "http://" + listener.Addr().String() + "/callback"
	authCh := make(chan *sdkauth.AuthorizationResult, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, req *http.Request) {
		if oauthErr := strings.TrimSpace(req.URL.Query().Get("error")); oauthErr != "" {
			select {
			case errCh <- fmt.Errorf("OAuth 授权失败: %s", oauthErr):
			default:
			}
			http.Error(w, "Authorization failed. You can close this window.", http.StatusBadRequest)
			return
		}
		result := &sdkauth.AuthorizationResult{Code: req.URL.Query().Get("code"), State: req.URL.Query().Get("state")}
		select {
		case authCh <- result:
		default:
		}
		_, _ = fmt.Fprint(w, "DeepSentry MCP authentication successful. You can close this window.")
	})
	callbackServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if serveErr := callbackServer.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			select {
			case errCh <- serveErr:
			default:
			}
		}
	}()
	defer callbackServer.Close()

	handler, err := sdkauth.NewAuthorizationCodeHandler(&sdkauth.AuthorizationCodeHandlerConfig{
		RedirectURL: redirectURL,
		AuthorizationCodeFetcher: func(ctx context.Context, args *sdkauth.AuthorizationArgs) (*sdkauth.AuthorizationResult, error) {
			if err := openOAuthBrowser(args.URL); err != nil {
				return nil, fmt.Errorf("无法打开浏览器，请手动访问 %s: %w", args.URL, err)
			}
			select {
			case result := <-authCh:
				return result, nil
			case authErr := <-errCh:
				return nil, authErr
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	})
	if err != nil {
		return fmt.Errorf("初始化 MCP OAuth 失败: %w", err)
	}
	if cfg.StartupTimeoutSec <= 0 {
		cfg.StartupTimeoutSec = 180
	}
	return connectWithOAuthHandler(cfg, handler)
}

func connectWithOAuthHandler(cfg ServerConfig, oauthHandler sdkauth.OAuthHandler) error {
	if cfg.Disabled {
		return nil
	}
	serverName := strings.TrimSpace(cfg.Name)
	if serverName == "" {
		serverName = strings.TrimSpace(cfg.Command)
	}
	if serverName == "" {
		return fmt.Errorf("MCP server name 不能为空")
	}
	transportName := strings.ToLower(strings.TrimSpace(cfg.Type))
	if transportName == "" {
		transportName = "stdio"
	}
	if transportName == "http" {
		transportName = "streamable_http"
	}
	fingerprintRaw, _ := json.Marshal(cfg)
	fingerprint := string(fingerprintRaw)
	if oauthHandler != nil {
		fingerprint += "|oauth"
	}

	sdkConnections.RLock()
	existing := sdkConnections.byName[serverName]
	sdkConnections.RUnlock()
	if existing != nil && existing.fingerprint == fingerprint {
		return nil
	}
	if existing != nil {
		closeSDKConnection(existing)
	}

	startupTimeout := time.Duration(cfg.StartupTimeoutSec) * time.Second
	if startupTimeout <= 0 {
		startupTimeout = 15 * time.Second
	}
	toolTimeout := time.Duration(cfg.ToolTimeoutSec) * time.Second
	if toolTimeout <= 0 {
		toolTimeout = 60 * time.Second
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	connectCtx, connectCancel := context.WithTimeout(baseCtx, startupTimeout)
	defer connectCancel()

	var conn *sdkConnection
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "deepsentry", Version: "2.0.1"}, &sdkmcp.ClientOptions{
		Capabilities: &sdkmcp.ClientCapabilities{},
		KeepAlive:    30 * time.Second,
		ToolListChangedHandler: func(context.Context, *sdkmcp.ToolListChangedRequest) {
			if conn != nil {
				go conn.refreshCapabilities()
			}
		},
		PromptListChangedHandler: func(context.Context, *sdkmcp.PromptListChangedRequest) {
			if conn != nil {
				go conn.refreshCapabilities()
			}
		},
		ResourceListChangedHandler: func(context.Context, *sdkmcp.ResourceListChangedRequest) {
			if conn != nil {
				go conn.refreshCapabilities()
			}
		},
	})

	var transport sdkmcp.Transport
	switch transportName {
	case "stdio":
		if strings.TrimSpace(cfg.Command) == "" {
			cancel()
			return fmt.Errorf("MCP stdio command 不能为空")
		}
		cmd := exec.Command(cfg.Command, cfg.Args...)
		cmd.Env = mcpProcessEnvironment(os.Environ(), cfg.Env)
		if strings.TrimSpace(cfg.CWD) != "" {
			cmd.Dir = cfg.CWD
		}
		transport = &sdkmcp.CommandTransport{Command: cmd, TerminateDuration: 3 * time.Second}
	case "streamable_http":
		if err := validateRemoteMCPURL(cfg.URL); err != nil {
			cancel()
			return err
		}
		transport = &sdkmcp.StreamableClientTransport{
			Endpoint:     cfg.URL,
			HTTPClient:   mcpHTTPClient(cfg),
			MaxRetries:   5,
			OAuthHandler: oauthHandler,
		}
	default:
		cancel()
		return fmt.Errorf("MCP transport %q 暂不支持；可用 stdio/http/streamable_http", cfg.Type)
	}

	session, err := client.Connect(connectCtx, transport, nil)
	if err != nil {
		cancel()
		setFailedServerStatus(serverName, transportName, err)
		return fmt.Errorf("MCP server %s 连接失败: %w", serverName, err)
	}
	init := session.InitializeResult()
	conn = &sdkConnection{
		serverName:  serverName,
		transport:   transportName,
		fingerprint: fingerprint,
		session:     session,
		cancel:      cancel,
		toolTimeout: toolTimeout,
		config:      cfg,
		status: ServerStatus{
			Name:      serverName,
			Transport: transportName,
			State:     "connected",
			Auth:      mcpAuthMode(cfg, oauthHandler != nil),
		},
	}
	if init != nil {
		conn.status.Protocol = init.ProtocolVersion
		conn.status.Instructions = strings.TrimSpace(init.Instructions)
	}
	if err := conn.refreshCapabilities(); err != nil {
		_ = session.Close()
		cancel()
		setFailedServerStatus(serverName, transportName, err)
		return fmt.Errorf("MCP server %s 能力发现失败: %w", serverName, err)
	}
	sdkConnections.Lock()
	sdkConnections.byName[serverName] = conn
	sdkConnections.Unlock()
	go monitorSDKConnection(conn)
	return nil
}

func openOAuthBrowser(target string) error {
	if parsed, err := url.Parse(target); err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return fmt.Errorf("OAuth URL 无效")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func (conn *sdkConnection) refreshCapabilities() error {
	conn.refreshMu.Lock()
	defer conn.refreshMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	toolCount := 0
	discovered := make([]serverToolHandler, 0)
	for tool, err := range conn.session.Tools(ctx, nil) {
		if err != nil {
			return err
		}
		if tool == nil || !conn.toolEnabled(tool.Name) {
			continue
		}
		schema, _ := tool.InputSchema.(map[string]interface{})
		external := ExternalTool{Name: tool.Name, OriginalName: tool.Name, Description: tool.Description, Server: conn.serverName, InputSchema: schema}
		originalName := tool.Name
		handler := func(args map[string]string) (string, error) {
			return conn.callTool(originalName, schema, args)
		}
		discovered = append(discovered, serverToolHandler{tool: external, handler: handler})
		toolCount++
	}
	globalRegistry.replaceServerHandlers(conn.serverName, discovered)

	resources := make([]ExternalResource, 0)
	for resource, err := range conn.session.Resources(ctx, nil) {
		if err != nil {
			break
		}
		if resource != nil {
			resources = append(resources, ExternalResource{Server: conn.serverName, URI: resource.URI, Name: resource.Name, Title: resource.Title, Description: resource.Description, MIMEType: resource.MIMEType, Size: resource.Size})
		}
	}
	templates := make([]ExternalResourceTemplate, 0)
	for template, err := range conn.session.ResourceTemplates(ctx, nil) {
		if err != nil {
			break
		}
		if template != nil {
			templates = append(templates, ExternalResourceTemplate{Server: conn.serverName, URITemplate: template.URITemplate, Name: template.Name, Title: template.Title, Description: template.Description, MIMEType: template.MIMEType})
		}
	}
	prompts := make([]ExternalPrompt, 0)
	for prompt, err := range conn.session.Prompts(ctx, nil) {
		if err != nil {
			break
		}
		if prompt != nil {
			prompts = append(prompts, ExternalPrompt{Server: conn.serverName, Name: prompt.Name, Title: prompt.Title, Description: prompt.Description, Arguments: prompt.Arguments})
		}
	}
	conn.mu.Lock()
	conn.resources = resources
	conn.templates = templates
	conn.prompts = prompts
	conn.status.State = "connected"
	conn.status.Error = ""
	conn.status.Tools = toolCount
	conn.status.Resources = len(resources)
	conn.status.Templates = len(templates)
	conn.status.Prompts = len(prompts)
	conn.mu.Unlock()
	return nil
}

func (conn *sdkConnection) toolEnabled(name string) bool {
	if len(conn.config.EnabledTools) > 0 && !containsFold(conn.config.EnabledTools, name) {
		return false
	}
	return !containsFold(conn.config.DisabledTools, name)
}

func (conn *sdkConnection) callTool(name string, schema map[string]interface{}, args map[string]string) (string, error) {
	coerced, err := validateAndCoerceMCPArgs(schema, args)
	if err != nil {
		return "", fmt.Errorf("MCP 工具 %s 参数无效: %w", name, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), conn.toolTimeout)
	defer cancel()
	result, err := conn.session.CallTool(ctx, &sdkmcp.CallToolParams{Name: name, Arguments: coerced})
	if err != nil {
		return "", err
	}
	out := formatMCPContent(result.Content, result.StructuredContent)
	if result.IsError {
		return "MCP 工具返回可修正错误:\n" + out, nil
	}
	return out, nil
}

func formatMCPContent(contents []sdkmcp.Content, structured any) string {
	parts := make([]string, 0, len(contents)+1)
	for _, content := range contents {
		switch item := content.(type) {
		case *sdkmcp.TextContent:
			if strings.TrimSpace(item.Text) != "" {
				parts = append(parts, item.Text)
			}
		case *sdkmcp.ResourceLink:
			parts = append(parts, fmt.Sprintf("[资源] %s (%s)", valueOrString(item.Title, item.Name), item.URI))
		case *sdkmcp.EmbeddedResource:
			if item.Resource != nil {
				if item.Resource.Text != "" {
					parts = append(parts, item.Resource.Text)
				} else {
					parts = append(parts, fmt.Sprintf("[嵌入资源] %s (%s, %d bytes)", item.Resource.URI, item.Resource.MIMEType, len(item.Resource.Blob)))
				}
			}
		case *sdkmcp.ImageContent:
			parts = append(parts, fmt.Sprintf("[图片内容] %s · %d bytes", item.MIMEType, len(item.Data)))
		case *sdkmcp.AudioContent:
			parts = append(parts, fmt.Sprintf("[音频内容] %s · %d bytes", item.MIMEType, len(item.Data)))
		default:
			if raw, err := json.Marshal(item); err == nil {
				parts = append(parts, string(raw))
			}
		}
	}
	if structured != nil {
		if raw, err := json.MarshalIndent(structured, "", "  "); err == nil && string(raw) != "null" {
			parts = append(parts, "[结构化结果]\n"+string(raw))
		}
	}
	if len(parts) == 0 {
		return "(MCP 无可显示输出)"
	}
	return truncateMCPText(strings.Join(parts, "\n"), 1<<20)
}

func ListServerStatuses() []ServerStatus {
	sdkConnections.RLock()
	connections := make([]*sdkConnection, 0, len(sdkConnections.byName))
	for _, conn := range sdkConnections.byName {
		connections = append(connections, conn)
	}
	sdkConnections.RUnlock()
	out := make([]ServerStatus, 0, len(connections))
	for _, conn := range connections {
		conn.mu.RLock()
		out = append(out, conn.status)
		conn.mu.RUnlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func FormatServerStatus() string {
	statuses := ListServerStatuses()
	if len(statuses) == 0 {
		return "当前没有已连接的 MCP Server。配置后请开始新会话或重启。"
	}
	var b strings.Builder
	for _, status := range statuses {
		line := fmt.Sprintf("- %s [%s] %s · tools=%d resources=%d templates=%d prompts=%d", status.Name, status.Transport, status.State, status.Tools, status.Resources, status.Templates, status.Prompts)
		if status.Protocol != "" {
			line += " · protocol=" + status.Protocol
		}
		if status.Auth != "" {
			line += " · auth=" + status.Auth
		}
		if status.Error != "" {
			line += " · error=" + status.Error
		}
		b.WriteString(line + "\n")
	}
	return strings.TrimSpace(b.String())
}

func mcpAuthMode(cfg ServerConfig, oauth bool) string {
	if oauth {
		return "oauth"
	}
	if strings.TrimSpace(cfg.BearerTokenEnvVar) != "" {
		return "bearer-env"
	}
	if len(cfg.Headers) > 0 {
		return "headers"
	}
	return "none"
}

func ListResources(server string) []ExternalResource {
	var out []ExternalResource
	for _, conn := range selectedConnections(server) {
		conn.mu.RLock()
		out = append(out, conn.resources...)
		conn.mu.RUnlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}
		return out[i].URI < out[j].URI
	})
	return out
}

func ListResourceTemplates(server string) []ExternalResourceTemplate {
	var out []ExternalResourceTemplate
	for _, conn := range selectedConnections(server) {
		conn.mu.RLock()
		out = append(out, conn.templates...)
		conn.mu.RUnlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}
		return out[i].URITemplate < out[j].URITemplate
	})
	return out
}

func ReadResource(server, uri string) (string, error) {
	conn, err := getSDKConnection(server)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), conn.toolTimeout)
	defer cancel()
	result, err := conn.session.ReadResource(ctx, &sdkmcp.ReadResourceParams{URI: uri})
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(result.Contents))
	for _, content := range result.Contents {
		if content == nil {
			continue
		}
		if content.Text != "" {
			parts = append(parts, content.Text)
		} else {
			parts = append(parts, fmt.Sprintf("[二进制资源] %s · %s · %d bytes", content.URI, content.MIMEType, len(content.Blob)))
		}
	}
	if len(parts) == 0 {
		return "(MCP 资源为空)", nil
	}
	return truncateMCPText(strings.Join(parts, "\n"), 1<<20), nil
}

func ListPrompts(server string) []ExternalPrompt {
	var out []ExternalPrompt
	for _, conn := range selectedConnections(server) {
		conn.mu.RLock()
		out = append(out, conn.prompts...)
		conn.mu.RUnlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func GetPrompt(server, name string, args map[string]string) (string, error) {
	conn, err := getSDKConnection(server)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), conn.toolTimeout)
	defer cancel()
	result, err := conn.session.GetPrompt(ctx, &sdkmcp.GetPromptParams{Name: name, Arguments: args})
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(result.Messages)+1)
	if result.Description != "" {
		parts = append(parts, result.Description)
	}
	for _, message := range result.Messages {
		if message != nil {
			parts = append(parts, fmt.Sprintf("[%s]\n%s", message.Role, formatMCPContent([]sdkmcp.Content{message.Content}, nil)))
		}
	}
	return truncateMCPText(strings.Join(parts, "\n\n"), 1<<20), nil
}

func FormatServerInstructions() string {
	statuses := ListServerStatuses()
	var b strings.Builder
	const totalBudget = 8192
	for _, status := range statuses {
		if status.Instructions == "" {
			continue
		}
		instructions := []rune(status.Instructions)
		if len(instructions) > 2048 {
			instructions = append(instructions[:2047], '…')
		}
		section := fmt.Sprintf("\nMCP Server %s 指令:\n%s\n", status.Name, string(instructions))
		if b.Len()+len(section) > totalBudget {
			break
		}
		b.WriteString(section)
	}
	return b.String()
}

func selectedConnections(server string) []*sdkConnection {
	server = strings.TrimSpace(server)
	sdkConnections.RLock()
	defer sdkConnections.RUnlock()
	if server != "" {
		if conn := sdkConnections.byName[server]; conn != nil {
			return []*sdkConnection{conn}
		}
		return nil
	}
	out := make([]*sdkConnection, 0, len(sdkConnections.byName))
	for _, conn := range sdkConnections.byName {
		out = append(out, conn)
	}
	return out
}

func getSDKConnection(server string) (*sdkConnection, error) {
	sdkConnections.RLock()
	conn := sdkConnections.byName[strings.TrimSpace(server)]
	sdkConnections.RUnlock()
	if conn == nil {
		return nil, fmt.Errorf("未连接 MCP Server: %s", server)
	}
	return conn, nil
}

func monitorSDKConnection(conn *sdkConnection) {
	err := conn.session.Wait()
	// A replaced connection may finish after its successor has registered the
	// same server name. Only the currently installed connection may mutate
	// status or unregister tools.
	sdkConnections.RLock()
	current := sdkConnections.byName[conn.serverName]
	sdkConnections.RUnlock()
	if current != conn {
		return
	}
	conn.mu.Lock()
	conn.status.State = "disconnected"
	if err != nil {
		conn.status.Error = err.Error()
	}
	conn.mu.Unlock()
	globalRegistry.unregisterServer(conn.serverName)
}

func closeSDKConnection(conn *sdkConnection) {
	if conn == nil {
		return
	}
	if conn.cancel != nil {
		conn.cancel()
	}
	if conn.session != nil {
		_ = conn.session.Close()
	}
	sdkConnections.Lock()
	if sdkConnections.byName[conn.serverName] == conn {
		delete(sdkConnections.byName, conn.serverName)
	}
	sdkConnections.Unlock()
	globalRegistry.unregisterServer(conn.serverName)
}

func closeSDKConnections() {
	sdkConnections.RLock()
	connections := make([]*sdkConnection, 0, len(sdkConnections.byName))
	for _, conn := range sdkConnections.byName {
		connections = append(connections, conn)
	}
	sdkConnections.RUnlock()
	for _, conn := range connections {
		closeSDKConnection(conn)
	}
}

// Disconnect closes one live MCP connection and removes all tools, resources
// and prompts discovered from it. It is safe to call for an offline server.
func Disconnect(server string) {
	sdkConnections.RLock()
	conn := sdkConnections.byName[strings.TrimSpace(server)]
	sdkConnections.RUnlock()
	if conn != nil {
		closeSDKConnection(conn)
	}
}

func setFailedServerStatus(name, transport string, err error) {
	conn := &sdkConnection{serverName: name, transport: transport, status: ServerStatus{Name: name, Transport: transport, State: "failed", Error: err.Error()}}
	sdkConnections.Lock()
	sdkConnections.byName[name] = conn
	sdkConnections.Unlock()
}

type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
	token   string
}

func (t headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	for key, value := range t.headers {
		if strings.TrimSpace(key) != "" && !strings.ContainsAny(key, "\r\n") && !strings.ContainsAny(value, "\r\n") {
			clone.Header.Set(key, value)
		}
	}
	if t.token != "" {
		clone.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.base.RoundTrip(clone)
}

func mcpHTTPClient(cfg ServerConfig) *http.Client {
	base := http.DefaultTransport
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		base = transport.Clone()
	}
	token := ""
	if name := strings.TrimSpace(cfg.BearerTokenEnvVar); name != "" {
		token = os.Getenv(name)
	}
	origin, _ := url.Parse(strings.TrimSpace(cfg.URL))
	return &http.Client{
		Transport: headerTransport{base: base, headers: cfg.Headers, token: token},
		Timeout:   0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("MCP HTTP 重定向次数过多")
			}
			// headerTransport applies credentials on every request, so redirects
			// must remain on the configured origin to prevent credential leaks.
			if origin == nil || !strings.EqualFold(req.URL.Scheme, origin.Scheme) || !strings.EqualFold(req.URL.Host, origin.Host) {
				return fmt.Errorf("MCP HTTP 拒绝携带凭据跨域重定向")
			}
			return nil
		},
	}
}

func truncateMCPText(text string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return text
	}
	return string(runes[:maxRunes]) + fmt.Sprintf("\n… [MCP 输出已限制为 %d 字符]", maxRunes)
}

func validateRemoteMCPURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("MCP HTTP URL 无效")
	}
	host := strings.ToLower(parsed.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return fmt.Errorf("MCP HTTP URL 必须使用 HTTPS；仅 localhost/回环地址允许 HTTP")
	}
	return nil
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func valueOrString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
