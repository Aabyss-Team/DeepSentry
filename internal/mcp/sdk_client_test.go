package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type sdkGreetingArgs struct {
	Name string `json:"name"`
}

func TestConnectStreamableHTTPDiscoversAndUsesAllServerPrimitives(t *testing.T) {
	CloseAll()
	t.Cleanup(CloseAll)

	server := sdkmcp.NewServer(
		&sdkmcp.Implementation{Name: "deepsentry-sdk-test", Version: "1"},
		&sdkmcp.ServerOptions{Instructions: "Prefer the documented resource."},
	)
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "greet", Description: "return a greeting"},
		func(_ context.Context, _ *sdkmcp.CallToolRequest, args sdkGreetingArgs) (*sdkmcp.CallToolResult, any, error) {
			return &sdkmcp.CallToolResult{Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "hello " + args.Name}}}, nil, nil
		})
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "hidden"},
		func(_ context.Context, _ *sdkmcp.CallToolRequest, _ any) (*sdkmcp.CallToolResult, any, error) {
			return &sdkmcp.CallToolResult{}, nil, nil
		})
	server.AddResource(&sdkmcp.Resource{Name: "guide", URI: "docs://guide", MIMEType: "text/plain"},
		func(_ context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
			return &sdkmcp.ReadResourceResult{Contents: []*sdkmcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "resource body"}}}, nil
		})
	server.AddResourceTemplate(&sdkmcp.ResourceTemplate{Name: "topic", URITemplate: "docs://{topic}", MIMEType: "text/plain"}, nil)
	server.AddPrompt(&sdkmcp.Prompt{Name: "review", Description: "review a topic", Arguments: []*sdkmcp.PromptArgument{{Name: "topic", Required: true}}},
		func(_ context.Context, req *sdkmcp.GetPromptRequest) (*sdkmcp.GetPromptResult, error) {
			return &sdkmcp.GetPromptResult{Messages: []*sdkmcp.PromptMessage{{Role: "user", Content: &sdkmcp.TextContent{Text: "review " + req.Params.Arguments["topic"]}}}}, nil
		})

	handler := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server { return server }, nil)
	var authSeen, headerSeen bool
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authSeen = authSeen || r.Header.Get("Authorization") == "Bearer test-secret"
		headerSeen = headerSeen || r.Header.Get("X-DeepSentry-Test") == "yes"
		handler.ServeHTTP(w, r)
	}))
	defer func() {
		Disconnect("sdk")
		httpServer.Close()
	}()

	const tokenEnv = "DEEPSENTRY_MCP_SDK_TEST_TOKEN"
	if err := os.Setenv(tokenEnv, "test-secret"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv(tokenEnv) })
	if err := Connect(ServerConfig{
		Name: "sdk", Type: "streamable_http", URL: httpServer.URL,
		Headers: map[string]string{"X-DeepSentry-Test": "yes"}, BearerTokenEnvVar: tokenEnv,
		EnabledTools: []string{"greet", "dynamic"},
	}); err != nil {
		t.Fatal(err)
	}

	if !authSeen || !headerSeen {
		t.Fatalf("expected configured HTTP authentication/header, auth=%v header=%v", authSeen, headerSeen)
	}
	if _, _, ok := Global().Get("sdk__greet"); !ok {
		t.Fatal("canonical MCP tool was not registered")
	}
	if _, _, ok := Global().Get("greet"); !ok {
		t.Fatal("unambiguous short alias was not registered")
	}
	if _, _, ok := Global().Get("sdk__hidden"); ok {
		t.Fatal("tool outside enabled_tools was exposed")
	}
	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "dynamic"},
		func(_ context.Context, _ *sdkmcp.CallToolRequest, _ any) (*sdkmcp.CallToolResult, any, error) {
			return &sdkmcp.CallToolResult{Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "dynamic result"}}}, nil, nil
		})
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, _, ok := Global().Get("sdk__dynamic"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tools/list_changed did not refresh the registry")
		}
		time.Sleep(10 * time.Millisecond)
	}
	got, err := Global().Run("sdk__greet", map[string]string{"name": "DeepSentry"})
	if err != nil || got != "hello DeepSentry" {
		t.Fatalf("tool result=%q err=%v", got, err)
	}
	if resources := ListResources("sdk"); len(resources) != 1 || resources[0].URI != "docs://guide" {
		t.Fatalf("unexpected resources: %#v", resources)
	}
	if templates := ListResourceTemplates("sdk"); len(templates) != 1 || templates[0].URITemplate != "docs://{topic}" {
		t.Fatalf("unexpected resource templates: %#v", templates)
	}
	if got, err := ReadResource("sdk", "docs://guide"); err != nil || got != "resource body" {
		t.Fatalf("resource result=%q err=%v", got, err)
	}
	if prompts := ListPrompts("sdk"); len(prompts) != 1 || prompts[0].Name != "review" {
		t.Fatalf("unexpected prompts: %#v", prompts)
	}
	if got, err := GetPrompt("sdk", "review", map[string]string{"topic": "auth"}); err != nil || !strings.Contains(got, "review auth") {
		t.Fatalf("prompt result=%q err=%v", got, err)
	}
	statuses := ListServerStatuses()
	if len(statuses) != 1 || statuses[0].Protocol == "" || statuses[0].Tools != 2 || statuses[0].Resources != 1 || statuses[0].Templates != 1 || statuses[0].Prompts != 1 {
		t.Fatalf("unexpected status: %#v", statuses)
	}
	if !strings.Contains(FormatServerInstructions(), "Prefer the documented resource") {
		t.Fatal("server instructions were not exposed to the agent prompt")
	}
}

func TestValidateRemoteMCPURL(t *testing.T) {
	for _, valid := range []string{"https://example.com/mcp", "http://localhost:8080/mcp", "http://127.0.0.1/mcp"} {
		if err := validateRemoteMCPURL(valid); err != nil {
			t.Errorf("valid URL %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"http://example.com/mcp", "file:///tmp/mcp", "https://user:pass@example.com/mcp"} {
		if err := validateRemoteMCPURL(invalid); err == nil {
			t.Errorf("unsafe URL %q accepted", invalid)
		}
	}
}

func TestMCPHTTPClientRejectsCredentialedCrossOriginRedirect(t *testing.T) {
	var destinationHit bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationHit = true
		if r.Header.Get("Authorization") != "" {
			t.Error("authorization leaked to redirect destination")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	t.Setenv("DEEPSENTRY_MCP_REDIRECT_TOKEN", "redirect-secret")
	client := mcpHTTPClient(ServerConfig{URL: origin.URL, BearerTokenEnvVar: "DEEPSENTRY_MCP_REDIRECT_TOKEN"})
	resp, err := client.Get(origin.URL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "跨域重定向") {
		t.Fatalf("cross-origin redirect should be rejected, err=%v", err)
	}
	if destinationHit {
		t.Fatal("redirect destination should not be contacted")
	}
}
