package analyzer

import (
	"ai-edr/internal/collector"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ai-edr/internal/config"
)

func TestOpenAICompatibleParsesUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"choices":[{"message":{"content":"{\"action\":\"finish\",\"final_report\":\"ok\"}"}}],
			"usage":{"prompt_tokens":123,"completion_tokens":45,"total_tokens":168}
		}`))
	}))
	defer server.Close()

	result, err := callOpenAICompatible(context.Background(), config.Config{
		ApiURL:    server.URL + "/v1/chat/completions",
		ModelName: "test-model",
		ApiKey:    "none",
	}, []Message{{Role: "user", Content: "hi"}}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Usage.PromptTokens != 123 || result.Usage.CompletionTokens != 45 || result.Usage.TotalTokens != 168 {
		t.Fatalf("usage not parsed: %#v", result.Usage)
	}
}

func TestOpenAICompatibleSendsNativeBuiltinSchemasAndParsesName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.ToolChoice != "auto" {
			t.Fatalf("tool_choice=%#v, want auto", request.ToolChoice)
		}
		if request.MaxTokens != 4096 {
			t.Fatalf("max_tokens=%d want local adaptive 4096", request.MaxTokens)
		}
		if len(request.Tools) > 10 {
			t.Fatalf("local compact model received too many native schemas: %d", len(request.Tools))
		}
		found := false
		for _, def := range request.Tools {
			if def.Function.Name == "config_manage" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("config_manage native definition missing from %d tools", len(request.Tools))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"","tool_calls":[{"id":"call_1","type":"function","function":{"name":"config_manage","arguments":"{\"action\":\"status\"}"}}]}}]}`))
	}))
	defer server.Close()

	result, err := callOpenAICompatible(context.Background(), config.Config{
		ApiURL: server.URL, ModelName: "test-model", ApiKey: "none",
	}, []Message{{Role: "user", Content: "show config status"}}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.ToolCallName != "config_manage" || result.ToolCallArgs != `{"action":"status"}` {
		t.Fatalf("unexpected tool result: %#v", result)
	}
}

func TestOpenAICompatiblePreservesReasoningContentAcrossToolTurn(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var request ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"","reasoning_content":"signed-thought","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_log","arguments":"{\"path\":\"fixture.log\"}"}}]}}]}`))
			return
		}
		if len(request.Messages) < 2 || request.Messages[1].ReasoningContent != "signed-thought" {
			t.Fatalf("reasoning content was not passed back: %#v", request.Messages)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"done"}}]}`))
	}))
	defer server.Close()

	cfg := config.Config{ApiURL: server.URL, ModelName: "thinking-model", ApiKey: "none"}
	first, err := callOpenAICompatible(context.Background(), cfg, []Message{{Role: "user", Content: "inspect"}}, true, nil)
	if err != nil || first.ReasoningContent != "signed-thought" {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	call := ToolCall{ID: first.ToolCallID, Type: "function"}
	call.Function.Name = first.ToolCallName
	call.Function.Arguments = first.ToolCallArgs
	messages := []Message{
		{Role: "user", Content: "inspect"},
		{Role: "assistant", ReasoningContent: first.ReasoningContent, ToolCalls: []ToolCall{call}},
		{Role: "tool", ToolCallID: first.ToolCallID, Name: first.ToolCallName, Content: "ok"},
	}
	if _, err := callOpenAICompatible(context.Background(), cfg, messages, true, nil); err != nil || requests != 2 {
		t.Fatalf("round trip requests=%d err=%v", requests, err)
	}
}

func TestOpenAIStreamingPreservesMultipleToolCallsAndUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintln(w, `data: {"choices":[{"delta":{"reasoning_content":"reason-","tool_calls":[{"index":0,"id":"call_a","function":{"name":"process_list","arguments":"{\"lim"}},{"index":1,"id":"call_b","function":{"name":"port_listen","arguments":"{}"}}]}}]}`)
		_, _ = fmt.Fprintln(w, `data: {"choices":[{"delta":{"reasoning_content":"content","tool_calls":[{"index":0,"function":{"arguments":"it\":20}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":6,"total_tokens":16}}`)
		_, _ = fmt.Fprintln(w, "data: [DONE]")
	}))
	defer server.Close()

	result, err := callOpenAICompatible(context.Background(), config.Config{ApiURL: server.URL, ModelName: "test", ApiKey: "none"}, []Message{{Role: "user", Content: "inspect"}}, true, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ToolCalls) != 2 || result.ToolCalls[0].ID != "call_a" || result.ToolCalls[0].Arguments != `{"limit":20}` || result.ToolCalls[1].ID != "call_b" {
		t.Fatalf("tool calls not reconstructed: %#v", result.ToolCalls)
	}
	if result.Usage.TotalTokens != 16 {
		t.Fatalf("usage=%#v", result.Usage)
	}
	if result.ReasoningContent != "reason-content" {
		t.Fatalf("reasoning content=%q", result.ReasoningContent)
	}
}

func TestOpenAIStreamingReturnsStructuredPartialError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintln(w, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_partial","function":{"name":"process_list","arguments":"{\"limit\":"}}]}}]}`)
	}))
	defer server.Close()
	result, err := callOpenAICompatible(context.Background(), config.Config{ApiURL: server.URL, ModelName: "test", ApiKey: "none"}, []Message{{Role: "user", Content: "inspect"}}, true, func(string) {})
	var partial *PartialStreamError
	if !errors.As(err, &partial) || len(result.ToolCalls) != 1 || result.ToolCalls[0].ID != "call_partial" || partial.Result.ToolCalls[0].ID != "call_partial" {
		t.Fatalf("result=%#v err=%T %v", result, err, err)
	}
}

func TestLLMFailoverUsesConfiguredFallback(t *testing.T) {
	original := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = original })
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"action\":\"finish\",\"final_report\":\"fallback-ok\"}"}}]}`))
	}))
	defer fallback.Close()
	config.GlobalConfig = config.Config{
		Provider: "custom", APIProtocol: "openai_chat", ApiURL: primary.URL, ApiKey: "none", ModelName: "primary",
		Models: []config.ModelConfig{
			{ID: "primary", Role: "primary", Provider: "custom", APIProtocol: "openai_chat", APIURL: primary.URL, ModelName: "primary", MaxRetries: 0},
			{ID: "fallback", Role: "fallback", Provider: "custom", APIProtocol: "openai_chat", APIURL: fallback.URL, ModelName: "fallback", MaxRetries: 0},
		},
		ModelRouting: config.ModelRoutingConfig{FailoverOn: []string{"invalid_output"}},
	}
	result, err := CallLLMWithRetryContext(context.Background(), []Message{{Role: "user", Content: "hi"}}, false, nil)
	if err != nil || result.ModelID != "fallback" || !strings.Contains(result.Content, "fallback-ok") || result.Failovers != 1 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestOpenAICompatibleRetriesWithoutUnsupportedMaxTokens(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var request ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if requests == 1 {
			if request.MaxTokens == 0 {
				t.Fatal("first request should use adaptive max_tokens")
			}
			http.Error(w, `{"error":"unknown parameter max_tokens"}`, http.StatusBadRequest)
			return
		}
		if request.MaxTokens != 0 {
			t.Fatalf("compatibility retry still sent max_tokens=%d", request.MaxTokens)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"action\":\"finish\",\"final_report\":\"ok\"}"}}]}`))
	}))
	defer server.Close()

	_, err := callOpenAICompatible(context.Background(), config.Config{
		ApiURL: server.URL, ModelName: "local-model", ApiKey: "none",
	}, []Message{{Role: "user", Content: "hi"}}, false, nil)
	if err != nil || requests != 2 {
		t.Fatalf("max_tokens compatibility fallback failed: requests=%d err=%v", requests, err)
	}
}

func TestRunAgentStepRetriesWithSmallerHistoryAfterContextLimit(t *testing.T) {
	original := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = original })

	requestSizes := make([]int, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		requestSizes = append(requestSizes, len(request.Messages))
		if len(requestSizes) == 1 {
			http.Error(w, `{"error":{"message":"maximum context length exceeded"}}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"action\":\"finish\",\"final_report\":\"recovered\"}"}}]}`))
	}))
	defer server.Close()

	config.GlobalConfig = config.Config{
		Provider:            "custom",
		APIProtocol:         "openai_chat",
		ApiURL:              server.URL,
		ApiKey:              "none",
		ModelName:           "local-14b",
		ModelParameterB:     14,
		ContextWindowTokens: 32_768,
	}
	history := []Message{{Role: "user", Content: "排查异常登录"}}
	for i := 0; i < 12; i++ {
		history = append(history, Message{Role: "user", Content: fmt.Sprintf("步骤 %d: %s", i, strings.Repeat("evidence ", 30))})
	}
	response, err := RunAgentStepWithOptions(StepOptions{
		Context:        context.Background(),
		SysCtx:         collector.SystemContext{},
		History:        &history,
		UseNativeTools: false,
	})
	if err != nil || response.Action != "finish" || response.FinalReport != "recovered" {
		t.Fatalf("context-limit recovery failed: response=%#v err=%v", response, err)
	}
	if len(requestSizes) != 2 || requestSizes[1] >= requestSizes[0] {
		t.Fatalf("retry did not shrink history: %v", requestSizes)
	}
}

func TestOpenAICompatibleRequestCanBeCancelled(t *testing.T) {
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-releaseHandler:
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	_, err := callOpenAICompatible(ctx, config.Config{
		ApiURL:    server.URL + "/v1/chat/completions",
		ModelName: "test-model",
		ApiKey:    "none",
	}, []Message{{Role: "user", Content: "hi"}}, false, nil)
	close(releaseHandler)
	server.Close()
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("cancelled request err=%v elapsed=%s", err, time.Since(start))
	}
}

func TestReadLimitedResponseBodyRejectsOversize(t *testing.T) {
	body, err := readLimitedResponseBody(strings.NewReader("1234"), 4)
	if err != nil || string(body) != "1234" {
		t.Fatalf("exact limit rejected: body=%q err=%v", body, err)
	}
	if _, err := readLimitedResponseBody(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversized LLM response should be rejected")
	}
}

func TestLLMRetryDelayUsesBoundedJitter(t *testing.T) {
	if got := llmRetryDelay(0); got != 0 {
		t.Fatalf("attempt 0 delay=%s, want 0", got)
	}
	for attempt := 1; attempt <= 4; attempt++ {
		base := time.Duration(attempt*attempt) * time.Second
		got := llmRetryDelay(attempt)
		if got < base || got > base+500*time.Millisecond {
			t.Fatalf("attempt %d delay=%s, want %s..%s", attempt, got, base, base+500*time.Millisecond)
		}
	}
}

func TestEffectiveTemperaturePreservesConfiguredZero(t *testing.T) {
	if got := effectiveTemperature(config.Config{Temperature: 0}); got != 0 {
		t.Fatalf("temperature 0 became %v", got)
	}
	if got := effectiveTemperature(config.Config{Temperature: 0.35}); got != 0.35 {
		t.Fatalf("temperature 0.35 became %v", got)
	}
}
