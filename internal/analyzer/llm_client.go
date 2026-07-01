package analyzer

import (
	"ai-edr/internal/config"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LLMResult LLM 调用结果
type LLMResult struct {
	Content      string
	ToolCallArgs string
	Usage        TokenUsage
}

type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens,omitempty"`
	CompletionTokens int `json:"completion_tokens,omitempty"`
	TotalTokens      int `json:"total_tokens,omitempty"`
}

func (u TokenUsage) HasAny() bool {
	return u.PromptTokens > 0 || u.CompletionTokens > 0 || u.TotalTokens > 0
}

// CallLLMWithRetry 带重试与降级的统一 LLM 调用；onStream 非 nil 时在 OpenAI 兼容 JSON 模式下启用 SSE 流式
func CallLLMWithRetry(messages []Message, useNativeTools bool, onStream func(string)) (LLMResult, error) {
	cfg := config.GlobalConfig
	retries := cfg.EffectiveLLMRetries()
	var lastErr error

	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * time.Second)
		}

		native := useNativeTools && cfg.IsOpenAICompatible()
		var result LLMResult
		var err error

		// TUI 等场景：有 onStream 时优先 JSON + SSE 流式
		if onStream != nil && cfg.IsOpenAICompatible() {
			result, err = callOpenAICompatible(cfg, messages, false, onStream)
			if err != nil && isStreamUnsupported(err) {
				result, err = callOpenAICompatible(cfg, messages, false, nil)
			}
		} else if cfg.IsAnthropic() {
			result, err = callAnthropic(cfg, messages)
		} else if cfg.IsOpenAIResponses() {
			result, err = callOpenAIResponses(cfg, messages)
		} else if native {
			result, err = callOpenAICompatible(cfg, messages, true, nil)
			if err != nil && isToolsUnsupported(err) {
				result, err = callOpenAICompatible(cfg, messages, false, onStream)
			}
		} else {
			result, err = callOpenAICompatible(cfg, messages, false, nil)
		}

		if err == nil {
			return result, nil
		}
		lastErr = err
		if !isRetryable(err) {
			break
		}
	}
	return LLMResult{}, fmt.Errorf("LLM 调用失败(已重试 %d 次): %w", retries, lastErr)
}

type responsesRequest struct {
	Model       string  `json:"model"`
	Input       string  `json:"input"`
	Temperature float64 `json:"temperature,omitempty"`
}

type responsesResponse struct {
	OutputText string `json:"output_text"`
	Output     []struct {
		Type    string `json:"type"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
		TotalTokens  int `json:"total_tokens"`
	} `json:"usage"`
}

func callOpenAIResponses(cfg config.Config, messages []Message) (LLMResult, error) {
	url := strings.TrimRight(cfg.ApiURL, "/")
	if !strings.HasSuffix(url, "/responses") {
		if strings.HasSuffix(url, "/v1") {
			url += "/responses"
		} else {
			url += "/v1/responses"
		}
	}
	reqBody := responsesRequest{
		Model:       cfg.ModelName,
		Input:       messagesToTranscript(messages),
		Temperature: effectiveTemperature(cfg),
	}
	body, status, err := doHTTPPost(url, cfg, reqBody)
	if err != nil {
		return LLMResult{}, err
	}
	if status != 200 {
		return LLMResult{}, fmt.Errorf("Responses API Error %d: %s", status, truncateStr(string(body), 500))
	}
	var rr responsesResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return LLMResult{}, err
	}
	if rr.Error != nil {
		return LLMResult{}, errors.New(rr.Error.Message)
	}
	usage := TokenUsage{
		PromptTokens:     rr.Usage.InputTokens,
		CompletionTokens: rr.Usage.OutputTokens,
		TotalTokens:      rr.Usage.TotalTokens,
	}
	if strings.TrimSpace(rr.OutputText) != "" {
		return LLMResult{Content: rr.OutputText, Usage: usage}, nil
	}
	var b strings.Builder
	for _, out := range rr.Output {
		for _, c := range out.Content {
			if c.Text != "" {
				b.WriteString(c.Text)
			}
		}
	}
	if b.Len() == 0 {
		return LLMResult{}, errors.New("empty responses output")
	}
	return LLMResult{Content: b.String(), Usage: usage}, nil
}

func messagesToTranscript(messages []Message) string {
	var b strings.Builder
	for _, m := range messages {
		role := strings.ToUpper(strings.TrimSpace(m.Role))
		if role == "" {
			role = "USER"
		}
		b.WriteString(role)
		b.WriteString(":\n")
		b.WriteString(m.Content)
		b.WriteString("\n\n")
	}
	return b.String()
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, code := range []string{"429", "500", "502", "503", "504", "timeout", "connection reset", "eof"} {
		if strings.Contains(s, code) {
			return true
		}
	}
	return false
}

func isToolsUnsupported(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "tool") || strings.Contains(s, "400") || strings.Contains(s, "404")
}

func isStreamUnsupported(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "stream") || strings.Contains(s, "400") ||
		strings.Contains(s, "404") || strings.Contains(s, "not support")
}

func isStreamOptionsUnsupported(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "stream_options") ||
		strings.Contains(s, "include_usage") ||
		strings.Contains(s, "unknown parameter") ||
		strings.Contains(s, "unrecognized") ||
		strings.Contains(s, "unsupported parameter")
}

func callOpenAICompatible(cfg config.Config, messages []Message, withTools bool, onStream func(string)) (LLMResult, error) {
	url := config.NormalizeChatURL(cfg.ApiURL)
	useStream := onStream != nil && !withTools
	reqBody := ChatRequest{
		Model:       cfg.ModelName,
		Messages:    messages,
		Stream:      useStream,
		Temperature: effectiveTemperature(cfg),
	}
	if withTools {
		reqBody.Tools = AgentToolDefinitions()
		reqBody.ToolChoice = map[string]interface{}{
			"type":     "function",
			"function": map[string]string{"name": "agent_action"},
		}
	}

	if useStream {
		reqBody.StreamOptions = &StreamOptions{IncludeUsage: true}
		result, err := callOpenAICompatibleStream(url, cfg, reqBody, onStream)
		if err != nil && isStreamOptionsUnsupported(err) {
			reqBody.StreamOptions = nil
			return callOpenAICompatibleStream(url, cfg, reqBody, onStream)
		}
		return result, err
	}

	body, status, err := doHTTPPost(url, cfg, reqBody)
	if err != nil {
		return LLMResult{}, err
	}
	if status != 200 {
		return LLMResult{}, fmt.Errorf("API Error %d: %s", status, truncateStr(string(body), 500))
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return LLMResult{}, fmt.Errorf("parse error: %w", err)
	}
	if len(chatResp.Choices) == 0 {
		return LLMResult{}, errors.New("empty response")
	}
	msg := chatResp.Choices[0].Message
	if len(msg.ToolCalls) > 0 {
		return LLMResult{Content: msg.Content, ToolCallArgs: msg.ToolCalls[0].Function.Arguments, Usage: chatResp.Usage}, nil
	}
	return LLMResult{Content: msg.Content, Usage: chatResp.Usage}, nil
}

type streamChunk struct {
	Choices []struct {
		Delta struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Index    int `json:"index"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage TokenUsage `json:"usage"`
}

func callOpenAICompatibleStream(url string, cfg config.Config, reqBody ChatRequest, onStream func(string)) (LLMResult, error) {
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return LLMResult{}, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return LLMResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if cfg.ApiKey != "" && cfg.ApiKey != "none" {
		req.Header.Set("Authorization", "Bearer "+cfg.ApiKey)
	}
	client := config.HTTPClient(time.Duration(cfg.EffectiveLLMTimeout()) * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return LLMResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return LLMResult{}, fmt.Errorf("API Error %d: %s", resp.StatusCode, truncateStr(string(body), 500))
	}

	var content strings.Builder
	var usage TokenUsage
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			break
		}
		var chunk streamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		if chunk.Usage.HasAny() {
			usage = chunk.Usage
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		delta := chunk.Choices[0].Delta.Content
		if delta == "" {
			continue
		}
		content.WriteString(delta)
		onStream(delta)
	}
	if err := scanner.Err(); err != nil {
		return LLMResult{}, fmt.Errorf("stream read error: %w", err)
	}
	if content.Len() == 0 {
		return LLMResult{}, errors.New("empty stream response")
	}
	return LLMResult{Content: content.String(), Usage: usage}, nil
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func callAnthropic(cfg config.Config, messages []Message) (LLMResult, error) {
	url := config.NormalizeChatURL(cfg.ApiURL)
	var system strings.Builder
	var msgs []anthropicMessage
	for _, m := range messages {
		switch m.Role {
		case "system":
			system.WriteString(m.Content)
			system.WriteString("\n")
		case "user", "assistant":
			msgs = append(msgs, anthropicMessage{Role: m.Role, Content: m.Content})
		}
	}
	if len(msgs) == 0 {
		msgs = append(msgs, anthropicMessage{Role: "user", Content: "continue"})
	}

	reqBody := anthropicRequest{
		Model:     cfg.ModelName,
		MaxTokens: 8192,
		System:    strings.TrimSpace(system.String()),
		Messages:  msgs,
	}

	raw, err := json.Marshal(reqBody)
	if err != nil {
		return LLMResult{}, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(raw))
	if err != nil {
		return LLMResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", cfg.ApiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := config.HTTPClient(time.Duration(cfg.EffectiveLLMTimeout()) * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return LLMResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return LLMResult{}, fmt.Errorf("Anthropic API %d: %s", resp.StatusCode, truncateStr(string(body), 500))
	}

	var ar anthropicResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return LLMResult{}, err
	}
	if ar.Error != nil {
		return LLMResult{}, errors.New(ar.Error.Message)
	}
	var text strings.Builder
	for _, c := range ar.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}
	usage := TokenUsage{
		PromptTokens:     ar.Usage.InputTokens,
		CompletionTokens: ar.Usage.OutputTokens,
		TotalTokens:      ar.Usage.InputTokens + ar.Usage.OutputTokens,
	}
	return LLMResult{Content: text.String(), Usage: usage}, nil
}

func doHTTPPost(url string, cfg config.Config, payload interface{}) ([]byte, int, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.ApiKey != "" && cfg.ApiKey != "none" {
		req.Header.Set("Authorization", "Bearer "+cfg.ApiKey)
	}
	client := config.HTTPClient(time.Duration(cfg.EffectiveLLMTimeout()) * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func effectiveTemperature(cfg config.Config) float64 {
	if cfg.Temperature > 0 {
		return cfg.Temperature
	}
	return 0.1
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// TruncateHistoryFallback 摘要失败时的机械截断
func TruncateHistoryFallback(history *[]Message, keepRecent int) {
	if history == nil || keepRecent <= 0 {
		return
	}
	h := *history
	if len(h) <= keepRecent+2 {
		return
	}
	trimmed := h[len(h)-keepRecent:]
	*history = append([]Message{{
		Role:    "system",
		Content: fmt.Sprintf("【前情提要】(机械截断，保留最近 %d 轮)\n较早对话已省略。", keepRecent),
	}}, trimmed...)
}
