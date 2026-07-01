package analyzer

import (
	"net/http"
	"net/http/httptest"
	"testing"

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

	result, err := callOpenAICompatible(config.Config{
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
