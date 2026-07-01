package config

import "testing"

func TestNormalizeChatURL(t *testing.T) {
	cases := map[string]string{
		"https://token-plan-cn.xiaomimimo.com/v1":           "https://token-plan-cn.xiaomimimo.com/v1/chat/completions",
		"https://api.deepseek.com/v1/chat/completions":      "https://api.deepseek.com/v1/chat/completions",
		"https://api.anthropic.com/v1":                      "https://api.anthropic.com/v1/messages",
		"https://dashscope.aliyuncs.com/compatible-mode/v1": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
		"https://api.hunyuan.cloud.tencent.com/v1":          "https://api.hunyuan.cloud.tencent.com/v1/chat/completions",
	}
	for in, want := range cases {
		got := NormalizeChatURL(in)
		if got != want {
			t.Fatalf("%s => %s, want %s", in, got, want)
		}
	}
}

func TestApplyProviderDefaultsMimo(t *testing.T) {
	cfg := &Config{Provider: "mimo", ApiURL: "", ModelName: ""}
	ApplyProviderDefaults(cfg)
	if cfg.ModelName == "" {
		t.Fatal("expected default model")
	}
	if !contains(cfg.ApiURL, "chat/completions") && !contains(cfg.ApiURL, "xiaomimimo") {
		t.Fatalf("unexpected url: %s", cfg.ApiURL)
	}
}

func TestProviderDefaultsChineseOpenAICompatible(t *testing.T) {
	cases := []struct {
		provider string
		urlPart  string
		model    string
	}{
		{"qwen", "dashscope.aliyuncs.com", "qwen-plus"},
		{"hunyuan", "hunyuan.cloud.tencent.com", "hunyuan-turbos-latest"},
		{"tencent_hy", "hunyuan.cloud.tencent.com", "hunyuan-turbos-latest"},
		{"teleai", "ctyun.cn", "GLM-5-Pro"},
		{"ctyun", "ctyun.cn", "GLM-5-Pro"},
	}
	for _, tc := range cases {
		cfg := &Config{Provider: tc.provider}
		ApplyProviderDefaults(cfg)
		if !contains(cfg.ApiURL, tc.urlPart) || !contains(cfg.ApiURL, "chat/completions") {
			t.Fatalf("%s unexpected url: %s", tc.provider, cfg.ApiURL)
		}
		if cfg.ModelName != tc.model || cfg.APIProtocol != ProtocolOpenAIChat {
			t.Fatalf("%s unexpected defaults: %+v", tc.provider, cfg)
		}
	}
}

func TestProviderDefaultsXAIAndLMStudio(t *testing.T) {
	xai := &Config{Provider: "xai"}
	ApplyProviderDefaults(xai)
	if xai.ModelName == "" || !contains(xai.ApiURL, "api.x.ai") || xai.APIProtocol != ProtocolOpenAIChat {
		t.Fatalf("unexpected xai defaults: %+v", xai)
	}

	lm := &Config{Provider: "lmstudio"}
	ApplyProviderDefaults(lm)
	if !contains(lm.ApiURL, "localhost:1234") || lm.APIProtocol != ProtocolOpenAIChat {
		t.Fatalf("unexpected lmstudio defaults: %+v", lm)
	}
}

func TestResponsesURLPreserved(t *testing.T) {
	in := "https://api.openai.com/v1/responses"
	if got := NormalizeChatURL(in); got != in {
		t.Fatalf("responses url changed: %s", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
