package config

import "strings"

// Provider 预设 LLM 厂商
type Provider string

const (
	ProviderOpenAI     Provider = "openai"
	ProviderAnthropic  Provider = "anthropic"
	ProviderGoogle     Provider = "google"
	ProviderDeepSeek   Provider = "deepseek"
	ProviderQwen       Provider = "qwen"
	ProviderQianfan    Provider = "qianfan"
	ProviderVolcengine Provider = "volcengine"
	ProviderMiniMax    Provider = "minimax"
	ProviderMimo       Provider = "mimo"
	ProviderGLM        Provider = "glm"
	ProviderHunyuan    Provider = "hunyuan"
	ProviderTencentHY  Provider = "tencent_hy"
	ProviderTeleAI     Provider = "teleai"
	ProviderCTYun      Provider = "ctyun"
	ProviderOllama     Provider = "ollama"
	ProviderLMStudio   Provider = "lmstudio"
	ProviderXAI        Provider = "xai"
	ProviderGrok       Provider = "grok"
	ProviderCustom     Provider = "custom"
)

const (
	ProtocolAuto              = "auto"
	ProtocolOpenAIChat        = "openai_chat"
	ProtocolAnthropicMessages = "anthropic_messages"
	ProtocolOpenAIResponses   = "openai_responses"
)

// ProviderPreset 厂商默认 endpoint 与模型
type ProviderPreset struct {
	ID          Provider
	DisplayName string
	APIURL      string
	Model       string
	AuthStyle   string // bearer | x-api-key
	Protocol    string
	NativeTools bool
}

// AllProviders contains convenience API/model presets. They are compatibility
// defaults rather than a promise that a provider still labels them "latest";
// operators can always override endpoint and model in config.
var AllProviders = []ProviderPreset{
	{
		ID: ProviderOpenAI, DisplayName: "OpenAI",
		APIURL: "https://api.openai.com/v1", Model: "gpt-5.5",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderAnthropic, DisplayName: "Anthropic Claude",
		APIURL: "https://api.anthropic.com/v1", Model: "claude-opus-4-8",
		AuthStyle: "x-api-key", Protocol: ProtocolAnthropicMessages, NativeTools: false,
	},
	{
		ID: ProviderGoogle, DisplayName: "Google Gemini",
		APIURL: "https://generativelanguage.googleapis.com/v1beta/openai", Model: "gemini-3.5-flash",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderDeepSeek, DisplayName: "DeepSeek",
		APIURL: "https://api.deepseek.com/v1", Model: "deepseek-v4-pro",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderQwen, DisplayName: "Alibaba Qwen / DashScope",
		APIURL: "https://dashscope.aliyuncs.com/compatible-mode/v1", Model: "qwen-plus",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderQianfan, DisplayName: "百度千帆 Coding Plan",
		APIURL: "https://qianfan.baidubce.com/v2/coding", Model: "qianfan-code-latest",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderVolcengine, DisplayName: "火山方舟 Coding Plan",
		APIURL: "https://ark.cn-beijing.volces.com/api/coding/v3", Model: "ark-code-latest",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderMiniMax, DisplayName: "MiniMax",
		APIURL: "https://api.minimax.chat/v1", Model: "MiniMax-M3",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderMimo, DisplayName: "Xiaomi MiMo Token Plan / MiMo Claw",
		APIURL: "https://token-plan-cn.xiaomimimo.com/v1", Model: "mimo-v2.5-pro",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderGLM, DisplayName: "智谱 GLM",
		APIURL: "https://open.bigmodel.cn/api/paas/v4", Model: "glm-5.2",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderHunyuan, DisplayName: "腾讯混元 Hunyuan",
		APIURL: "https://api.hunyuan.cloud.tencent.com/v1", Model: "hunyuan-turbos-latest",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderTencentHY, DisplayName: "Tencent HY (alias)",
		APIURL: "https://api.hunyuan.cloud.tencent.com/v1", Model: "hunyuan-turbos-latest",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderTeleAI, DisplayName: "中国电信星辰 / TeleAI",
		APIURL: "https://wishub-x6.ctyun.cn/coding/v1", Model: "GLM-5-Pro",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderCTYun, DisplayName: "天翼云息壤 TokenHub (alias)",
		APIURL: "https://wishub-x6.ctyun.cn/coding/v1", Model: "GLM-5-Pro",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderOllama, DisplayName: "Ollama (本地)",
		APIURL: "http://localhost:11434/v1", Model: "llama3.3",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: false,
	},
	{
		ID: ProviderLMStudio, DisplayName: "LM Studio (本地)",
		APIURL: "http://localhost:1234/v1", Model: "local-model",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: false,
	},
	{
		ID: ProviderXAI, DisplayName: "xAI Grok",
		APIURL: "https://api.x.ai/v1", Model: "grok-4",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
	{
		ID: ProviderGrok, DisplayName: "Grok (alias)",
		APIURL: "https://api.x.ai/v1", Model: "grok-4",
		AuthStyle: "bearer", Protocol: ProtocolOpenAIChat, NativeTools: true,
	},
}

// FindProvider 按 ID 查找预设
func FindProvider(id string) (ProviderPreset, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, p := range AllProviders {
		if string(p.ID) == id {
			return p, true
		}
	}
	return ProviderPreset{}, false
}

// ApplyProviderDefaults 根据 provider 填充空的 api_url / model_name
func ApplyProviderDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	p := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if p == "" || p == string(ProviderCustom) {
		if strings.TrimSpace(cfg.APIProtocol) == "" || strings.EqualFold(cfg.APIProtocol, ProtocolAuto) {
			if strings.Contains(cfg.ApiURL, "anthropic.com") {
				cfg.APIProtocol = ProtocolAnthropicMessages
			} else if strings.Contains(cfg.ApiURL, "/responses") {
				cfg.APIProtocol = ProtocolOpenAIResponses
			} else {
				cfg.APIProtocol = ProtocolOpenAIChat
			}
		}
		cfg.ApiURL = NormalizeChatURL(cfg.ApiURL)
		return
	}
	preset, ok := FindProvider(p)
	if !ok {
		cfg.ApiURL = NormalizeChatURL(cfg.ApiURL)
		return
	}
	if strings.TrimSpace(cfg.ApiURL) == "" {
		cfg.ApiURL = preset.APIURL
	}
	if strings.TrimSpace(cfg.ModelName) == "" {
		cfg.ModelName = preset.Model
	}
	if strings.TrimSpace(cfg.APIProtocol) == "" || strings.EqualFold(cfg.APIProtocol, ProtocolAuto) {
		cfg.APIProtocol = preset.Protocol
	}
	cfg.ApiURL = NormalizeChatURL(cfg.ApiURL)
}

// NormalizeChatURL 将 base URL 规范为 chat/completions 端点
func NormalizeChatURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	raw = strings.TrimRight(raw, "/")
	if strings.HasSuffix(raw, "/chat/completions") {
		return raw
	}
	if strings.HasSuffix(raw, "/responses") {
		return raw
	}
	// Anthropic 使用 /v1/messages
	if strings.Contains(raw, "anthropic.com") {
		if strings.HasSuffix(raw, "/v1") {
			return raw + "/messages"
		}
		return raw
	}
	if strings.HasSuffix(raw, "/v1") {
		return raw + "/chat/completions"
	}
	if strings.HasSuffix(raw, "/v4") {
		// 智谱 v4
		return raw + "/chat/completions"
	}
	if !strings.Contains(raw, "chat/completions") && !strings.Contains(raw, "/messages") && !strings.Contains(raw, "/responses") {
		return raw + "/chat/completions"
	}
	return raw
}

// IsAnthropic 是否 Anthropic API
func (c *Config) IsAnthropic() bool {
	if strings.EqualFold(c.APIProtocol, ProtocolAnthropicMessages) {
		return true
	}
	p := strings.ToLower(c.Provider)
	return p == string(ProviderAnthropic) || strings.Contains(c.ApiURL, "anthropic.com")
}

// IsOpenAICompatible 是否 OpenAI 兼容 Chat Completions
func (c *Config) IsOpenAICompatible() bool {
	return !c.IsAnthropic() && !strings.EqualFold(c.APIProtocol, ProtocolOpenAIResponses)
}

func (c *Config) IsOpenAIResponses() bool {
	return strings.EqualFold(c.APIProtocol, ProtocolOpenAIResponses) || strings.Contains(c.ApiURL, "/responses")
}

func (c *Config) EffectiveAPIProtocol() string {
	if strings.TrimSpace(c.APIProtocol) == "" {
		if c.IsAnthropic() {
			return ProtocolAnthropicMessages
		}
		if c.IsOpenAIResponses() {
			return ProtocolOpenAIResponses
		}
		return ProtocolOpenAIChat
	}
	return strings.ToLower(strings.TrimSpace(c.APIProtocol))
}

// EffectiveLLMTimeout 单步 LLM 超时秒
func (c *Config) EffectiveLLMTimeout() int {
	if c.LLMTimeoutSec > 0 {
		return c.LLMTimeoutSec
	}
	return 120
}

// EffectiveLLMRetries 重试次数
func (c *Config) EffectiveLLMRetries() int {
	if c.LLMRetries > 0 {
		return c.LLMRetries
	}
	return 3
}

// EffectiveSSHTimeout SSH 单命令超时秒
func (c *Config) EffectiveSSHTimeout() int {
	if c.SSHCommandTimeoutSec > 0 {
		return c.SSHCommandTimeoutSec
	}
	return 90
}

// EffectiveSSHMaxOutputBytes SSH 单命令回传上限（字节）；超出后截断并继续排空管道，不报错
func (c *Config) EffectiveSSHMaxOutputBytes() int {
	if c.SSHMaxOutputBytes > 0 {
		return c.SSHMaxOutputBytes
	}
	return 512 * 1024
}
