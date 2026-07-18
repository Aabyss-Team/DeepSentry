package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ValidateRuntimeConfig rejects ambiguous or unsupported runtime state before
// it can reach an executor. Zero-valued tuning fields retain their documented
// auto/default semantics.
func ValidateRuntimeConfig(cfg Config) error {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		return fmt.Errorf("provider 不能为空")
	}
	if provider != string(ProviderCustom) {
		if _, ok := FindProvider(provider); !ok {
			return fmt.Errorf("未知 provider %q；自定义兼容接口请使用 provider=custom", cfg.Provider)
		}
	}
	protocol := strings.ToLower(strings.TrimSpace(cfg.EffectiveAPIProtocol()))
	switch protocol {
	case ProtocolOpenAIChat, ProtocolAnthropicMessages, ProtocolOpenAIResponses:
	default:
		return fmt.Errorf("api_protocol=%q 无效；可选 auto|%s|%s|%s", cfg.APIProtocol, ProtocolOpenAIChat, ProtocolAnthropicMessages, ProtocolOpenAIResponses)
	}
	if strings.TrimSpace(cfg.ModelName) == "" {
		return fmt.Errorf("model_name 不能为空")
	}
	if err := validateHTTPURL("api_url", cfg.ApiURL); err != nil {
		return err
	}
	profile := strings.ToLower(strings.TrimSpace(cfg.ModelProfile))
	if profile != "" && profile != "auto" && profile != ModelProfileCompact && profile != ModelProfileBalanced && profile != ModelProfileFull {
		return fmt.Errorf("model_profile=%q 无效；可选 auto|compact|balanced|full", cfg.ModelProfile)
	}
	if cfg.ModelParameterB < 0 {
		return fmt.Errorf("model_parameter_b 不能为负数")
	}
	if cfg.ContextWindowTokens != 0 && (cfg.ContextWindowTokens < 4_096 || cfg.ContextWindowTokens > 4_194_304) {
		return fmt.Errorf("context_window_tokens 必须为 0(auto) 或 4096~4194304")
	}
	if cfg.ContextUtilization != 0 && (cfg.ContextUtilization < 0.40 || cfg.ContextUtilization > 0.90) {
		return fmt.Errorf("context_utilization 必须为 0(auto) 或 0.40~0.90")
	}
	if cfg.ReservedOutputTokens < 0 || cfg.NativeToolLimit < 0 {
		return fmt.Errorf("reserved_output_tokens/native_tool_limit 不能为负数")
	}
	if cfg.ContextWindowTokens > 0 && cfg.ReservedOutputTokens >= cfg.ContextWindowTokens {
		return fmt.Errorf("reserved_output_tokens 必须小于 context_window_tokens")
	}
	if cfg.LLMTimeoutSec < 0 || cfg.LLMRetries < 0 || cfg.SSHCommandTimeoutSec < 0 || cfg.SSHMaxOutputBytes < 0 || cfg.MaxSteps < 0 || cfg.SubAgentMaxSteps < 0 {
		return fmt.Errorf("timeout/retries/output/max_steps 配置不能为负数")
	}
	if cfg.LLMRetries > 10 {
		return fmt.Errorf("llm_retries 最大为 10")
	}
	if cfg.MaxSteps > 1_000 || cfg.SubAgentMaxSteps > 200 {
		return fmt.Errorf("max_steps 最大 1000，subagent_max_steps 最大 200")
	}

	targetProtocol := strings.ToLower(strings.TrimSpace(cfg.TargetProtocol))
	switch targetProtocol {
	case "", "local", "ssh", "telnet", "ftp":
	default:
		return fmt.Errorf("target_protocol=%q 无效；可选 local|ssh|telnet|ftp", cfg.TargetProtocol)
	}
	policy := strings.ToLower(strings.TrimSpace(cfg.SSHHostKeyPolicy))
	switch policy {
	case "strict", "accept-new", "insecure":
	default:
		return fmt.Errorf("ssh_host_key_policy=%q 无效；可选 strict|accept-new|insecure", cfg.SSHHostKeyPolicy)
	}
	if policy != "insecure" && strings.TrimSpace(cfg.SSHKnownHostsPath) == "" {
		return fmt.Errorf("ssh_known_hosts_path 不能为空")
	}
	if cfg.ArchiveMaxEntries < 0 || cfg.ArchiveMaxFileBytes < 0 || cfg.ArchiveMaxTotalBytes < 0 {
		return fmt.Errorf("archive 安全上限不能为负数")
	}
	if cfg.ArchiveMaxFileBytes > 0 && cfg.ArchiveMaxTotalBytes > 0 && cfg.ArchiveMaxFileBytes > cfg.ArchiveMaxTotalBytes {
		return fmt.Errorf("archive_max_file_bytes 不能大于 archive_max_total_bytes")
	}
	if raw := strings.TrimSpace(cfg.ControllerProxy); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return fmt.Errorf("controller_proxy URL 无效")
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "socks5", "socks5h":
		default:
			return fmt.Errorf("controller_proxy 仅支持 http|https|socks5|socks5h")
		}
	}
	if tz := strings.TrimSpace(cfg.SchedulerTimezone); tz != "" && !strings.EqualFold(tz, "local") {
		if _, err := time.LoadLocation(tz); err != nil {
			return fmt.Errorf("scheduler_timezone=%q 无效: %w", tz, err)
		}
	}
	if err := validateTargets(cfg.Targets); err != nil {
		return err
	}
	if err := validateMCPServers(cfg.MCPServerConfigs); err != nil {
		return err
	}
	return nil
}

func validateHTTPURL(name, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s 必须是有效的 HTTP(S) URL", name)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s 仅支持 http/https", name)
	}
	return nil
}

func validateTargets(targets []TargetConfig) error {
	seen := make(map[string]bool, len(targets))
	for i, target := range targets {
		protocol := strings.ToLower(strings.TrimSpace(target.Protocol))
		switch protocol {
		case "ssh", "telnet", "ftp":
		default:
			return fmt.Errorf("targets[%d].protocol=%q 无效", i, target.Protocol)
		}
		if strings.TrimSpace(target.Host) == "" {
			return fmt.Errorf("targets[%d].host 不能为空", i)
		}
		identity := strings.ToLower(strings.TrimSpace(target.Name))
		if identity == "" {
			identity = protocol + ":" + strings.ToLower(strings.TrimSpace(target.Host))
		}
		if seen[identity] {
			return fmt.Errorf("targets 存在重复目标 %q", identity)
		}
		seen[identity] = true
	}
	return nil
}

func validateMCPServers(servers []MCPServerConfig) error {
	seen := make(map[string]bool, len(servers))
	for i, server := range servers {
		if server.Disabled {
			continue
		}
		name := strings.TrimSpace(server.Name)
		if name == "" {
			return fmt.Errorf("mcp_server_configs[%d].name 不能为空", i)
		}
		if seen[name] {
			return fmt.Errorf("mcp_server_configs 存在重复 name %q", name)
		}
		seen[name] = true
		serverType := strings.ToLower(strings.TrimSpace(server.Type))
		if serverType == "" {
			serverType = "stdio"
		}
		switch serverType {
		case "stdio":
			if strings.TrimSpace(server.Command) == "" {
				return fmt.Errorf("mcp_server_configs[%d].command 不能为空", i)
			}
		case "http", "streamable_http":
			parsed, err := url.Parse(strings.TrimSpace(server.URL))
			if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()))) {
				return fmt.Errorf("mcp_server_configs[%d].url 必须使用 HTTPS；仅 localhost/回环地址允许 HTTP", i)
			}
		default:
			return fmt.Errorf("mcp_server_configs[%d].type=%q 暂不支持；可用 stdio/http/streamable_http", i, server.Type)
		}
		if server.StartupTimeoutSec < 0 || server.StartupTimeoutSec > 300 || server.ToolTimeoutSec < 0 || server.ToolTimeoutSec > 3600 {
			return fmt.Errorf("mcp_server_configs[%d] timeout 超出允许范围", i)
		}
		if tokenEnv := strings.TrimSpace(server.BearerTokenEnvVar); tokenEnv != "" && !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(tokenEnv) {
			return fmt.Errorf("mcp_server_configs[%d].bearer_token_env_var 不是合法环境变量名", i)
		}
		for key, value := range server.Headers {
			if strings.TrimSpace(key) == "" || strings.ContainsAny(key+value, "\r\n") {
				return fmt.Errorf("mcp_server_configs[%d].headers 包含无效请求头", i)
			}
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
