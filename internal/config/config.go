package config

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

// GlobalConfig 全局配置实例，供其他模块读取
var GlobalConfig Config

func setViperDefaults() {
	viper.SetDefault("provider", "deepseek")
	viper.SetDefault("api_protocol", "auto")
	viper.SetDefault("api_url", "https://api.deepseek.com/v1")
	viper.SetDefault("model_name", "deepseek-v4-pro")
	viper.SetDefault("temperature", 0.0)
	viper.SetDefault("model_profile", "auto")
	viper.SetDefault("model_parameter_b", 0.0)
	viper.SetDefault("context_window_tokens", 0)
	viper.SetDefault("context_utilization", 0.0)
	viper.SetDefault("reserved_output_tokens", 0)
	viper.SetDefault("native_tool_limit", 0)
	viper.SetDefault("ssh_user", "root")
	viper.SetDefault("ssh_host_key_policy", "accept-new")
	viper.SetDefault("ssh_known_hosts_path", "~/.deepsentry/known_hosts")
	viper.SetDefault("telnet_user", "root")
	viper.SetDefault("ftp_user", "anonymous")
	viper.SetDefault("use_native_tools", true)
	viper.SetDefault("llm_timeout_sec", 120)
	viper.SetDefault("llm_retries", 3)
	viper.SetDefault("ssh_command_timeout_sec", 90)
	viper.SetDefault("ssh_max_output_bytes", 512*1024)
	viper.SetDefault("max_steps", 30)
	viper.SetDefault("subagent_max_steps", 15)
	viper.SetDefault("controller_proxy", "")
	viper.SetDefault("browser_timeout_sec", 20)
	viper.SetDefault("browser_artifact_dir", "reports/browser")
	viper.SetDefault("archive_max_entries", 10_000)
	viper.SetDefault("archive_max_file_bytes", int64(512*1024*1024))
	viper.SetDefault("archive_max_total_bytes", int64(2*1024*1024*1024))
	viper.SetDefault("scheduler_enabled", true)
	viper.SetDefault("scheduler_store", "reports/schedules/tasks.json")
	viper.SetDefault("scheduler_interval_sec", 30)
	viper.SetDefault("scheduler_timezone", "Local")
	viper.SetDefault("dingtalk_webhook", "")
	viper.SetDefault("dingtalk_secret", "")
	viper.SetDefault("feishu_webhook", "")
	viper.SetDefault("feishu_secret", "")
	viper.SetDefault("email_gateway_url", "")
	viper.SetDefault("email_gateway_token", "")
	viper.SetDefault("email_gateway_header", "Authorization")
	viper.SetDefault("email_to", "")
	viper.SetDefault("email_from", "")
	viper.SetDefault("benchmark_base_url", "")
	viper.SetDefault("benchmark_token", "")
}

// Config 结构体定义
type Config struct {
	// --- LLM 配置 ---
	Provider    string  `mapstructure:"provider"`     // openai|anthropic|google|deepseek|qwen|hunyuan|teleai|minimax|mimo|glm|custom
	APIProtocol string  `mapstructure:"api_protocol"` // openai_chat|anthropic_messages|openai_responses|auto
	ApiURL      string  `mapstructure:"api_url"`
	ModelName   string  `mapstructure:"model_name"`
	ApiKey      string  `mapstructure:"api_key"`
	Temperature float64 `mapstructure:"temperature"`

	// --- Model capability / context adaptation ---
	// Zero values use conservative auto-detection. Local runtimes should set
	// context_window_tokens to their actual num_ctx/max_model_len for best use.
	ModelProfile         string  `mapstructure:"model_profile"` // auto|compact|balanced|full
	ModelParameterB      float64 `mapstructure:"model_parameter_b"`
	ContextWindowTokens  int     `mapstructure:"context_window_tokens"`
	ContextUtilization   float64 `mapstructure:"context_utilization"`
	ReservedOutputTokens int     `mapstructure:"reserved_output_tokens"`
	NativeToolLimit      int     `mapstructure:"native_tool_limit"`

	LLMTimeoutSec        int `mapstructure:"llm_timeout_sec"`
	LLMRetries           int `mapstructure:"llm_retries"`
	SSHCommandTimeoutSec int `mapstructure:"ssh_command_timeout_sec"`
	SSHMaxOutputBytes    int `mapstructure:"ssh_max_output_bytes"`
	MaxSteps             int `mapstructure:"max_steps"`
	SubAgentMaxSteps     int `mapstructure:"subagent_max_steps"`

	// --- SSH 配置 ---
	TargetProtocol    string         `mapstructure:"target_protocol"` // local|ssh|telnet|ftp，空值兼容旧 ssh_host
	SSHHost           string         `mapstructure:"ssh_host"`
	SSHUser           string         `mapstructure:"ssh_user"`
	SSHPassword       string         `mapstructure:"ssh_password"`
	SSHKeyPath        string         `mapstructure:"ssh_key_path"`
	SSHHostKeyPolicy  string         `mapstructure:"ssh_host_key_policy"` // strict|accept-new|insecure
	SSHKnownHostsPath string         `mapstructure:"ssh_known_hosts_path"`
	TelnetHost        string         `mapstructure:"telnet_host"`
	TelnetUser        string         `mapstructure:"telnet_user"`
	TelnetPassword    string         `mapstructure:"telnet_password"`
	TelnetPrompt      string         `mapstructure:"telnet_prompt"`
	FTPHost           string         `mapstructure:"ftp_host"`
	FTPUser           string         `mapstructure:"ftp_user"`
	FTPPassword       string         `mapstructure:"ftp_password"`
	Targets           []TargetConfig `mapstructure:"targets"`

	// --- Deep Agent Harness ---
	UseNativeTools       bool              `mapstructure:"use_native_tools"`
	EnabledTools         []string          `mapstructure:"enabled_tools"`
	DisabledTools        []string          `mapstructure:"disabled_tools"`
	SkillSources         []string          `mapstructure:"skill_sources"`
	DisabledSkillSources []string          `mapstructure:"disabled_skill_sources"`
	DisabledSkills       []string          `mapstructure:"disabled_skills"`
	SkillsDisabled       bool              `mapstructure:"skills_disabled"`
	MCPServers           []string          `mapstructure:"mcp_servers"`
	MCPServerConfigs     []MCPServerConfig `mapstructure:"mcp_server_configs"`

	// --- Controller browser runtime ---
	ControllerProxy      string `mapstructure:"controller_proxy"`
	BrowserBinary        string `mapstructure:"browser_binary"`
	BrowserTimeoutSec    int    `mapstructure:"browser_timeout_sec"`
	BrowserArtifactDir   string `mapstructure:"browser_artifact_dir"`
	ArchiveMaxEntries    int    `mapstructure:"archive_max_entries"`
	ArchiveMaxFileBytes  int64  `mapstructure:"archive_max_file_bytes"`
	ArchiveMaxTotalBytes int64  `mapstructure:"archive_max_total_bytes"`

	// --- Controller scheduler / notifications ---
	SchedulerEnabled     bool   `mapstructure:"scheduler_enabled"`
	SchedulerStore       string `mapstructure:"scheduler_store"`
	SchedulerIntervalSec int    `mapstructure:"scheduler_interval_sec"`
	SchedulerTimezone    string `mapstructure:"scheduler_timezone"`
	DingTalkWebhook      string `mapstructure:"dingtalk_webhook"`
	DingTalkSecret       string `mapstructure:"dingtalk_secret"`
	FeishuWebhook        string `mapstructure:"feishu_webhook"`
	FeishuSecret         string `mapstructure:"feishu_secret"`
	EmailGatewayURL      string `mapstructure:"email_gateway_url"`
	EmailGatewayToken    string `mapstructure:"email_gateway_token"`
	EmailGatewayHeader   string `mapstructure:"email_gateway_header"`
	EmailTo              string `mapstructure:"email_to"`
	EmailFrom            string `mapstructure:"email_from"`

	// --- Benchmark platform integrations ---
	BenchmarkBaseURL string `mapstructure:"benchmark_base_url"`
	BenchmarkToken   string `mapstructure:"benchmark_token"`
}

// EffectiveDisabledSkills returns the name denylist consumed by the live
// catalog. "*" is an internal sentinel for the global /skill off switch.
func (c Config) EffectiveDisabledSkills() []string {
	out := append([]string(nil), c.DisabledSkills...)
	if c.SkillsDisabled {
		out = append(out, "*")
	}
	return out
}

type TargetConfig struct {
	Name     string   `mapstructure:"name" json:"name"`
	Protocol string   `mapstructure:"protocol" json:"protocol"` // ssh|telnet|ftp
	Host     string   `mapstructure:"host" json:"host"`
	User     string   `mapstructure:"user" json:"user"`
	Password string   `mapstructure:"password" json:"password"`
	KeyPath  string   `mapstructure:"key_path" json:"key_path"`
	Prompt   string   `mapstructure:"prompt" json:"prompt"`
	Tags     []string `mapstructure:"tags" json:"tags"`
}

type MCPServerConfig struct {
	Name              string            `mapstructure:"name" json:"name" yaml:"name"`
	Type              string            `mapstructure:"type" json:"type" yaml:"type"`
	Command           string            `mapstructure:"command" json:"command" yaml:"command"`
	Args              []string          `mapstructure:"args" json:"args" yaml:"args"`
	Env               map[string]string `mapstructure:"env" json:"env" yaml:"env"`
	CWD               string            `mapstructure:"cwd" json:"cwd" yaml:"cwd"`
	URL               string            `mapstructure:"url" json:"url" yaml:"url"`
	Headers           map[string]string `mapstructure:"headers" json:"headers" yaml:"headers"`
	BearerTokenEnvVar string            `mapstructure:"bearer_token_env_var" json:"bearer_token_env_var" yaml:"bearer_token_env_var"`
	EnabledTools      []string          `mapstructure:"enabled_tools" json:"enabled_tools" yaml:"enabled_tools"`
	DisabledTools     []string          `mapstructure:"disabled_tools" json:"disabled_tools" yaml:"disabled_tools"`
	StartupTimeoutSec int               `mapstructure:"startup_timeout_sec" json:"startup_timeout_sec" yaml:"startup_timeout_sec"`
	ToolTimeoutSec    int               `mapstructure:"tool_timeout_sec" json:"tool_timeout_sec" yaml:"tool_timeout_sec"`
	Required          bool              `mapstructure:"required" json:"required" yaml:"required"`
	Disabled          bool              `mapstructure:"disabled" json:"disabled" yaml:"disabled"`
}

// InitConfig 初始化配置 (核心加载逻辑)
func InitConfig(cfgFile string) error {
	setViperDefaults()
	if cfgFile != "" {
		// 1. 如果用户通过命令行指定了文件，直接使用
		viper.SetConfigFile(cfgFile)
	} else {
		// 2. 否则按顺序搜索默认路径
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		// 搜索路径优先级：
		// 1. 当前目录 (.)
		viper.AddConfigPath(".")
		// 2. 用户主目录下的 .deepsentry 文件夹
		viper.AddConfigPath(filepath.Join(home, ".deepsentry"))
		// 3. 系统级配置 /etc/deepsentry
		viper.AddConfigPath("/etc/deepsentry")

		viper.SetConfigName("config") // 查找 config.yaml, config.json 等
		viper.SetConfigType("yaml")   // 默认以 yaml 格式解析
	}

	// 3. 开启环境变量自动覆盖
	// 例如: export DEEPSENTRY_API_KEY="xxx" 会自动覆盖配置文件中的 api_key
	viper.SetEnvPrefix("DEEPSENTRY")
	viper.AutomaticEnv()

	// 4. 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		// 如果只是没找到文件，返回特定错误类型，以便 main.go 决定是否进入向导
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return err
		}
		// 其他错误（如 YAML 格式错误）直接返回
		return fmt.Errorf("配置文件读取错误: %w", err)
	}

	// 5. 将读取到的配置映射到全新结构体，校验后原子替换
	var loaded Config
	if err := viper.Unmarshal(&loaded); err != nil {
		return fmt.Errorf("配置解析失败: %w", err)
	}
	ApplyProviderDefaults(&loaded)
	if err := applyRawCaseSensitiveConfig(viper.ConfigFileUsed(), &loaded); err != nil {
		return fmt.Errorf("读取大小写敏感配置失败: %w", err)
	}
	if err := ValidateRuntimeConfig(loaded); err != nil {
		return fmt.Errorf("配置校验失败: %w", err)
	}
	GlobalConfig = loaded
	return nil
}

func (c Config) EffectiveArchiveLimits() (entries int, fileBytes, totalBytes int64) {
	entries = c.ArchiveMaxEntries
	if entries <= 0 {
		entries = 10_000
	}
	fileBytes = c.ArchiveMaxFileBytes
	if fileBytes <= 0 {
		fileBytes = 512 * 1024 * 1024
	}
	totalBytes = c.ArchiveMaxTotalBytes
	if totalBytes <= 0 {
		totalBytes = 2 * 1024 * 1024 * 1024
	}
	if totalBytes < fileBytes {
		fileBytes = totalBytes
	}
	return entries, fileBytes, totalBytes
}

func applyRawCaseSensitiveConfig(path string, cfg *Config) error {
	if strings.TrimSpace(path) == "" || cfg == nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return applyRawCaseSensitiveData(data, cfg)
}

func applyRawCaseSensitiveData(data []byte, cfg *Config) error {
	if cfg == nil {
		return nil
	}
	var raw struct {
		MCPServerConfigs []MCPServerConfig `yaml:"mcp_server_configs"`
		BenchmarkBaseURL string            `yaml:"BENCHMARK_BASE_URL"`
		BenchmarkToken   string            `yaml:"BENCHMARK_TOKEN"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.MCPServerConfigs != nil {
		cfg.MCPServerConfigs = raw.MCPServerConfigs
	}
	if strings.TrimSpace(raw.BenchmarkBaseURL) != "" {
		cfg.BenchmarkBaseURL = strings.TrimSpace(raw.BenchmarkBaseURL)
	}
	if strings.TrimSpace(raw.BenchmarkToken) != "" {
		cfg.BenchmarkToken = strings.TrimSpace(raw.BenchmarkToken)
	}
	return nil
}

// HTTPClient returns a controller-side HTTP client honoring controller_proxy.
// Supported explicit proxy schemes: http, https, socks5, socks5h.
// Empty controller_proxy falls back to the standard environment proxy behavior.
func HTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	raw := strings.TrimSpace(GlobalConfig.ControllerProxy)
	if raw != "" {
		if u, err := url.Parse(raw); err == nil {
			switch strings.ToLower(u.Scheme) {
			case "http", "https":
				tr.Proxy = http.ProxyURL(u)
			case "socks5", "socks5h":
				if d, err := proxy.FromURL(u, proxy.Direct); err == nil {
					tr.Proxy = nil
					tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
						type dialResult struct {
							conn net.Conn
							err  error
						}
						ch := make(chan dialResult, 1)
						go func() {
							c, err := d.Dial(network, addr)
							ch <- dialResult{conn: c, err: err}
						}()
						select {
						case <-ctx.Done():
							return nil, ctx.Err()
						case r := <-ch:
							return r.conn, r.err
						}
					}
				}
			}
		}
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// SaveConfig 将当前 Viper 中的配置保存到文件 (默认保存到当前目录)
func SaveConfig() error {
	// 确保默认保存为 yaml 格式
	viper.SetConfigType("yaml")
	// 保存到当前目录下的 config.yaml
	return WriteConfigAsPrivate("config.yaml")
}

func WriteConfigAsPrivate(path string) error {
	if err := viper.WriteConfigAs(path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
