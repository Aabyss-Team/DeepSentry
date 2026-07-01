package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func TestManageConfigAddSkillSourceCreatesConfig(t *testing.T) {
	old := GlobalConfig
	defer func() { GlobalConfig = old }()

	path := filepath.Join(t.TempDir(), "config.yaml")
	out, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "add_skill_source",
		"source":      "/opt/deepsentry-skills",
	})
	if err != nil {
		t.Fatalf("ManageConfig add_skill_source: %v", err)
	}
	if !strings.Contains(out, "新建配置") {
		t.Fatalf("expected new config message, got %q", out)
	}

	values := readYAMLStringSeq(t, path, "skill_sources")
	want := []string{"skills", "~/.deepsentry/skills", "/opt/deepsentry-skills"}
	if strings.Join(values, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected skill_sources: %#v", values)
	}
	if len(GlobalConfig.SkillSources) != 3 {
		t.Fatalf("GlobalConfig not reloaded with skill_sources: %#v", GlobalConfig.SkillSources)
	}
}

func TestManageConfigPathArgDoesNotOverrideConfigPath(t *testing.T) {
	old := GlobalConfig
	defer func() { GlobalConfig = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("skill_sources:\n  - skills\n"), 0o600); err != nil {
		t.Fatalf("write seed config: %v", err)
	}
	viper.SetConfigFile(path)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("read seed config: %v", err)
	}

	source := filepath.Join(dir, "external-skills")
	out, err := ManageConfig(map[string]string{
		"action": "add_skill_source",
		"path":   source,
	})
	if err != nil {
		t.Fatalf("ManageConfig add_skill_source with path source: %v", err)
	}
	if !strings.Contains(out, path) {
		t.Fatalf("expected current config path in output, got %q", out)
	}
	values := readYAMLStringSeq(t, path, "skill_sources")
	if !containsString(values, source) {
		t.Fatalf("skill source not added to current config: %#v", values)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("path arg should be treated as skill source, not config file; stat err=%v", err)
	}
}

func TestManageConfigGetAction(t *testing.T) {
	old := GlobalConfig
	defer func() { GlobalConfig = old }()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("ssh_password: SuperSecret123!\nskill_sources:\n  - skills\n"), 0o600); err != nil {
		t.Fatalf("write seed config: %v", err)
	}
	out, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "get",
		"key":         "skill_sources",
	})
	if err != nil {
		t.Fatalf("ManageConfig get skill_sources: %v", err)
	}
	if !strings.Contains(out, "skills") {
		t.Fatalf("unexpected get output: %q", out)
	}
	secretOut, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "get",
		"key":         "ssh_password",
	})
	if err != nil {
		t.Fatalf("ManageConfig get ssh_password: %v", err)
	}
	if strings.Contains(secretOut, "SuperSecret123!") || !strings.Contains(secretOut, "***") {
		t.Fatalf("secret should be redacted, got %q", secretOut)
	}
	statusOut, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "get_config",
	})
	if err != nil {
		t.Fatalf("ManageConfig get_config alias: %v", err)
	}
	if !strings.Contains(statusOut, "配置文件:") {
		t.Fatalf("get_config should return config status, got %q", statusOut)
	}
}

func TestManageConfigSetSSHBacksUpAndRedactsOutput(t *testing.T) {
	old := GlobalConfig
	defer func() { GlobalConfig = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("provider: deepseek\nmodel_name: test-model\n"), 0o600); err != nil {
		t.Fatalf("write seed config: %v", err)
	}

	out, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "set_ssh",
		"host":        "10.0.0.8:22",
		"user":        "root",
		"password":    "SuperSecret123!",
	})
	if err != nil {
		t.Fatalf("ManageConfig set_ssh: %v", err)
	}
	if strings.Contains(out, "SuperSecret123!") {
		t.Fatalf("tool output leaked password: %q", out)
	}
	if GlobalConfig.SSHHost != "10.0.0.8:22" || GlobalConfig.SSHPassword != "SuperSecret123!" {
		t.Fatalf("GlobalConfig not reloaded with ssh values: %#v", GlobalConfig)
	}

	backups, err := filepath.Glob(filepath.Join(dir, ".deepsentry_backups", "config_*.yaml"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("expected one backup, got %#v err=%v", backups, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "SuperSecret123!") {
		t.Fatalf("updated config missing password:\n%s", data)
	}
}

func TestManageConfigAddTargetUpsertsByHost(t *testing.T) {
	old := GlobalConfig
	defer func() { GlobalConfig = old }()

	path := filepath.Join(t.TempDir(), "config.yaml")
	for _, user := range []string{"ubuntu", "admin"} {
		if _, err := ManageConfig(map[string]string{
			"config_path": path,
			"action":      "add_target",
			"protocol":    "ssh",
			"host":        "10.0.0.9:2222",
			"user":        user,
			"tags":        "prod,web",
		}); err != nil {
			t.Fatalf("ManageConfig add_target user=%s: %v", user, err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	targets, ok := root["targets"].([]any)
	if !ok || len(targets) != 1 {
		t.Fatalf("expected one upserted target, got %#v", root["targets"])
	}
	target := targets[0].(map[string]any)
	if target["user"] != "admin" {
		t.Fatalf("expected target user updated to admin, got %#v", target)
	}
}

func TestManageConfigEnableFleetPromotesSingleTarget(t *testing.T) {
	old := GlobalConfig
	defer func() { GlobalConfig = old }()

	path := filepath.Join(t.TempDir(), "config.yaml")
	seed := `target_protocol: ssh
ssh_host: 8.137.114.242:2222
ssh_user: root
ssh_password: single-secret
targets:
  - name: ssh-10.204.1.249
    protocol: ssh
    host: 10.204.1.249:2222
    user: root
    password: target-secret
`
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("write seed config: %v", err)
	}
	out, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "enable_fleet",
	})
	if err != nil {
		t.Fatalf("ManageConfig enable_fleet: %v", err)
	}
	if !strings.Contains(out, "当前单目标") {
		t.Fatalf("unexpected output: %q", out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if root["target_protocol"] != "local" {
		t.Fatalf("target_protocol = %#v, want local", root["target_protocol"])
	}
	targets, ok := root["targets"].([]any)
	if !ok || len(targets) != 2 {
		t.Fatalf("expected two fleet targets, got %#v", root["targets"])
	}
	if len(GlobalConfig.Targets) != 2 || GlobalConfig.TargetProtocol != "local" {
		t.Fatalf("GlobalConfig not reloaded as fleet: %#v", GlobalConfig)
	}
}

func TestManageConfigReplaceYAMLBacksUpInvalidConfig(t *testing.T) {
	old := GlobalConfig
	defer func() { GlobalConfig = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("provider: [\n"), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	out, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "replace_yaml",
		"content":     "provider: deepseek\nmodel_name: repaired-model\n",
	})
	if err != nil {
		t.Fatalf("ManageConfig replace_yaml: %v", err)
	}
	if !strings.Contains(out, "已替换并重载配置") {
		t.Fatalf("unexpected output: %q", out)
	}
	if GlobalConfig.ModelName != "repaired-model" {
		t.Fatalf("GlobalConfig not reloaded after repair: %#v", GlobalConfig)
	}
	backups, err := filepath.Glob(filepath.Join(dir, ".deepsentry_backups", "config_*.yaml"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("expected one invalid-config backup, got %#v err=%v", backups, err)
	}
	backupData, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backupData) != "provider: [\n" {
		t.Fatalf("backup should preserve invalid original, got %q", backupData)
	}
}

func TestManageConfigImportClaudeMCPAndToggle(t *testing.T) {
	old := GlobalConfig
	defer func() { GlobalConfig = old }()

	path := filepath.Join(t.TempDir(), "config.yaml")
	claudeJSON := `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "env": {"TOKEN": "abc"},
      "cwd": "/tmp"
    }
  }
}`
	if _, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "import_claude_mcp",
		"content":     claudeJSON,
	}); err != nil {
		t.Fatalf("import_claude_mcp: %v", err)
	}
	if len(GlobalConfig.MCPServerConfigs) != 1 {
		t.Fatalf("expected one mcp server config, got %#v", GlobalConfig.MCPServerConfigs)
	}
	got := GlobalConfig.MCPServerConfigs[0]
	if got.Name != "fs" || got.Command != "npx" || got.CWD != "/tmp" || got.Env["TOKEN"] != "abc" {
		t.Fatalf("unexpected imported config: %#v", got)
	}

	if _, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "disable_mcp_server",
		"name":        "fs",
	}); err != nil {
		t.Fatalf("disable_mcp_server: %v", err)
	}
	if !GlobalConfig.MCPServerConfigs[0].Disabled {
		t.Fatalf("expected fs disabled: %#v", GlobalConfig.MCPServerConfigs[0])
	}
}

func TestManageConfigToggleSkillSource(t *testing.T) {
	old := GlobalConfig
	defer func() { GlobalConfig = old }()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if _, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "add_skill_source",
		"source":      "/opt/deepsentry-skills",
	}); err != nil {
		t.Fatalf("add_skill_source: %v", err)
	}
	if _, err := ManageConfig(map[string]string{
		"config_path": path,
		"action":      "disable_skill_source",
		"source":      "/opt/deepsentry-skills",
	}); err != nil {
		t.Fatalf("disable_skill_source: %v", err)
	}
	if len(GlobalConfig.DisabledSkillSources) != 1 || GlobalConfig.DisabledSkillSources[0] != "/opt/deepsentry-skills" {
		t.Fatalf("unexpected disabled skill sources: %#v", GlobalConfig.DisabledSkillSources)
	}
}

func readYAMLStringSeq(t *testing.T, path, key string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var root map[string][]string
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	return root[key]
}
