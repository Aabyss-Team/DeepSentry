package harness

import (
	"ai-edr/internal/analyzer"
	"ai-edr/internal/config"
	"ai-edr/internal/executor"
	"ai-edr/internal/tools"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseActionInfersTool(t *testing.T) {
	action := ParseAction(analyzer.AgentResponse{
		Thought:  "ping host",
		ToolName: "ping",
		ToolArgs: map[string]string{"host": "127.0.0.1"},
	})
	if action.Type != ActionTool {
		t.Fatalf("expected ActionTool, got %s", action.Type)
	}
}

func TestParseActionInfersAskUser(t *testing.T) {
	action := ParseAction(analyzer.AgentResponse{
		Thought:  "need webhook",
		Question: "请提供钉钉 Webhook 地址",
		Options:  []string{"稍后提供", "跳过通知"},
	})
	if action.Type != ActionAskUser {
		t.Fatalf("expected ActionAskUser, got %s", action.Type)
	}
	if action.Question == "" || len(action.Options) != 2 {
		t.Fatalf("ask fields not carried: %#v", action)
	}
}

func TestParseActionInfersReadFile(t *testing.T) {
	action := ParseAction(analyzer.AgentResponse{Path: "/etc/hosts"})
	if action.Type != ActionReadFile {
		t.Fatalf("expected ActionReadFile, got %s", action.Type)
	}
}

func TestParseActionCarriesTargetSelector(t *testing.T) {
	action := ParseAction(analyzer.AgentResponse{
		Action:         string(ActionTask),
		TaskName:       "log-analyst",
		TaskPrompt:     "check logs",
		TaskMaxSteps:   24,
		TargetSelector: "prod",
	})
	if action.TargetSelector != "prod" || action.TaskName != "log-analyst" || action.TaskMaxSteps != 24 {
		t.Fatalf("target fields not carried: %#v", action)
	}
}

func TestParseActionCarriesParallelTasks(t *testing.T) {
	action := ParseAction(analyzer.AgentResponse{
		Action: string(ActionTask),
		ParallelTasks: []analyzer.TaskSpec{
			{TaskName: "log-analyst", TaskPrompt: "分析 auth.log", TaskMaxSteps: 20},
			{TaskName: "network-analyst", TaskPrompt: "分析异常连接", TargetSelector: "prod", TaskMaxSteps: 12},
		},
	})
	if action.Type != ActionTask || len(action.ParallelTasks) != 2 {
		t.Fatalf("parallel tasks not carried: %#v", action)
	}
	if action.ParallelTasks[1].TargetSelector != "prod" || action.ParallelTasks[0].TaskMaxSteps != 20 {
		t.Fatalf("parallel task fields not carried: %#v", action.ParallelTasks)
	}
}

func TestActionToJSONPreservesFields(t *testing.T) {
	raw := actionToJSON(AgentAction{
		Thought:   "test",
		Type:      ActionTool,
		ToolName:  "net_connections",
		ToolArgs:  map[string]string{"filter": "listen"},
		Path:      "/var/log/syslog",
		TaskName:  "log-analyst",
		MemoryKey: "foo",
	})
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if m["tool_name"] != "net_connections" {
		t.Fatalf("tool_name lost: %v", m)
	}
	if m["path"] != "/var/log/syslog" {
		t.Fatalf("path lost: %v", m)
	}
}

func TestOffloadOutputIsSessionScoped(t *testing.T) {
	dir := t.TempDir()
	mw := &ContextMiddleware{OutputThreshold: 10}
	outA := strings.Repeat("A", 32)
	outB := strings.Repeat("B", 32)

	msgA := mw.OffloadOutput(NewAgentStateWithSession(dir, "session_a"), "step1", outA)
	msgB := mw.OffloadOutput(NewAgentStateWithSession(dir, "session_b"), "step1", outB)
	if !strings.Contains(msgA, filepath.Join("sessions", "session_a", "output_step1.txt")) {
		t.Fatalf("session_a path missing from output: %s", msgA)
	}
	if !strings.Contains(msgB, filepath.Join("sessions", "session_b", "output_step1.txt")) {
		t.Fatalf("session_b path missing from output: %s", msgB)
	}

	dataA, err := os.ReadFile(filepath.Join(dir, "sessions", "session_a", "output_step1.txt"))
	if err != nil {
		t.Fatal(err)
	}
	dataB, err := os.ReadFile(filepath.Join(dir, "sessions", "session_b", "output_step1.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(dataA) != outA || string(dataB) != outB {
		t.Fatalf("offloaded outputs were not isolated: A=%q B=%q", string(dataA), string(dataB))
	}
}

func TestIsEmptyAction(t *testing.T) {
	if isEmptyAction(AgentAction{ToolName: "ping"}) {
		t.Fatal("tool_name should not be empty action")
	}
	if !isEmptyAction(AgentAction{Thought: "thinking"}) {
		t.Fatal("thought-only should be empty action")
	}
}

func TestUnknownUploadActionGuidance(t *testing.T) {
	got := unknownActionGuidance(AgentAction{Type: ActionType("upload")})
	for _, want := range []string{`action="execute"`, "upload <本地路径> <远程路径>", "不是独立 action"} {
		if !strings.Contains(got, want) {
			t.Fatalf("guidance missing %q: %s", want, got)
		}
	}
}

func TestNonInteractiveAskAnswerTellsAgentToContinue(t *testing.T) {
	got := nonInteractiveAskAnswer(AgentAction{
		Thought:  "need webhook",
		Question: "请提供 webhook",
		Options:  []string{"跳过通知", "稍后配置"},
	})
	for _, want := range []string{"非交互模式", "采用保守默认方案继续", "跳过对应功能", "不要再次 ask_user", "跳过通知"} {
		if !strings.Contains(got, want) {
			t.Fatalf("non-interactive answer missing %q: %s", want, got)
		}
	}
}

func TestWebshellPromptForbidsAskUser(t *testing.T) {
	got := nonInteractivePrompt(true)
	for _, want := range []string{"非交互模式", "不要使用 action=\"ask_user\"", "多步骤命令的关键输出"} {
		if !strings.Contains(got, want) {
			t.Fatalf("webshell prompt missing %q: %s", want, got)
		}
	}
	for _, banned := range []string{"保存 checkpoint", "--resume"} {
		if strings.Contains(got, banned) {
			t.Fatalf("webshell prompt should not encourage ask_user checkpoint, found %q in %s", banned, got)
		}
	}
}

func TestAskResumeMessageWebshellShowsSupplementCommand(t *testing.T) {
	got := askResumeMessage("session_test", true)
	for _, want := range []string{"deepsentry --webshell --resume session_test", `--task "在这里填写补充内容"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("resume message missing %q: %s", want, got)
		}
	}
}

func TestBlockDeepSentryConfigShell(t *testing.T) {
	cases := []string{
		"cat /root/config.yaml",
		"sed -i 's/a/b/' /root/config.yaml",
		"cat ./config.yaml",
		"python3 - <<'PY'\nopen('config.yaml').read()\nPY",
	}
	for _, cmd := range cases {
		out, blocked := blockDeepSentryConfigShell(cmd, fakeRemoteExecutor{})
		if !blocked {
			t.Fatalf("expected config command blocked: %s", cmd)
		}
		if !strings.Contains(out, "config_manage") || !strings.Contains(out, "远端目标机") {
			t.Fatalf("unexpected guidance for %s:\n%s", cmd, out)
		}
	}

	if _, blocked := blockDeepSentryConfigShell("cat /var/www/app/config.yaml", fakeRemoteExecutor{}); blocked {
		t.Fatal("business config path should not be blocked")
	}
}

func TestResolveFleetExecRiskUsesInnerCommand(t *testing.T) {
	tool, ok := tools.Get("fleet_exec")
	if !ok {
		t.Fatal("fleet_exec tool should exist")
	}

	lowAction := AgentAction{
		Type:     ActionTool,
		ToolName: "fleet_exec",
		ToolArgs: map[string]string{
			"selector": "target-01",
			"command":  "ls -la /tmp/flag.txt /tmp/flag.zip && echo '---CONTENT---' && cat /tmp/flag.txt",
		},
	}
	risk, reason := resolveToolRisk(lowAction, tool)
	if risk != tools.RiskLow {
		t.Fatalf("read-only fleet_exec should be low risk, got %s (%s)", risk, reason)
	}

	aliasAction := AgentAction{
		Type:     ActionTool,
		ToolName: "fleet_exec",
		ToolArgs: map[string]string{
			"selector": "target-01",
			"cmd":      "cat /tmp/flag.txt",
		},
	}
	risk, reason = resolveToolRisk(aliasAction, tool)
	if risk != tools.RiskLow {
		t.Fatalf("read-only fleet_exec cmd alias should be low risk, got %s (%s)", risk, reason)
	}

	highAction := AgentAction{
		Type:     ActionTool,
		ToolName: "fleet_exec",
		ToolArgs: map[string]string{
			"selector": "target-01",
			"command":  "rm -rf /tmp/flag.txt",
		},
	}
	risk, reason = resolveToolRisk(highAction, tool)
	if risk != tools.RiskHigh {
		t.Fatalf("destructive fleet_exec should be high risk, got %s (%s)", risk, reason)
	}
}

func TestResolveFleetFileRiskUsesAction(t *testing.T) {
	tool, ok := tools.Get("fleet_file")
	if !ok {
		t.Fatal("fleet_file tool should exist")
	}
	for _, actionName := range []string{"ls", "read", "download"} {
		risk, reason := resolveToolRisk(AgentAction{
			Type:     ActionTool,
			ToolName: "fleet_file",
			ToolArgs: map[string]string{"action": actionName},
		}, tool)
		if risk != tools.RiskLow {
			t.Fatalf("fleet_file %s should be low risk, got %s (%s)", actionName, risk, reason)
		}
	}

	risk, reason := resolveToolRisk(AgentAction{
		Type:     ActionTool,
		ToolName: "fleet_file",
		ToolArgs: map[string]string{"action": "upload"},
	}, tool)
	if risk != tools.RiskHigh {
		t.Fatalf("fleet_file upload should be high risk, got %s (%s)", risk, reason)
	}
}

func TestEnrichActionExecutionTargetLocalRunOverridesRemote(t *testing.T) {
	origExecutor := executor.Current
	origHost := config.GlobalConfig.SSHHost
	executor.Current = fakeSSHExecutor{}
	config.GlobalConfig.SSHHost = "8.137.114.242:2222"
	defer func() {
		executor.Current = origExecutor
		config.GlobalConfig.SSHHost = origHost
	}()

	action := AgentAction{Type: ActionExecute, Command: "local_run sshpass -p x ssh root@10.0.0.1 hostname"}
	enrichActionExecutionTarget(&action)
	if action.TargetProtocol != "local" || action.TargetHost != "" || action.TargetName != "" {
		t.Fatalf("local_run target = name=%q proto=%q host=%q, want local without remote host", action.TargetName, action.TargetProtocol, action.TargetHost)
	}

	remote := AgentAction{Type: ActionExecute, Command: "hostname"}
	enrichActionExecutionTarget(&remote)
	if remote.TargetProtocol != "ssh" || remote.TargetHost != "8.137.114.242:2222" {
		t.Fatalf("remote target = proto=%q host=%q, want ssh host", remote.TargetProtocol, remote.TargetHost)
	}
}

type fakeRemoteExecutor struct{}

func (fakeRemoteExecutor) Run(string) (string, error) { return "", errors.New("not implemented") }
func (fakeRemoteExecutor) ReadTargetFile(string) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (fakeRemoteExecutor) ListTargetDir(string) ([]string, error) {
	return nil, errors.New("not implemented")
}
func (fakeRemoteExecutor) IsRemote() bool { return true }
func (fakeRemoteExecutor) Close()         {}

type fakeSSHExecutor struct{ fakeRemoteExecutor }

func (fakeSSHExecutor) Mode() string { return "ssh" }
