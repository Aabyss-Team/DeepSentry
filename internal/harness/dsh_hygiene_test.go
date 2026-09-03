package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-edr/internal/analyzer"
	"ai-edr/internal/skills"
	"ai-edr/internal/tools"
)

func TestSkillsMiddlewareAutoLoadsMatchingPlaybook(t *testing.T) {
	catalog, err := skills.LoadCatalog([]string{filepath.Join("..", "..", "skills")})
	if err != nil {
		t.Fatal(err)
	}
	state := NewAgentState(t.TempDir())
	mw := NewSkillsMiddleware(catalog)
	loaded := mw.AutoLoadForQuery(state, "用MCP打开B站播放杰克奥特曼第二集，2倍速并全屏")
	if len(loaded) == 0 || loaded[0] != "bilibili-play" {
		t.Fatalf("auto-load=%#v", loaded)
	}
	if !strings.Contains(state.LoadedSkills["bilibili-play"], "playbackRate") {
		t.Fatalf("playbook was not injected: %q", state.LoadedSkills["bilibili-play"])
	}
	prompt := mw.EnhancePrompt("base", state)
	if !strings.Contains(prompt, "【已加载 Skills】") || !strings.Contains(prompt, "playbackRate") {
		t.Fatalf("loaded skill missing from prompt:\n%s", prompt)
	}
	if again := mw.AutoLoadForQuery(state, "继续播放"); len(again) != 0 {
		t.Fatalf("already loaded skill was injected again: %#v", again)
	}
}

func TestSkillsMiddlewareAutoLoadPinsZipRecoverTool(t *testing.T) {
	catalog, err := skills.LoadCatalog([]string{filepath.Join("..", "..", "skills")})
	if err != nil {
		t.Fatal(err)
	}
	state := NewAgentState(t.TempDir())
	mw := NewSkillsMiddleware(catalog)
	if loaded := mw.AutoLoadForQuery(state, "解开 test04.zip"); len(loaded) == 0 || loaded[0] != "zipcracker" {
		t.Fatalf("auto-load=%#v", loaded)
	}
	names := strings.Join(state.SelectedToolNames(), ",")
	if !strings.Contains(names, "zip_password_recover") {
		t.Fatalf("zipcracker should pin zip_password_recover, got %q", names)
	}
	hint, ok := state.GetMemory("zip_source_hint")
	if !ok || !strings.Contains(hint, "test04.zip") {
		t.Fatalf("zip source hint=%q ok=%v", hint, ok)
	}
	prompt := mw.EnhancePrompt("base", state)
	if !strings.Contains(prompt, "【ZIP 原生优先】") || !strings.Contains(prompt, "test04.zip") {
		t.Fatalf("native-first banner missing:\n%s", prompt)
	}
}

func TestNormalizeSkillActionMapsNativeSkillTool(t *testing.T) {
	action := &AgentAction{Type: ActionTool, ToolName: "skill", ToolArgs: map[string]string{"name": "fofamap"}}
	normalizeSkillAction(action)
	if action.Type != ActionLoadSkill || action.SkillName != "fofamap" {
		t.Fatalf("action=%#v", action)
	}
}

func TestClassifySkillToolIsLowRisk(t *testing.T) {
	risk, reason := classifyToolRisk(AgentAction{Type: ActionTool, ToolName: "skill", ToolArgs: map[string]string{"name": "bilibili-play"}})
	if risk != tools.RiskLow {
		t.Fatalf("skill should be low risk, got %s (%s)", risk, reason)
	}
}

func TestLoopBeforeExecuteSkipsIdenticalFailedCall(t *testing.T) {
	state := NewAgentState(t.TempDir())
	action := AgentAction{Type: ActionTool, ToolName: "hx0-hawkeye__browser_tabs", ToolArgs: map[string]string{"action": "new"}}
	if warning := state.LoopAfterExecute(action, "failed to create tab", true); warning != "" {
		t.Fatalf("first failure should not warn: %s", warning)
	}
	decision := state.LoopBeforeExecute(action)
	if decision.Allow || !strings.Contains(decision.Warning, "拒绝再次执行") {
		t.Fatalf("identical failed probe must be skipped before execute: %#v", decision)
	}
}

func TestLoopBeforeExecuteAllowsOneRetryAfterTransientFailure(t *testing.T) {
	state := NewAgentState(t.TempDir())
	action := AgentAction{Type: ActionTool, ToolName: "read_log", ToolArgs: map[string]string{"path": "/var/log/auth.log"}}
	state.LoopAfterExecute(action, "connection reset by peer", true)
	if decision := state.LoopBeforeExecute(action); !decision.Allow {
		t.Fatalf("first identical retry after a transient failure must be allowed: %#v", decision)
	}
	state.LoopAfterExecute(action, "connection reset by peer", true)
	if decision := state.LoopBeforeExecute(action); decision.Allow {
		t.Fatalf("third identical attempt must be blocked after two failures: %#v", decision)
	}
}

func TestLoopBeforeExecuteAllowsTwoSnapshotsThenBlocks(t *testing.T) {
	state := NewAgentState(t.TempDir())
	action := AgentAction{Type: ActionTool, ToolName: "hx0-hawkeye__browser_snapshot", ToolArgs: map[string]string{"max_text": "8000"}}
	state.LoopAfterExecute(action, "page one", false)
	if decision := state.LoopBeforeExecute(action); !decision.Allow {
		t.Fatalf("second snapshot should still run: %#v", decision)
	}
	state.LoopAfterExecute(action, "page two", false)
	decision := state.LoopBeforeExecute(action)
	if decision.Allow {
		t.Fatalf("third identical snapshot must be skipped: %#v", decision)
	}
}

func TestLoopBeforeExecuteBlocksNewTabWhenPlaySkillLoaded(t *testing.T) {
	state := NewAgentState(t.TempDir())
	state.LoadedSkills = map[string]string{"bilibili-play": "playbackRate"}
	action := AgentAction{Type: ActionTool, ToolName: "hx0-hawkeye__browser_tabs", ToolArgs: map[string]string{"action": "new"}}
	decision := state.LoopBeforeExecute(action)
	if decision.Allow || !strings.Contains(decision.Warning, "browser_navigate") {
		t.Fatalf("loaded play skill must block tabs new: %#v", decision)
	}
}

func TestLoopBeforeExecuteBlocksPwdWhenZipcrackerLoaded(t *testing.T) {
	state := NewAgentState(t.TempDir())
	state.LoadedSkills = map[string]string{"zipcracker": "zip_password_recover"}
	action := AgentAction{Type: ActionExecute, Command: "pwd"}
	decision := state.LoopBeforeExecute(action)
	if decision.Allow || !strings.Contains(decision.Warning, "pwd/ls") {
		t.Fatalf("zipcracker must block pwd probes: %#v", decision)
	}
	ls := AgentAction{Type: ActionLS, Path: "."}
	if decision := state.LoopBeforeExecute(ls); decision.Allow {
		t.Fatalf("zipcracker must block ls .: %#v", decision)
	}
	targeted := AgentAction{Type: ActionExecute, Command: "ls /var/log"}
	if decision := state.LoopBeforeExecute(targeted); !decision.Allow {
		t.Fatalf("explicit-path ls should remain allowed: %#v", decision)
	}
}

func TestLoopBeforeExecuteBlocksFlagPayloadAsCommand(t *testing.T) {
	state := NewAgentState(t.TempDir())
	action := AgentAction{Type: ActionExecute, Command: "flag{Adm1N-B2G-kU-SZIP}"}
	decision := state.LoopBeforeExecute(action)
	if decision.Allow || !strings.Contains(decision.Output, "不是 shell 命令") {
		t.Fatalf("flag payload must be blocked without confirmation: %#v", decision)
	}
	echo := AgentAction{Type: ActionExecute, Command: "echo flag{Adm1N-B2G-kU-SZIP}"}
	if decision := state.LoopBeforeExecute(echo); !decision.Allow {
		t.Fatalf("echoing a flag should remain allowed: %#v", decision)
	}
}

func TestLoopBeforeExecuteBlocksExternalZIPCrackUntilNativeTried(t *testing.T) {
	state := NewAgentState(t.TempDir())
	state.LoadedSkills = map[string]string{"zipcracker": "zip_password_recover"}
	python := AgentAction{Type: ActionExecute, Command: "python3 ZipCracker.py test04.zip -m '?uali?s?d?d?d'"}
	decision := state.LoopBeforeExecute(python)
	if decision.Allow || !strings.Contains(decision.Warning, "zip_password_recover") {
		t.Fatalf("python ZipCracker must be blocked before native try: %#v", decision)
	}

	sidecar := NewAgentState(t.TempDir())
	sidecar.LoadedSkills = map[string]string{"zipcracker": "zip_password_recover"}
	unzip := AgentAction{Type: ActionExecute, Command: "unzip -P 123456 build/test04.zip"}
	if decision := sidecar.LoopBeforeExecute(unzip); decision.Allow {
		t.Fatalf("unzip must be blocked before native try: %#v", decision)
	}
	extract := NewAgentState(t.TempDir())
	extract.LoadedSkills = map[string]string{"zipcracker": "zip_password_recover"}
	archive := AgentAction{Type: ActionTool, ToolName: "archive_extract", ToolArgs: map[string]string{"source": "build/test04.zip"}}
	if decision := extract.LoopBeforeExecute(archive); decision.Allow {
		t.Fatalf("archive_extract on zip must be blocked before native try: %#v", decision)
	}

	native := AgentAction{Type: ActionTool, ToolName: "zip_password_recover", ToolArgs: map[string]string{"action": "auto", "source": "build/test04.zip"}}
	if decision := state.LoopBeforeExecute(native); !decision.Allow {
		t.Fatalf("native zip_password_recover must stay allowed: %#v", decision)
	}
	state.LoopAfterExecute(native, "ZIP 口令恢复失败：未命中", true)
	if !state.HasTriedTool("zip_password_recover") {
		t.Fatal("native attempt should be recorded")
	}
	if decision := state.LoopBeforeExecute(python); !decision.Allow {
		t.Fatalf("after native failure, fallback python should be allowed: %#v", decision)
	}
}

func TestLoopBeforeExecuteBlocksFofaReconWhenMCPConnected(t *testing.T) {
	orig := hasFofaMapMCP
	hasFofaMapMCP = func() bool { return true }
	t.Cleanup(func() { hasFofaMapMCP = orig })

	state := NewAgentState(t.TempDir())
	python := AgentAction{Type: ActionExecute, Command: "cd /opt/deepsentry/skills/fofamap && python3 scripts/fofa_recon.py search --help"}
	decision := state.LoopBeforeExecute(python)
	if decision.Allow || !strings.Contains(decision.Warning, "FofaMap MCP") {
		t.Fatalf("fofa_recon.py must be blocked when MCP is connected: %#v", decision)
	}

	curl := AgentAction{Type: ActionExecute, Command: "curl https://fofa.info/api/v1/search/all"}
	if decision := state.LoopBeforeExecute(curl); decision.Allow {
		t.Fatalf("curl FOFA API must be blocked when MCP is connected: %#v", decision)
	}

	mcpCall := AgentAction{Type: ActionTool, ToolName: "fofamap__fofa_search", ToolArgs: map[string]string{"query": `domain="example.com"`}}
	if decision := state.LoopBeforeExecute(mcpCall); !decision.Allow {
		t.Fatalf("MCP fofa_search must stay allowed: %#v", decision)
	}

	hasFofaMapMCP = func() bool { return false }
	fallback := NewAgentState(t.TempDir())
	if decision := fallback.LoopBeforeExecute(python); !decision.Allow {
		t.Fatalf("without MCP, fofa_recon.py fallback should remain allowed: %#v", decision)
	}
}

func TestLoopAfterExecuteWarnsOnRepeatedTimeouts(t *testing.T) {
	state := NewAgentState(t.TempDir())
	action := AgentAction{Type: ActionTool, ToolName: "fofamap__fofa_search", ToolArgs: map[string]string{"query": "app"}}
	state.LoopAfterExecute(action, "timeout waiting for FOFA", true)
	warning := state.LoopAfterExecute(action, "等待 JSON-RPC 响应超时", true)
	if !strings.Contains(warning, "超时") {
		t.Fatalf("second timeout should warn: %q", warning)
	}
}

func TestLoopAfterExecuteNudgesStaleTodos(t *testing.T) {
	state := NewAgentState(t.TempDir())
	state.Todos = []TodoItem{{ID: "1", Content: "play video", Status: "in_progress"}}
	read := AgentAction{Type: ActionReadFile, Path: "/tmp/a"}
	var warning string
	for i := 0; i < todoNudgeAfter; i++ {
		warning = state.LoopAfterExecute(read, fmt.Sprintf("content-%d", i), false)
	}
	if !strings.Contains(warning, "todo") {
		t.Fatalf("expected todo nudge after %d steps: %q", todoNudgeAfter, warning)
	}
}

func TestLoopShouldHaltAfterRepeatedStalls(t *testing.T) {
	state := NewAgentState(t.TempDir())
	state.LoadedSkills = map[string]string{"bilibili-play": "play"}
	action := AgentAction{Type: ActionTool, ToolName: "hx0-hawkeye__browser_tabs", ToolArgs: map[string]string{"action": "new"}}
	for i := 0; i < maxStallWarnings; i++ {
		decision := state.LoopBeforeExecute(action)
		if decision.Allow {
			t.Fatalf("iteration %d should skip: %#v", i, decision)
		}
		if decision.HardStop {
			if i != maxStallWarnings-1 {
				t.Fatalf("hard stop too early at %d", i)
			}
			if !state.LoopShouldHalt() {
				t.Fatal("LoopShouldHalt should be true")
			}
			return
		}
		state.LoopRecordSkip(action)
	}
	t.Fatal("expected hard stop")
}

func TestLatestUserTaskSkipsInjectedWarnings(t *testing.T) {
	history := []analyzer.Message{
		{Role: "user", Content: "打开B站播放奥特曼"},
		{Role: "user", Content: "循环守卫：连续 3 次执行了相同动作。"},
		{Role: "user", Content: "系统警告: 请输出 action"},
	}
	if got := latestUserTask(history); got != "打开B站播放奥特曼" {
		t.Fatalf("latest user task=%q", got)
	}
}

func TestFilesystemMiddlewareExposesWorkspaceCwd(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	state := NewAgentState(filepath.Join(t.TempDir(), "evidence"))
	prompt := NewFilesystemMiddleware(nil).EnhancePrompt("base", state)
	if !strings.Contains(prompt, wd) || !strings.Contains(prompt, state.WorkspaceDir) || !strings.Contains(prompt, "不要先 execute pwd") {
		t.Fatalf("workspace prompt missing cwd/evidence:\n%s", prompt)
	}
}
