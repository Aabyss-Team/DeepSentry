package memory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreSetAndLoad(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", oldHome)

	store, err := NewStore(ScopeLocal)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Set("web_root", "/var/www/html", "agent"); err != nil {
		t.Fatal(err)
	}

	store2, err := NewStore(ScopeLocal)
	if err != nil {
		t.Fatal(err)
	}

	entries := store2.ActiveEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Key != "web_root" || entries[0].Value != "/var/www/html" {
		t.Fatalf("unexpected entry: %+v", entries[0])
	}

	// 验证文件落盘
	path := filepath.Join(tmp, ".deepsentry", "memory", "store.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("store file not created: %v", err)
	}
}

func TestBuiltinAgentsMDLoadedWithoutExternalFile(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", oldHome)

	store, err := NewStore(ScopeLocal)
	if err != nil {
		t.Fatal(err)
	}
	if store.AgentsMDCount() != 1 {
		t.Fatalf("expected builtin AGENTS.md only, got %d", store.AgentsMDCount())
	}
	prompt := store.FormatPrompt()
	if !strings.Contains(prompt, BuiltinAgentsMDPath) {
		t.Fatalf("prompt should include builtin AGENTS.md source, got:\n%s", prompt)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".deepsentry", "AGENTS.md")); !os.IsNotExist(err) {
		t.Fatalf("builtin AGENTS.md should not create external file, stat err=%v", err)
	}
}

func TestMemoryPromptExplainsAutoAgentsMDPolicy(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", oldHome)

	store, err := NewStore(ScopeLocal)
	if err != nil {
		t.Fatal(err)
	}
	prompt := store.FormatPrompt()
	for _, want := range []string{"AGENTS.md 不要求用户手动维护", "有温度的记忆点", "稳定偏好"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt should explain auto memory policy %q, got:\n%s", want, prompt)
		}
	}
}

func TestStoreScopeIsolation(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", oldHome)

	store, _ := NewStore("ssh:192.168.1.1_22")
	_ = store.Set("hostname", "prod-web", "agent")
	_ = store.SetGlobal("report_lang", "zh-CN", "agent")

	local, _ := NewStore(ScopeLocal)
	localEntries := local.ActiveEntries()
	if len(localEntries) != 1 || localEntries[0].Key != "report_lang" {
		t.Fatalf("local should only see global entry, got %+v", localEntries)
	}

	ssh, _ := NewStore("ssh:192.168.1.1_22")
	sshEntries := ssh.ActiveEntries()
	if len(sshEntries) != 2 {
		t.Fatalf("ssh scope should see 2 entries, got %d", len(sshEntries))
	}
}

func TestRejectSensitiveMemory(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", oldHome)

	store, _ := NewStore(ScopeLocal)
	err := store.Set("creds", "api_key=sk-secret123", "agent")
	if err == nil {
		t.Fatal("expected error for sensitive content")
	}
}

func TestDeleteMemory(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", oldHome)

	store, _ := NewStore(ScopeLocal)
	_ = store.Set("temp", "value", "agent")
	if err := store.Delete("temp"); err != nil {
		t.Fatal(err)
	}
	if len(store.ActiveEntries()) != 0 {
		t.Fatal("entry should be deleted")
	}
}

func TestClearMemoryScopes(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", oldHome)

	store, _ := NewStore("ssh:demo")
	_ = store.Set("target_note", "value", "agent")
	_ = store.SetGlobal("global_note", "value", "agent")

	n, err := store.Clear("target")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("target clear removed %d entries, want 1", n)
	}
	entries := store.ActiveEntries()
	if len(entries) != 1 || entries[0].Key != "global_note" {
		t.Fatalf("target clear should keep global entry, got %+v", entries)
	}

	n, err = store.Clear("all")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(store.ActiveEntries()) != 0 {
		t.Fatalf("all clear failed: n=%d entries=%+v", n, store.ActiveEntries())
	}
}

func TestClearExternalAgentsMD(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Setenv("HOME", tmp)
	defer os.Setenv("HOME", oldHome)

	userAgents := filepath.Join(tmp, ".deepsentry", "AGENTS.md")
	if err := os.MkdirAll(filepath.Dir(userAgents), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userAgents, []byte("# Custom\n- remember me\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(ScopeLocal)
	if err != nil {
		t.Fatal(err)
	}
	if store.AgentsMDCount() != 2 {
		t.Fatalf("expected builtin + custom AGENTS.md, got %d", store.AgentsMDCount())
	}
	n, err := store.ClearExternalAgentsMD()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("removed %d AGENTS.md files, want 1", n)
	}
	if _, err := os.Stat(userAgents); !os.IsNotExist(err) {
		t.Fatalf("custom AGENTS.md should be deleted, stat err=%v", err)
	}
	if store.AgentsMDCount() != 1 {
		t.Fatalf("builtin AGENTS.md should remain, got %d sources", store.AgentsMDCount())
	}
}
