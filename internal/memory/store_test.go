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
