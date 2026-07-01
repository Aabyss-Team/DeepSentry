package builtin

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ai-edr/internal/executor"
)

func TestFlagScanFindsDefaultFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(path, []byte("hello flag{deep_sentry_test}"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := executor.Current
	executor.Current = &executor.LocalExecutor{}
	defer func() { executor.Current = old }()

	out, err := FlagScan(Runtime{}, dir, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "flag{deep_sentry_test}") {
		t.Fatalf("missing flag: %s", out)
	}
}

func TestFlagScanDoesNotSkipHiddenFlagFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".flag")
	if err := os.WriteFile(path, []byte("ctf{hidden_file_flag}"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := executor.Current
	executor.Current = &executor.LocalExecutor{}
	defer func() { executor.Current = old }()

	out, err := FlagScan(Runtime{}, dir, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ctf{hidden_file_flag}") {
		t.Fatalf("missing hidden flag: %s", out)
	}
}

func TestShouldSkipFlagScanNameOnlySkipsNoisyRoots(t *testing.T) {
	for _, name := range []string{"proc", "/sys", ".git", "node_modules", "__pycache__", "vendor"} {
		if !shouldSkipFlagScanName(name) {
			t.Fatalf("expected %q to be skipped", name)
		}
	}
	for _, name := range []string{".flag", ".env", "challenge"} {
		if shouldSkipFlagScanName(name) {
			t.Fatalf("did not expect %q to be skipped", name)
		}
	}
}

func TestAWDServiceCheckTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listen unavailable in this sandbox: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	out, err := AWDServiceCheck(Runtime{}, ln.Addr().String(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "TCP OPEN") {
		t.Fatalf("expected open service: %s", out)
	}
}

func TestAWDServiceCheckCapsTargets(t *testing.T) {
	targets := make([]string, maxAWDCheckTargets+3)
	for i := range targets {
		targets[i] = "http://[::1"
	}
	out, err := AWDServiceCheck(Runtime{}, strings.Join(targets, ","), 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out, "- http://[::1"); got != maxAWDCheckTargets {
		t.Fatalf("checked %d targets, want %d\n%s", got, maxAWDCheckTargets, out)
	}
	if !strings.Contains(out, "仅检查前 100 个") {
		t.Fatalf("missing cap notice: %s", out)
	}
}
