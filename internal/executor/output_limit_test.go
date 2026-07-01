package executor

import (
	"ai-edr/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutputCollectorTruncatesAndContinues(t *testing.T) {
	c := newOutputCollector(10)
	for _, line := range []string{"abcdefghij\n", "klmnopqrst\n"} {
		c.appendLine(line)
	}
	if !c.truncated {
		t.Fatal("expected truncation")
	}
	got := c.result()
	if !strings.Contains(got, "输出已截断") {
		t.Fatalf("expected truncation notice, got %q", got)
	}
	if len(strings.TrimSpace(strings.Split(got, "\n")[0])) > 20 {
		t.Fatalf("stored output too long: %q", got)
	}
}

func TestTruncateOutput(t *testing.T) {
	s := strings.Repeat("a", 100)
	got := truncateOutput(s, 50)
	if !strings.Contains(got, "输出已截断") {
		t.Fatalf("expected truncation notice")
	}
	if len(got) < 50 {
		t.Fatalf("truncated output too short")
	}
}

func TestLocalExecutorRunWithStreamingEmitsLines(t *testing.T) {
	var lines []string
	out, err := (&LocalExecutor{}).RunWithStreaming("printf 'one\\n'; printf 'two\\n'", func(line string) {
		lines = append(lines, line)
	})
	if err != nil {
		t.Fatalf("RunWithStreaming failed: %v", err)
	}
	if !strings.Contains(out, "one") || !strings.Contains(out, "two") {
		t.Fatalf("expected collected output to include both lines, got %q", out)
	}
	if len(lines) != 2 || lines[0] != "one\n" || lines[1] != "two\n" {
		t.Fatalf("expected two streamed lines, got %#v", lines)
	}
}

func TestLocalExecutorBlocksRawSSHLikeCommands(t *testing.T) {
	origTargets := config.GlobalConfig.Targets
	config.GlobalConfig.Targets = []config.TargetConfig{{
		Name:     "target-01",
		Protocol: "ssh",
		Host:     "10.204.1.249:2222",
		User:     "root",
		Password: "secret",
		Tags:     []string{"toolbox"},
	}}
	t.Cleanup(func() { config.GlobalConfig.Targets = origTargets })

	out, err := (&LocalExecutor{}).RunWithStreaming(`ssh -p 2222 root@10.204.1.249 "echo ok"`, nil)
	if err != nil {
		t.Fatalf("raw ssh should return guidance, not hard fail: %v", err)
	}
	for _, want := range []string{"已拦截控制端裸 ssh 命令", "不会读取 DeepSentry config.yaml", "fleet_exec", "target-01"} {
		if !strings.Contains(out, want) {
			t.Fatalf("raw ssh guidance missing %q:\n%s", want, out)
		}
	}
}

func TestLocalExecutorBlocksRawSCPCommand(t *testing.T) {
	out, err := (&LocalExecutor{}).RunWithStreaming(`scp root@10.0.0.1:/tmp/a ~/a`, nil)
	if err != nil {
		t.Fatalf("raw scp should return guidance, not hard fail: %v", err)
	}
	for _, want := range []string{"已拦截控制端裸 scp 命令", "fleet_file", "原始命令未执行"} {
		if !strings.Contains(out, want) {
			t.Fatalf("raw scp guidance missing %q:\n%s", want, out)
		}
	}
}

func TestRawSSHLikeCommandBlocksOnlyRemoteConnections(t *testing.T) {
	blockedCases := []string{
		`ssh -p 2222 root@10.204.1.249 "echo ok"`,
		`timeout 5 ssh root@10.204.1.249 true`,
		`env SSHPASS=x sshpass -e ssh root@10.204.1.249 true`,
		`scp ./flag.zip root@10.204.1.249:/tmp/flag.zip`,
		`scp -- ./flag.zip root@10.204.1.249:/tmp/flag.zip`,
		`sftp root@10.204.1.249`,
		`ssh root@10.204.1.249 echo -G`,
	}
	for _, cmd := range blockedCases {
		if _, blocked := blockRawSSHLikeCommand(cmd); !blocked {
			t.Fatalf("expected raw remote command to be blocked: %s", cmd)
		}
	}

	allowedCases := []string{
		`ssh -V`,
		`ssh -G root@10.204.1.249`,
		`scp -h`,
		`sftp -h`,
		`sftp -P 2222`,
	}
	for _, cmd := range allowedCases {
		_, blocked := blockRawSSHLikeCommand(cmd)
		if blocked {
			t.Fatalf("expected local/help command to be allowed: %s", cmd)
		}
	}
}

func TestParsePowerShellCommandKeepsRequestedShell(t *testing.T) {
	shell, script := parsePowerShellCommand(`pwsh -c "Write-Output ok"`)
	if shell != "pwsh" || script != "Write-Output ok" {
		t.Fatalf("expected pwsh command, got shell=%q script=%q", shell, script)
	}

	shell, script = parsePowerShellCommand(`powershell -Command "Get-Date"`)
	if shell != "powershell" || script != "Get-Date" {
		t.Fatalf("expected powershell command, got shell=%q script=%q", shell, script)
	}
}

func TestParseTransferCommandKeepsQuotedPaths(t *testing.T) {
	action, src, dst, ok := parseTransferCommand(`upload '/tmp/a b/source.txt' "/tmp/c d/dest.txt"`)
	if !ok {
		t.Fatal("expected command to parse")
	}
	if action != "upload" || src != "/tmp/a b/source.txt" || dst != "/tmp/c d/dest.txt" {
		t.Fatalf("unexpected parse: action=%q src=%q dst=%q", action, src, dst)
	}

	_, _, _, ok = parseTransferCommand(`download '/tmp/open`)
	if ok {
		t.Fatal("expected unterminated quote to fail")
	}
}

func TestExpandLocalPathExpandsHomePrefix(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got := expandLocalPath("~/Downloads/test_flag.zip")
	want := filepath.Join(home, "Downloads", "test_flag.zip")
	if got != want {
		t.Fatalf("expanded path=%q want %q", got, want)
	}
	if got := expandLocalPath("~literal/file"); got != "~literal/file" {
		t.Fatalf("non-home tilde should not expand, got %q", got)
	}
}

func TestCopyLocalFileExpandsTildeDestination(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	src := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(src, []byte("flag-data"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := copyLocalFile(src, "~/Downloads/test_flag.txt")
	if err != nil {
		t.Fatalf("copyLocalFile failed: %v", err)
	}
	want := filepath.Join(home, "Downloads", "test_flag.txt")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected expanded destination to exist: %v", err)
	}
	if strings.Contains(out, "~/Downloads") {
		t.Fatalf("result should report expanded destination, got %q", out)
	}
}
