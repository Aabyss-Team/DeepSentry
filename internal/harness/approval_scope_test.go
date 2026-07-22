package harness

import "testing"

func TestSessionApprovalScopeFileMutationIsBoundToTypeAndExactPath(t *testing.T) {
	first, label := SessionApprovalScope(&AgentAction{Type: ActionEditFile, Path: "/tmp/site.html", OldString: "a", NewString: "b"})
	second, _ := SessionApprovalScope(&AgentAction{Type: ActionEditFile, Path: "/tmp/site.html", OldString: "b", NewString: "c"})
	otherPath, _ := SessionApprovalScope(&AgentAction{Type: ActionEditFile, Path: "/tmp/other.html", OldString: "a", NewString: "b"})
	write, _ := SessionApprovalScope(&AgentAction{Type: ActionWriteFile, Path: "/tmp/site.html", Content: "new"})

	if first == "" || label == "" || first != second {
		t.Fatalf("repeated edits of one file must share a useful scope: %q %q %q", first, second, label)
	}
	if first == otherPath || first == write {
		t.Fatal("file approval scope broadened across another path or mutation type")
	}
}

func TestSessionApprovalScopeCommandsAndToolsRemainExact(t *testing.T) {
	command, _ := SessionApprovalScope(&AgentAction{Type: ActionExecute, Command: "rm /tmp/a", TargetHost: "host-a"})
	otherCommand, _ := SessionApprovalScope(&AgentAction{Type: ActionExecute, Command: "rm /tmp/b", TargetHost: "host-a"})
	otherTarget, _ := SessionApprovalScope(&AgentAction{Type: ActionExecute, Command: "rm /tmp/a", TargetHost: "host-b"})
	if command == otherCommand || command == otherTarget {
		t.Fatal("command session approval broadened across command or target")
	}

	tool, _ := SessionApprovalScope(&AgentAction{Type: ActionTool, ToolName: "config_manage", ToolArgs: map[string]string{"action": "set", "key": "a"}})
	otherArgs, _ := SessionApprovalScope(&AgentAction{Type: ActionTool, ToolName: "config_manage", ToolArgs: map[string]string{"action": "set", "key": "b"}})
	if tool == otherArgs {
		t.Fatal("tool session approval broadened across arguments")
	}
}

func TestRedactedActionCarriesScopeDerivedBeforeSecretRedaction(t *testing.T) {
	action := AgentAction{Type: ActionTool, ToolName: "redis_probe", ToolArgs: map[string]string{
		"host": "127.0.0.1", "password": "first-secret",
	}}
	wantKey, wantLabel := SessionApprovalScope(&action)
	redacted := RedactedAction(action)
	if redacted.ApprovalScopeKey != wantKey || redacted.ApprovalScopeLabel != wantLabel {
		t.Fatal("redacted confirmation lost its original approval fingerprint")
	}

	other := action
	other.ToolArgs = map[string]string{"host": "127.0.0.1", "password": "second-secret"}
	otherRedacted := RedactedAction(other)
	if redacted.ApprovalScopeKey == otherRedacted.ApprovalScopeKey {
		t.Fatal("different original secret-bearing invocations shared one approval scope")
	}
}
