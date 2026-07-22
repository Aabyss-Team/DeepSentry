package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// SessionApprovalScope returns a conservative fingerprint for "allow similar
// actions for this session". File mutations intentionally ignore the changed
// content but retain both the operation and exact path. Commands and tools use
// their complete invocation. RedactedAction derives and stores this hash
// before removing secrets, so an approval never silently broadens
// to another command, target, tool action, or argument set.
func SessionApprovalScope(action *AgentAction) (key, label string) {
	if action == nil {
		return "", ""
	}
	target := strings.Join([]string{
		strings.TrimSpace(action.TargetProtocol),
		strings.TrimSpace(action.TargetName),
		strings.TrimSpace(action.TargetHost),
		strings.TrimSpace(action.TargetSelector),
	}, "|")

	switch action.Type {
	case ActionEditFile, ActionWriteFile:
		path := filepath.Clean(strings.TrimSpace(action.Path))
		if path == "." || path == "" {
			path = "<unspecified>"
		}
		return approvalScopeKey(string(action.Type), target, path),
			fmt.Sprintf("后续 `%s` 同一文件 `%s`", action.Type, path)
	case ActionExecute:
		return approvalScopeKey(string(action.Type), target, strings.TrimSpace(action.Command)),
			"后续在同一目标执行完全相同的命令"
	case ActionTool:
		invocation := action.ToolName + "|" + stableApprovalArgs(action.ToolArgs)
		return approvalScopeKey(string(action.Type), target, invocation),
			fmt.Sprintf("后续使用相同参数调用工具 `%s`", action.ToolName)
	case ActionToolBatch:
		parts := make([]string, 0, len(action.ToolCalls))
		for _, call := range action.ToolCalls {
			parts = append(parts, call.Name+"|"+stableApprovalArgs(call.Args))
		}
		return approvalScopeKey(string(action.Type), target, strings.Join(parts, "\n")),
			"后续执行完全相同的批量工具调用"
	default:
		identity := strings.Join([]string{action.TaskName, action.TaskPrompt, action.Path, action.Reason}, "|")
		return approvalScopeKey(string(action.Type), target, identity),
			fmt.Sprintf("后续执行相同的 `%s` 操作", action.Type)
	}
}

func approvalScopeKey(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func stableApprovalArgs(args map[string]string) string {
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(args[key])
		b.WriteByte('\n')
	}
	return b.String()
}
