package analyzer

import (
	"strings"
	"testing"
)

func TestExtractJSONPayload_MarkdownBlock(t *testing.T) {
	raw := "The lastb output is too massive for SSH pipe processing.\n\n```json\n" +
		`{"action":"tool","tool_name":"read_log","tool_args":{"path":"/var/log/auth.log","lines":500,"pattern":"Failed"}}` +
		"\n```"

	jsonPart, prose := extractJSONPayload(raw)
	if jsonPart == "" {
		t.Fatal("expected JSON extracted")
	}
	if !strings.Contains(jsonPart, `"action":"tool"`) {
		t.Fatalf("unexpected json: %s", jsonPart)
	}
	if prose == "" {
		t.Fatal("expected prose before json block")
	}
}

func TestExtractBalancedJSONObject(t *testing.T) {
	s := `prefix {"action":"execute","command":"ls"} suffix`
	obj := extractBalancedJSONObject(s)
	if obj != `{"action":"execute","command":"ls"}` {
		t.Fatalf("got %q", obj)
	}
}

func TestCleanJSON_MixedResponse(t *testing.T) {
	raw := "Let me read auth.log\n\n```json\n{\"action\":\"tool\",\"tool_name\":\"grep\"}\n```"
	out, prose := cleanJSON(raw)
	if !strings.Contains(out, `"tool_name"`) {
		t.Fatalf("cleanJSON failed: %q prose=%q", out, prose)
	}
	if prose == "" {
		t.Fatal("expected prose")
	}
}

func TestExtractClarificationQuestion(t *testing.T) {
	raw := "您好！为了设置每10分钟监控CPU使用率并发送到钉钉机器人，请提供 Webhook URL。"
	q := extractClarificationQuestion(raw)
	if q == "" {
		t.Fatal("expected clarification question to be detected")
	}
}

func TestDecodeJSONUnicodeEscapesInCommand(t *testing.T) {
	got := decodeJSONUnicodeEscapes(`chmod +x /opt/scripts/cpu_monitor.sh \u0026\u0026 ls -la /opt/scripts/cpu_monitor.sh`)
	if got != "chmod +x /opt/scripts/cpu_monitor.sh && ls -la /opt/scripts/cpu_monitor.sh" {
		t.Fatalf("unexpected command: %q", got)
	}
}

func TestTodoItemAcceptsNumericIDAndTitleDetail(t *testing.T) {
	raw := `{"id":1,"title":"修复签名逻辑","status":"in_progress","detail":"将 printf '%s' 改为 printf '%s\n'"}`
	var item TodoItem
	if err := item.UnmarshalJSON([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if item.ID != "1" {
		t.Fatalf("id=%q", item.ID)
	}
	if !strings.Contains(item.Content, "修复签名逻辑") || !strings.Contains(item.Content, "printf") {
		t.Fatalf("content not normalized: %q", item.Content)
	}
	if item.Status != "in_progress" {
		t.Fatalf("status=%q", item.Status)
	}
}

func TestAgentToolSchemaConstrainsSubAgentTasks(t *testing.T) {
	defs := AgentToolDefinitions()
	if len(defs) == 0 {
		t.Fatal("expected agent tool definitions")
	}
	props, ok := defs[0].Function.Parameters["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("properties missing or wrong type: %#v", defs[0].Function.Parameters["properties"])
	}
	action, ok := props["action"].(map[string]interface{})
	if !ok {
		t.Fatalf("action schema missing enum-friendly shape: %#v", props["action"])
	}
	if _, ok := action["enum"].([]string); !ok {
		t.Fatalf("action enum missing: %#v", action)
	}
	parallel, ok := props["parallel_tasks"].(map[string]interface{})
	if !ok {
		t.Fatalf("parallel_tasks schema missing: %#v", props["parallel_tasks"])
	}
	items, ok := parallel["items"].(map[string]interface{})
	if !ok {
		t.Fatalf("parallel_tasks items missing: %#v", parallel["items"])
	}
	required, ok := items["required"].([]string)
	if !ok {
		t.Fatalf("parallel_tasks items required missing: %#v", items["required"])
	}
	if len(required) != 2 || required[0] != "task_name" || required[1] != "task_prompt" {
		t.Fatalf("unexpected parallel task required fields: %#v", required)
	}
}
