package harness

import (
	"ai-edr/internal/collector"
	"ai-edr/internal/harness/subagent"
	"strings"
	"testing"
)

func TestAuthorizeSubAgentExecuteAllowsAIReviewedLowRisk(t *testing.T) {
	action := &AgentAction{Type: ActionExecute, Command: "echo hi > /tmp/out.txt"}
	confirmCalled := false
	reviewer := func(collector.SystemContext, string, string) (string, string, bool) {
		return "low", "只写入临时演示文件", true
	}

	allowed, feedback := authorizeSubAgentExecute(action, collector.SystemContext{}, false, nil, func(*AgentAction) bool {
		confirmCalled = true
		return false
	}, reviewer)
	if !allowed {
		t.Fatalf("expected AI-reviewed low risk command to run, feedback=%q", feedback)
	}
	if confirmCalled {
		t.Fatal("confirm should not be called after AI review marks command low risk")
	}
	if action.RiskLevel != "low" || !strings.Contains(action.Reason, "临时") {
		t.Fatalf("unexpected reviewed risk: risk=%q reason=%q", action.RiskLevel, action.Reason)
	}
}

func TestAuthorizeSubAgentExecuteConfirmsHighRiskCommand(t *testing.T) {
	action := &AgentAction{Type: ActionExecute, Command: "rm -rf /tmp/deepsentry-risk-test"}
	confirmCalled := false

	allowed, feedback := authorizeSubAgentExecute(action, collector.SystemContext{}, false, nil, func(a *AgentAction) bool {
		confirmCalled = true
		if a.RiskLevel != "high" {
			t.Fatalf("confirm should receive high risk action, got %q", a.RiskLevel)
		}
		return true
	}, nil)
	if !allowed {
		t.Fatalf("expected approved high risk command to run, feedback=%q", feedback)
	}
	if !confirmCalled {
		t.Fatal("expected high risk command to request confirmation")
	}
}

func TestAuthorizeSubAgentExecuteDeniesWhenConfirmationRejected(t *testing.T) {
	action := &AgentAction{Type: ActionExecute, Command: "rm -rf /tmp/deepsentry-risk-deny"}

	allowed, feedback := authorizeSubAgentExecute(action, collector.SystemContext{}, false, nil, func(*AgentAction) bool {
		return false
	}, nil)
	if allowed {
		t.Fatal("expected rejected high risk command to be denied")
	}
	if !strings.Contains(feedback, "请改用只读、低风险方式继续") {
		t.Fatalf("feedback should guide sub-agent to a safer plan, got %q", feedback)
	}
}

func TestResolveSubAgentMaxStepsCapsRequestedAndEstimate(t *testing.T) {
	spec := subagent.Spec{Name: "log-analyst", MaxSteps: 15}
	got := resolveSubAgentMaxSteps(spec, "完整分析 auth.log/syslog 登录失败、提权、异常 IP、时间线和证据链", 40, 24)
	if got != 24 {
		t.Fatalf("max steps should be capped by user limit, got %d", got)
	}

	got = resolveSubAgentMaxSteps(spec, "简单确认文件存在", 0, 15)
	if got != 15 {
		t.Fatalf("default cap/base should keep 15, got %d", got)
	}
}
