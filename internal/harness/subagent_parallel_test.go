package harness

import (
	"ai-edr/internal/analyzer"
	"ai-edr/internal/collector"
	"ai-edr/internal/harness/subagent"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNormalizeParallelTasksFallsBackToSingleTask(t *testing.T) {
	action := &AgentAction{
		TaskName:       "log-analyst",
		TaskPrompt:     "分析登录日志",
		TargetSelector: "prod",
		TaskMaxSteps:   22,
	}
	tasks := normalizeParallelTasks(action)
	if len(tasks) != 1 {
		t.Fatalf("expected one fallback task, got %d", len(tasks))
	}
	if tasks[0].TaskName != "log-analyst" || tasks[0].TargetSelector != "prod" || tasks[0].TaskMaxSteps != 22 {
		t.Fatalf("fallback task fields lost: %#v", tasks[0])
	}
}

func TestNormalizeParallelTasksSkipsEmptyItems(t *testing.T) {
	action := &AgentAction{ParallelTasks: []SubAgentTaskAction{
		{},
		{TaskName: "log-analyst", TaskPrompt: "分析 auth.log"},
	}}
	tasks := normalizeParallelTasks(action)
	if len(tasks) != 1 || tasks[0].TaskName != "log-analyst" {
		t.Fatalf("unexpected normalized tasks: %#v", tasks)
	}
}

func TestSubAgentMiddlewareRejectsMissingTaskName(t *testing.T) {
	agent := &DeepAgent{State: NewAgentState(t.TempDir())}
	mw := &SubAgentMiddleware{Parent: agent}
	result, handled, err := mw.HandleAction(&StepContext{State: agent.State}, &AgentAction{
		Type:       ActionTask,
		TaskPrompt: "审计今天的登录日志",
	})
	if err != nil {
		t.Fatalf("missing task_name should not hard fail: %v", err)
	}
	if !handled || result == nil {
		t.Fatalf("missing task_name should be handled, result=%#v", result)
	}
	if !strings.Contains(result.Output, "task_name 为空") || strings.Contains(result.Output, "未知子 Agent") {
		t.Fatalf("expected format guidance, got:\n%s", result.Output)
	}
}

func TestParallelSubAgentMiddlewareRejectsMissingTaskName(t *testing.T) {
	agent := &DeepAgent{State: NewAgentState(t.TempDir())}
	mw := &SubAgentMiddleware{Parent: agent}
	result, handled, err := mw.HandleAction(&StepContext{State: agent.State}, &AgentAction{
		Type: ActionTask,
		ParallelTasks: []SubAgentTaskAction{
			{TaskPrompt: "审计 target-01 今天的登录日志", TargetSelector: "target-01"},
		},
	})
	if err != nil {
		t.Fatalf("missing parallel task_name should not hard fail: %v", err)
	}
	if !handled || result == nil {
		t.Fatalf("missing parallel task_name should be handled, result=%#v", result)
	}
	if !strings.Contains(result.Output, "parallel_tasks[0].task_name 为空") || strings.Contains(result.Output, "未知子 Agent") {
		t.Fatalf("expected parallel format guidance, got:\n%s", result.Output)
	}
}

func TestRunParallelSubAgentsSmokeCombinesResults(t *testing.T) {
	var calls int32
	parent := &DeepAgent{
		Middleware:     SubAgentMiddlewareStack(nil, nil),
		State:          NewAgentState(t.TempDir()),
		UseNativeTools: false,
	}
	mw := &SubAgentMiddleware{Parent: parent}
	origMake := makeSubAgentRunner
	makeSubAgentRunner = func(parent *DeepAgent) *SubAgentRunner {
		r := origMake(parent)
		r.StepFn = func(opts analyzer.StepOptions) (analyzer.AgentResponse, error) {
			n := atomic.AddInt32(&calls, 1)
			return analyzer.AgentResponse{
				Thought:     "parallel done",
				Action:      string(ActionFinish),
				FinalReport: "PARALLEL_OK_" + string(rune('0'+n)),
			}, nil
		}
		return r
	}
	defer func() { makeSubAgentRunner = origMake }()

	result, handled, err := mw.HandleAction(&StepContext{
		SysCtx:           collector.SystemContext{},
		State:            NewAgentState(t.TempDir()),
		BatchMode:        false,
		SubAgentMaxSteps: 5,
	}, &AgentAction{
		Type: ActionTask,
		ParallelTasks: []SubAgentTaskAction{
			{TaskName: "log-analyst", TaskPrompt: "日志：分析 auth.log", TaskMaxSteps: 5},
			{TaskName: "network-analyst", TaskPrompt: "网络：分析连接", TaskMaxSteps: 5},
		},
	})
	if err != nil {
		t.Fatalf("parallel sub-agent smoke failed: %v", err)
	}
	if !handled || result == nil {
		t.Fatalf("parallel task should be handled, result=%#v", result)
	}
	if !strings.Contains(result.Output, "并行子 Agent 协作结果") || !strings.Contains(result.Output, "log-analyst") || !strings.Contains(result.Output, "network-analyst") {
		t.Fatalf("combined output missing expected sections:\n%s", result.Output)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected 2 sub-agent calls, got %d", calls)
	}
}

func TestSubAgentMiddlewareUnknownAgentReturnsFriendlyError(t *testing.T) {
	agent := &DeepAgent{State: NewAgentState(t.TempDir())}
	mw := &SubAgentMiddleware{Parent: agent}
	result, handled, err := mw.HandleAction(&StepContext{State: agent.State}, &AgentAction{
		Type:       ActionTask,
		TaskName:   "missing-agent",
		TaskPrompt: "test",
	})
	if err != nil {
		t.Fatalf("unknown sub-agent should not hard fail: %v", err)
	}
	if !handled || result == nil || !strings.Contains(result.Output, "未知子 Agent") {
		t.Fatalf("unexpected unknown-agent result: handled=%v result=%#v", handled, result)
	}
}

func TestSubAgentTargetSelectorNoMatchReturnsFriendlyError(t *testing.T) {
	agent := &DeepAgent{State: NewAgentState(t.TempDir())}
	mw := &SubAgentMiddleware{Parent: agent}
	spec, ok := subagent.Find("log-analyst")
	if !ok {
		t.Fatal("log-analyst should exist")
	}
	result, handled, err := mw.runTargetSubAgents(&StepContext{State: agent.State}, *spec, &AgentAction{
		TaskName:       "log-analyst",
		TaskPrompt:     "test",
		TargetSelector: "definitely-no-such-target",
	})
	if err != nil {
		t.Fatalf("missing target selector should not hard fail: %v", err)
	}
	if !handled || result == nil || !strings.Contains(result.Output, "无匹配目标") {
		t.Fatalf("unexpected target selector result: handled=%v result=%#v", handled, result)
	}
}
