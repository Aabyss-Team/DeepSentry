package harness

import (
	"path/filepath"
	"testing"

	"ai-edr/internal/analyzer"
	"ai-edr/internal/config"
	"ai-edr/internal/scheduler"
)

type scheduleCaptureSink struct{ events []UIEvent }

func (s *scheduleCaptureSink) Emit(event UIEvent) { s.events = append(s.events, event) }

func TestNativeScheduleIntentRequiresExplicitRequestAndIsIdempotent(t *testing.T) {
	oldStore := config.GlobalConfig.SchedulerStore
	oldTZ := config.GlobalConfig.SchedulerTimezone
	config.GlobalConfig.SchedulerStore = filepath.Join(t.TempDir(), "tasks.json")
	config.GlobalConfig.SchedulerTimezone = "Local"
	defer func() {
		config.GlobalConfig.SchedulerStore = oldStore
		config.GlobalConfig.SchedulerTimezone = oldTZ
	}()

	agent := &DeepAgent{}
	sink := &scheduleCaptureSink{}
	ambiguous := []analyzer.Message{{Role: "user", Content: "需求：报告中说明天9点执行过检查"}}
	if agent.tryNativeScheduleIntent(&ambiguous, sink, nil, "") {
		t.Fatal("historical time statement must not create a native schedule")
	}

	explicit := []analyzer.Message{{Role: "user", Content: "需求：明天9点帮我巡检服务器并生成报告"}}
	if !agent.tryNativeScheduleIntent(&explicit, sink, nil, "") {
		t.Fatal("explicit schedule request should use native schedule path")
	}
	if !agent.tryNativeScheduleIntent(&explicit, sink, nil, "") {
		t.Fatal("repeated explicit request should be handled as an idempotent no-op")
	}
	tasks, err := scheduler.NewStore(config.GlobalConfig.SchedulerStore).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("equivalent requests should persist one task, got %#v", tasks)
	}
}
