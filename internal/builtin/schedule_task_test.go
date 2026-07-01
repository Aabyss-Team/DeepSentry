package builtin

import (
	"strings"
	"testing"

	"ai-edr/internal/config"
)

func TestScheduleTaskPlan(t *testing.T) {
	oldStore := config.GlobalConfig.SchedulerStore
	oldTZ := config.GlobalConfig.SchedulerTimezone
	config.GlobalConfig.SchedulerStore = t.TempDir() + "/tasks.json"
	config.GlobalConfig.SchedulerTimezone = "Asia/Shanghai"
	defer func() {
		config.GlobalConfig.SchedulerStore = oldStore
		config.GlobalConfig.SchedulerTimezone = oldTZ
	}()

	out, err := ScheduleTask(NewRuntime("linux", false), map[string]string{
		"action": "plan",
		"text":   "明天9点巡检服务器并生成报告发钉钉通知",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "解析完成") || !strings.Contains(out, "dingtalk") || !strings.Contains(out, "inspection") {
		t.Fatalf("unexpected output: %s", out)
	}
}
