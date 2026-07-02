package scheduler

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPlanTaskParsesTomorrowInspectionDingTalk(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 26, 15, 30, 0, 0, loc)
	plan, err := PlanTask(PlanInput{
		Text:     "明天9点帮我巡检服务器并生成巡检报告发钉钉通知给我",
		Timezone: "Asia/Shanghai",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 6, 27, 9, 0, 0, 0, loc)
	if !plan.Task.RunAt.Equal(want) {
		t.Fatalf("run_at mismatch: got %s want %s", plan.Task.RunAt, want)
	}
	if plan.Task.Kind != KindInspection {
		t.Fatalf("kind=%s", plan.Task.Kind)
	}
	if !plan.Task.Report {
		t.Fatal("inspection should enable report")
	}
	if plan.Task.Notify != NotifyDingTalk {
		t.Fatalf("notify=%s", plan.Task.Notify)
	}
}

func TestPlanTaskParsesMultiChannelNotify(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 26, 15, 30, 0, 0, loc)
	plan, err := PlanTask(PlanInput{
		Text:     "明天9点巡检服务器并生成报告，同时发钉钉、飞书和邮件通知",
		Timezone: "Asia/Shanghai",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Task.Notify != "dingtalk,feishu,email" {
		t.Fatalf("notify=%s", plan.Task.Notify)
	}
	channels := NotifyChannels(plan.Task.Notify)
	if len(channels) != 3 || channels[0] != NotifyDingTalk || channels[1] != NotifyFeishu || channels[2] != NotifyEmail {
		t.Fatalf("channels=%#v", channels)
	}
}

func TestNormalizeNotifyAliases(t *testing.T) {
	got := normalizeNotify("ding + lark + mail + ding")
	if got != "dingtalk,feishu,email" {
		t.Fatalf("notify=%s", got)
	}
}

func TestPlanTaskParsesRelativeTime(t *testing.T) {
	loc := time.FixedZone("test", 8*3600)
	now := time.Date(2026, 6, 26, 15, 0, 0, 0, loc)
	plan, err := PlanTask(PlanInput{Text: "10分钟后巡检", Timezone: "Local"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Task.RunAt.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("unexpected relative run_at: %s", plan.Task.RunAt)
	}
}

func TestLooksLikeScheduleIntent(t *testing.T) {
	if !LooksLikeSchedule("明天9点帮我巡检服务器并生成报告发钉钉通知") {
		t.Fatal("expected schedule intent")
	}
	if LooksLikeSchedule("检查 crontab 计划任务后门") {
		t.Fatal("crontab audit should not be treated as creating a schedule")
	}
	if LooksLikeSchedule("攻击者似乎篡改了系统命令，导致该命令一旦运行就会执行恶意回连的动作。提交回连的IP和端口，例如：1.1.1.1:1111") {
		t.Fatal("callback answer prompt should not be treated as creating a schedule")
	}
}

func TestPlanTaskDoesNotParseIPPortAsClock(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 2, 17, 25, 0, 0, loc)
	_, err = PlanTask(PlanInput{
		Text:     "攻击者似乎篡改了系统命令，导致该命令一旦运行就会执行恶意回连的动作。提交回连的IP和端口，例如：1.1.1.1:1111",
		Timezone: "Asia/Shanghai",
	}, now)
	if err == nil {
		t.Fatal("expected IP:port prompt to fail time parsing")
	}
}

func TestStoreAddRemove(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "tasks.json"))
	now := time.Now()
	task := Task{ID: "sched_test", Name: "test", RunAt: now, Status: StatusEnabled, Repeat: RepeatOnce}
	if err := store.Add(task); err != nil {
		t.Fatal(err)
	}
	tasks, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].ID != task.ID {
		t.Fatalf("unexpected tasks: %#v", tasks)
	}
	removed, ok, err := store.Remove(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || removed.ID != task.ID {
		t.Fatalf("remove failed: ok=%v removed=%#v", ok, removed)
	}
	tasks, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 0 {
		t.Fatalf("expected empty store, got %#v", tasks)
	}
}
