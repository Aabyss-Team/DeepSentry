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
	positives := []string{
		"明天9点帮我巡检服务器并生成报告发钉钉通知",
		"每天上午9点巡检生产服务器",
		"10分钟后提醒我检查备份",
		"创建定时任务：2026-08-01 09:30 生成报告",
	}
	for _, input := range positives {
		if ok, reason := DetectScheduleIntent(input); !ok {
			t.Errorf("expected schedule intent for %q, reason=%s", input, reason)
		}
	}

	negatives := []string{
		"检查 crontab 计划任务后门",
		"攻击者似乎篡改了系统命令，导致该命令一旦运行就会执行恶意回连的动作。提交回连的IP和端口，例如：1.1.1.1:1111",
		"**Q10：持久化项文件 md5（重启执行后门）**\n**答案**\n62aba584ae744fcb6ff4a9ffbc848041\n文件：/etc/systemd/system/syntime.service",
		"明天9点执行结果如下",
		"报告中说今天10:30运行过检查",
		"脚本每天9点会执行备份",
		"10分钟后执行结果显示检查成功",
		"[10:30:01] 执行检查失败 HTTP/1.1 500",
		"Q10：执行文件是什么？",
	}
	for _, input := range negatives {
		if ok, reason := DetectScheduleIntent(input); ok {
			t.Errorf("false positive schedule intent for %q, reason=%s", input, reason)
		}
	}
}

func TestExtractClockRejectsLabelsAndRequiresColonMinutes(t *testing.T) {
	for _, input := range []string{"Q10：", "Step 20: result", "CVE-2026-10: 执行"} {
		if h, m, ok := extractClock(input); ok {
			t.Errorf("%q parsed as %02d:%02d", input, h, m)
		}
	}
	if h, m, ok := extractClock("明天 10:30 巡检"); !ok || h != 10 || m != 30 {
		t.Fatalf("valid clock parse = %02d:%02d ok=%v", h, m, ok)
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

func TestPlanTaskRejectsPastExplicitDateAndInvalidCalendarDate(t *testing.T) {
	loc := time.FixedZone("test", 8*3600)
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, loc)
	for _, input := range []string{"今天9点帮我巡检服务器", "2026-02-30 09:00 帮我检查服务器"} {
		if _, err := PlanTask(PlanInput{Text: input, Timezone: "Asia/Shanghai"}, now); err == nil {
			t.Errorf("expected invalid schedule to fail: %q", input)
		}
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

func TestStoreAddUniquePreventsEquivalentDuplicates(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "tasks.json"))
	runAt := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	first := Task{ID: "sched_first", Prompt: "  每天 巡检服务器  ", Kind: KindInspection, RunAt: runAt, Timezone: "UTC", Repeat: RepeatDaily, Status: StatusEnabled}
	second := first
	second.ID = "sched_second"
	second.Prompt = "每天 巡检服务器"
	if _, created, err := store.AddUnique(first); err != nil || !created {
		t.Fatalf("first add: created=%v err=%v", created, err)
	}
	existing, created, err := store.AddUnique(second)
	if err != nil || created || existing.ID != first.ID {
		t.Fatalf("duplicate add: existing=%#v created=%v err=%v", existing, created, err)
	}
	tasks, err := store.Load()
	if err != nil || len(tasks) != 1 {
		t.Fatalf("stored tasks=%#v err=%v", tasks, err)
	}
}
