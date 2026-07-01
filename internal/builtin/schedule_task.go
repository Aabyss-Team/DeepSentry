package builtin

import (
	"fmt"
	"strings"
	"time"

	"ai-edr/internal/config"
	"ai-edr/internal/scheduler"
)

func ScheduleTask(rt Runtime, args map[string]string) (string, error) {
	action := strings.ToLower(strings.TrimSpace(arg(args, "action")))
	if action == "" {
		action = "plan"
	}
	store := scheduler.NewStore(config.GlobalConfig.SchedulerStore)
	switch action {
	case "plan", "parse":
		plan, err := scheduler.PlanTask(schedulePlanInput(args), time.Now())
		if err != nil {
			return "", err
		}
		return formatSchedulePlan(plan, false), nil
	case "add", "create":
		plan, err := scheduler.PlanTask(schedulePlanInput(args), time.Now())
		if err != nil {
			return "", err
		}
		if err := store.Add(plan.Task); err != nil {
			return "", err
		}
		return formatSchedulePlan(plan, true), nil
	case "list":
		tasks, err := store.Load()
		if err != nil {
			return "", err
		}
		return formatScheduleList(tasks), nil
	case "remove", "delete":
		id := arg(args, "id", "task_id")
		if id == "" {
			return "", fmt.Errorf("id 必填")
		}
		removed, ok, err := store.Remove(id)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", fmt.Errorf("未找到任务: %s", id)
		}
		return fmt.Sprintf("已删除定时任务: %s (%s)", removed.ID, removed.Name), nil
	case "run", "run-now":
		id := arg(args, "id", "task_id")
		if id == "" {
			return "", fmt.Errorf("id 必填")
		}
		r := scheduler.NewRunner(config.GlobalConfig)
		out, err := r.RunNow(id, time.Now())
		if err != nil {
			return "", err
		}
		return out, nil
	case "run-due", "tick":
		r := scheduler.NewRunner(config.GlobalConfig)
		out, err := r.RunDue(time.Now())
		if err != nil {
			return "", err
		}
		return out, nil
	default:
		return "", fmt.Errorf("action 仅支持 plan|add|list|remove|run|run-due")
	}
}

func schedulePlanInput(args map[string]string) scheduler.PlanInput {
	return scheduler.PlanInput{
		Text:       arg(args, "text", "natural", "request"),
		Prompt:     arg(args, "task", "prompt", "goal"),
		RunAt:      arg(args, "run_at", "time", "at"),
		Repeat:     arg(args, "repeat", "recurrence"),
		Notify:     arg(args, "notify", "notification"),
		Selector:   arg(args, "selector", "target", "targets"),
		Kind:       arg(args, "kind", "type"),
		Timezone:   firstNonEmptyLocal(arg(args, "timezone", "tz"), config.GlobalConfig.SchedulerTimezone),
		Report:     optionalBool(args, "report"),
		AllowBatch: argBool(args, "allow_batch"),
	}
}

func optionalBool(args map[string]string, key string) *bool {
	raw, ok := args[key]
	if !ok {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(raw))
	b := v == "1" || v == "true" || v == "yes" || v == "y" || v == "on" || v == "是"
	return &b
}

func firstNonEmptyLocal(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func formatSchedulePlan(plan scheduler.Plan, saved bool) string {
	task := plan.Task
	status := "解析完成，尚未写入"
	if saved {
		status = "已写入定时任务"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s\n", status))
	b.WriteString(fmt.Sprintf("- ID: %s\n", task.ID))
	b.WriteString(fmt.Sprintf("- 名称: %s\n", task.Name))
	b.WriteString(fmt.Sprintf("- 类型: %s\n", task.Kind))
	b.WriteString(fmt.Sprintf("- 执行时间: %s (%s)\n", task.RunAt.Format("2006-01-02 15:04:05"), task.Timezone))
	b.WriteString(fmt.Sprintf("- 重复: %s\n", task.Repeat))
	b.WriteString(fmt.Sprintf("- 目标: %s\n", emptyDefault(task.Selector, "当前目标/all")))
	b.WriteString(fmt.Sprintf("- 报告: %v\n", task.Report))
	b.WriteString(fmt.Sprintf("- 通知: %s\n", task.Notify))
	if len(plan.Notes) > 0 {
		b.WriteString("\n说明:\n")
		for _, note := range plan.Notes {
			b.WriteString("- " + note + "\n")
		}
	}
	return b.String()
}

func formatScheduleList(tasks []scheduler.Task) string {
	if len(tasks) == 0 {
		return "无定时任务"
	}
	var b strings.Builder
	b.WriteString("定时任务列表\n")
	for _, task := range tasks {
		b.WriteString(fmt.Sprintf("- %s [%s] %s next=%s repeat=%s kind=%s notify=%s runs=%d\n",
			task.ID, task.Status, task.Name, task.RunAt.Format("2006-01-02 15:04:05"), task.Repeat, task.Kind, task.Notify, task.RunCount))
		if task.LastResult != "" {
			b.WriteString(fmt.Sprintf("  last: %s\n", task.LastResult))
		}
	}
	return b.String()
}
