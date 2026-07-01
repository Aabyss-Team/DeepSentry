package scheduler

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ai-edr/internal/config"
	"ai-edr/internal/executor"
)

type Runner struct {
	Store      *Store
	Config     config.Config
	ConfigPath string
	Logf       func(string, ...any)
	mu         sync.Mutex
}

func NewRunner(cfg config.Config) *Runner {
	return &Runner{
		Store:  NewStore(cfg.SchedulerStore),
		Config: cfg,
	}
}

func (r *Runner) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		_, _ = r.RunDue(time.Now())
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				_, _ = r.RunDue(now)
			}
		}
	}()
}

func (r *Runner) RunDue(now time.Time) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Store == nil {
		r.Store = NewStore(r.Config.SchedulerStore)
	}
	due, err := r.Store.Due(now)
	if err != nil {
		return "", err
	}
	if len(due) == 0 {
		return "无到期定时任务", nil
	}
	var b strings.Builder
	for _, task := range due {
		updated := r.runOne(task, now)
		if err := r.Store.Update(updated); err != nil {
			b.WriteString(fmt.Sprintf("[ERR] %s 更新状态失败: %v\n", task.ID, err))
			continue
		}
		b.WriteString(fmt.Sprintf("[%s] %s -> %s\n", updated.ID, updated.Name, updated.LastResult))
	}
	return strings.TrimSpace(b.String()), nil
}

func (r *Runner) RunNow(id string, now time.Time) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tasks, err := r.Store.Load()
	if err != nil {
		return "", err
	}
	for _, task := range tasks {
		if task.ID == id {
			updated := r.runOne(task, now)
			if err := r.Store.Update(updated); err != nil {
				return "", err
			}
			return updated.LastResult, nil
		}
	}
	return "", fmt.Errorf("未找到任务: %s", id)
}

func (r *Runner) runOne(task Task, now time.Time) Task {
	if now.IsZero() {
		now = time.Now()
	}
	start := now
	task.LastRunAt = &start
	task.RunCount++
	task.UpdatedAt = now
	reportPath := ""
	result := ""
	var err error

	switch task.Kind {
	case KindInspection:
		reportPath, result, err = r.executeInspection(task, now)
	case KindAgent:
		reportPath, result, err = r.executeAgent(task, now)
	default:
		err = fmt.Errorf("未知任务类型: %s", task.Kind)
	}
	if reportPath != "" {
		task.LastReportPath = reportPath
	}
	if err != nil {
		task.LastResult = "失败: " + err.Error()
	} else {
		task.LastResult = result
	}
	if task.Notify != NotifyNone && reportPath != "" {
		task.LastResult += r.notifyTask(task, reportPath)
	}
	task.RunAt = nextRun(task, now)
	if task.Repeat == RepeatOnce {
		task.Status = StatusCompleted
	}
	return task
}

func (r *Runner) executeInspection(task Task, now time.Time) (string, string, error) {
	command := inspectionCommand()
	var b strings.Builder
	b.WriteString("# DeepSentry 定时巡检报告\n\n")
	b.WriteString(fmt.Sprintf("- 任务: %s\n", task.Name))
	b.WriteString(fmt.Sprintf("- ID: %s\n", task.ID))
	b.WriteString(fmt.Sprintf("- 时间: %s\n", now.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("- 类型: %s\n", task.Kind))
	b.WriteString(fmt.Sprintf("- 目标选择器: %s\n", emptyDefault(task.Selector, "当前目标/all")))
	b.WriteString("\n---\n\n")

	if len(r.Config.Targets) > 0 {
		selector := task.Selector
		if strings.TrimSpace(selector) == "" {
			selector = "all"
		}
		results := executor.RunFleet(r.Config.Targets, selector, command, 3)
		b.WriteString(executor.FormatFleetResults(results))
	} else if executor.Current != nil {
		out, err := executor.Current.Run(command)
		b.WriteString("## 当前目标\n\n")
		b.WriteString("```text\n")
		b.WriteString(truncateReport(out, 24000))
		b.WriteString("\n```\n")
		if err != nil {
			b.WriteString(fmt.Sprintf("\n执行错误: %v\n", err))
		}
	} else {
		return "", "", fmt.Errorf("执行器未初始化")
	}

	reportPath, err := writeScheduleReport(task.ID, now, b.String())
	if err != nil {
		return "", "", err
	}
	return reportPath, "巡检完成，报告: " + reportPath, nil
}

func (r *Runner) executeAgent(task Task, now time.Time) (string, string, error) {
	if !task.AllowBatch {
		return "", "", fmt.Errorf("泛化 Agent 定时任务需要 allow_batch=true；巡检场景请使用 kind=inspection")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	args := []string{"--no-tui", "--quiet", "--batch", "-y", "--task", task.Prompt}
	if strings.TrimSpace(r.ConfigPath) != "" {
		args = append([]string{"-c", r.ConfigPath}, args...)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = os.Environ()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	content := fmt.Sprintf("# DeepSentry 定时 Agent 任务报告\n\n- 任务: %s\n- ID: %s\n- 时间: %s\n\n```text\n%s\n```\n",
		task.Name, task.ID, now.Format("2006-01-02 15:04:05"), truncateReport(out.String(), 30000))
	reportPath, writeErr := writeScheduleReport(task.ID, now, content)
	if writeErr != nil {
		return "", "", writeErr
	}
	if err != nil {
		return reportPath, "", fmt.Errorf("agent batch 执行失败: %w", err)
	}
	return reportPath, "Agent 任务完成，报告: " + reportPath, nil
}

func (r *Runner) notifyTask(task Task, reportPath string) string {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return "；通知失败: " + err.Error()
	}
	title := "DeepSentry 定时任务: " + task.Name
	text := string(data)
	if strings.TrimSpace(text) == "" {
		text = title
	}
	channels := NotifyChannels(task.Notify)
	if len(channels) == 0 {
		return ""
	}
	results := make([]string, 0, len(channels))
	for _, ch := range channels {
		label, notifyErr := r.sendNotification(ch, title, text)
		if notifyErr != nil {
			results = append(results, fmt.Sprintf("%s通知失败: %v", label, notifyErr))
		} else {
			results = append(results, label+"已通知")
		}
	}
	if len(results) == 0 {
		return ""
	}
	return "；" + strings.Join(results, "；")
}

func (r *Runner) sendNotification(channel, title, text string) (string, error) {
	switch channel {
	case NotifyDingTalk:
		return "钉钉", SendDingTalkMarkdown(r.Config.DingTalkWebhook, r.Config.DingTalkSecret, title, text)
	case NotifyFeishu:
		return "飞书", SendFeishuMarkdown(r.Config.FeishuWebhook, r.Config.FeishuSecret, title, text)
	case NotifyEmail:
		return "邮件", SendEmailGatewayMarkdown(r.Config.EmailGatewayURL, r.Config.EmailGatewayToken, r.Config.EmailGatewayHeader, r.Config.EmailTo, r.Config.EmailFrom, title, text)
	default:
		return channel, fmt.Errorf("未知通知通道: %s", channel)
	}
}

func nextRun(task Task, now time.Time) time.Time {
	next := task.RunAt
	switch task.Repeat {
	case RepeatDaily:
		for !next.After(now) {
			next = next.AddDate(0, 0, 1)
		}
	case RepeatWeekly:
		for !next.After(now) {
			next = next.AddDate(0, 0, 7)
		}
	case RepeatInterval:
		sec := task.IntervalSec
		if sec <= 0 {
			sec = 3600
		}
		for !next.After(now) {
			next = next.Add(time.Duration(sec) * time.Second)
		}
	}
	return next
}

func writeScheduleReport(id string, now time.Time, content string) (string, error) {
	dir := filepath.Join("reports", "schedules")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("report_%s_%s.md", id, now.Format("20060102_150405")))
	return path, os.WriteFile(path, []byte(content), 0600)
}

func inspectionCommand() string {
	return `printf '== HOST ==\n'; (hostname 2>/dev/null || uname -n 2>/dev/null || true); date 2>/dev/null || true; uptime 2>/dev/null || true; printf '\n== DISK ==\n'; df -h 2>/dev/null || true; printf '\n== MEMORY ==\n'; (free -m 2>/dev/null || cat /proc/meminfo 2>/dev/null | head -40 || true); printf '\n== LISTEN ==\n'; (ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || cat /proc/net/tcp 2>/dev/null | head -30 || true); printf '\n== TOP PROCESS ==\n'; (ps aux --sort=-%cpu 2>/dev/null | head -15 || ps -ef 2>/dev/null | head -15 || true)`
}

func truncateReport(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n...(报告内容过长已截断)..."
}

func emptyDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
