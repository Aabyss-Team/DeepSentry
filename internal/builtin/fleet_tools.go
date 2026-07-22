package builtin

import (
	"fmt"
	"strings"

	"ai-edr/internal/config"
	"ai-edr/internal/executor"
)

func FleetInventory(rt Runtime, selector string) (string, error) {
	targets := executor.MatchTargets(config.GlobalConfig.Targets, selector)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s Fleet Inventory\n", rt.tag()))
	if len(targets) == 0 {
		b.WriteString("(无匹配目标；请在 config.yaml targets 中配置)\n")
		return b.String(), nil
	}
	for _, t := range targets {
		b.WriteString(fmt.Sprintf("- %s protocol=%s host=%s user=%s tags=%s\n",
			executor.TargetDisplayName(t), t.Protocol, t.Host, t.User, strings.Join(t.Tags, ",")))
	}
	b.WriteString(fmt.Sprintf("下一步: inventory 只确认了 %d 个目标，尚未采集健康/日志证据；同项批量巡检请继续调用 fleet_exec(selector=%q, command=<只读巡检命令>)，文件取证用 fleet_file。\n",
		len(targets), emptyDefault(selector, "all")))
	return b.String(), nil
}

func FleetExec(rt Runtime, selector, command string, concurrency int) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("command 必填")
	}
	targets := executor.MatchTargets(config.GlobalConfig.Targets, selector)
	if len(targets) == 0 {
		return "", fmt.Errorf("无匹配目标: %s", selector)
	}
	results := executor.RunFleet(config.GlobalConfig.Targets, selector, command, concurrency)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s Fleet Exec selector=%s command=%s\n", rt.tag(), emptyDefault(selector, "all"), command))
	b.WriteString(executor.FormatFleetResults(results))
	return b.String(), nil
}

func FleetFile(rt Runtime, selector, action, remotePath, localPath string) (string, error) {
	targets := executor.MatchTargets(config.GlobalConfig.Targets, selector)
	if len(targets) == 0 {
		return "", fmt.Errorf("无匹配目标: %s", selector)
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s Fleet File action=%s selector=%s\n", rt.tag(), action, emptyDefault(selector, "all")))
	for _, t := range targets {
		out, err := executor.FleetFile(t, action, remotePath, localPath)
		name := executor.TargetDisplayName(t)
		if err != nil {
			b.WriteString(fmt.Sprintf("[ERR] %s: %v\n\n", name, err))
			continue
		}
		b.WriteString(fmt.Sprintf("[OK] %s\n%s\n\n", name, truncate(out, 4000)))
	}
	return b.String(), nil
}
