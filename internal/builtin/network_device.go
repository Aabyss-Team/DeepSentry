package builtin

import (
	"fmt"
	"strings"

	"ai-edr/internal/executor"
)

// NetworkDeviceBaseline collects a deterministic, read-only evidence set for
// common switch/router CLIs. Unsupported commands do not abort the workflow.
func NetworkDeviceBaseline(rt Runtime, requestedProfile string) (string, error) {
	return runNetworkDeviceCommands(rt, requestedProfile, "full", networkBaselineCommands)
}

// NetworkDeviceDiagnose is the competition/incident fast path. It keeps the
// evidence set deterministic while avoiding a full seven-command baseline
// when the question is clearly about interfaces, routing, L2, or logs.
func NetworkDeviceDiagnose(rt Runtime, requestedProfile, focus string) (string, error) {
	focus = strings.ToLower(strings.TrimSpace(focus))
	if focus == "" {
		focus = "overview"
	}
	return runNetworkDeviceCommands(rt, requestedProfile, focus, func(profile string) []string {
		return networkDiagnosticCommands(profile, focus)
	})
}

func runNetworkDeviceCommands(rt Runtime, requestedProfile, focus string, commandsFor func(string) []string) (string, error) {
	if rt.Exec == nil {
		return "", fmt.Errorf("执行器未初始化")
	}
	profile := strings.ToLower(strings.TrimSpace(requestedProfile))
	prompt := ""
	if reporter, ok := rt.Exec.(executor.NetworkDeviceReporter); ok {
		info := reporter.NetworkDeviceInfo()
		if profile == "" || profile == "auto" {
			profile = info.Vendor
		}
		prompt = info.Prompt
	}
	if profile == "" || profile == "auto" || profile == "generic" {
		if strings.HasPrefix(prompt, "<") || strings.HasPrefix(prompt, "[") {
			profile = "huawei"
		} else {
			profile = "ruijie"
		}
	}
	commands := commandsFor(profile)
	if len(commands) == 0 {
		return "", fmt.Errorf("不支持的网络设备 profile/focus: %q/%q", profile, focus)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "【网络设备只读证据】profile=%s focus=%s prompt=%s\n", profile, focus, prompt)
	for _, command := range commands {
		fmt.Fprintf(&b, "\n=== %s ===\n", command)
		out, err := rt.Exec.Run(command)
		if err != nil {
			fmt.Fprintf(&b, "采集失败: %v\n", err)
			if strings.TrimSpace(out) != "" {
				b.WriteString(out + "\n")
			}
			continue
		}
		b.WriteString(out)
		if !strings.HasSuffix(out, "\n") {
			b.WriteByte('\n')
		}
	}
	return truncate(b.String(), 180000), nil
}

func networkDiagnosticCommands(profile, focus string) []string {
	profile = strings.ToLower(strings.TrimSpace(profile))
	focus = strings.ToLower(strings.TrimSpace(focus))
	display := profile == "huawei" || profile == "h3c"
	switch focus {
	case "overview":
		if display {
			return []string{"display version", "display device", "display interface brief"}
		}
		if profile == "ruijie" {
			return []string{"show version", "show device", "show interfaces status"}
		}
		if profile == "cisco" {
			return []string{"show version", "show inventory", "show interfaces status"}
		}
	case "interfaces":
		if display {
			return []string{"display interface brief", "display ip interface brief", "display interface"}
		}
		if profile == "ruijie" || profile == "cisco" {
			return []string{"show interfaces status", "show ip interface brief", "show interfaces"}
		}
	case "routing":
		if display {
			return []string{"display ip routing-table", "display ospf peer brief", "display ip interface brief"}
		}
		if profile == "ruijie" || profile == "cisco" {
			return []string{"show ip route", "show ip ospf neighbor", "show ip interface brief"}
		}
	case "l2":
		if display {
			return []string{"display vlan summary", "display stp brief", "display mac-address"}
		}
		if profile == "ruijie" || profile == "cisco" {
			return []string{"show vlan brief", "show spanning-tree summary", "show mac address-table dynamic"}
		}
	case "logs":
		if display {
			return []string{"display logbuffer", "display alarm active"}
		}
		if profile == "ruijie" || profile == "cisco" {
			return []string{"show logging", "show clock"}
		}
	case "full":
		return networkBaselineCommands(profile)
	}
	return nil
}

func networkBaselineCommands(profile string) []string {
	switch strings.ToLower(profile) {
	case "huawei", "h3c":
		return []string{"display version", "display device", "display interface brief", "display ip interface brief", "display ip routing-table", "display stp brief", "display logbuffer"}
	case "ruijie":
		return []string{"show version", "show device", "show interfaces status", "show ip interface brief", "show ip route", "show spanning-tree summary", "show logging"}
	case "cisco":
		return []string{"show version", "show inventory", "show interfaces status", "show ip interface brief", "show ip route", "show spanning-tree summary", "show logging"}
	default:
		return nil
	}
}
