package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"ai-edr/internal/analyzer"
	"ai-edr/internal/collector"
	"ai-edr/internal/config"
	"ai-edr/internal/executor"
	"ai-edr/internal/harness"
	"ai-edr/internal/harness/subagent"
	"ai-edr/internal/logger"
	"ai-edr/internal/scheduler"
	"ai-edr/internal/tools"
	"ai-edr/internal/tui"
	"ai-edr/internal/ui"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

func main() {
	// 1. 跨平台控制台初始化
	enableWindowsANSI()
	defer ui.ResetTerminalState()

	// 🟢 [核心增强] 强制设置 Windows 控制台代码页为 UTF-8
	// 这解决了即便开启了 ANSI 渲染，底层系统命令输出依然可能坚持使用 GBK 的问题
	if runtime.GOOS == "windows" {
		_ = exec.Command("cmd", "/c", "chcp 65001").Run()
	}

	// 2. Flag 解析
	configFile := flag.String("c", "", "指定配置文件路径")
	batchMode := flag.Bool("batch", false, "开启无人值守模式")
	autoYes := flag.Bool("y", false, "跳过 batch 模式确认")
	reconf := flag.Bool("init", false, "强制重新配置")
	resumeSession := flag.String("resume", "", "恢复 checkpoint 会话 ID")
	listSessions := flag.Bool("list-sessions", false, "列出可恢复的会话")
	pickSession := flag.Bool("pick-session", false, "TUI 选择 checkpoint 会话")
	tuiMode := flag.Bool("tui", true, "启用全屏 TUI 界面（默认）")
	noTUI := flag.Bool("no-tui", false, "使用经典 stdout CLI")
	taskFlag := flag.String("task", "", "任务描述（agent/脚本推荐）")
	taskShort := flag.String("q", "", "任务描述（--task 简写）")
	planMode := flag.Bool("plan", false, "计划模式：必要时先追问，再生成 todo 计划并执行")
	subAgentMaxStepsFlag := flag.Int("subagent-max-steps", 0, "子 Agent 最大步数上限（默认读取 config.yaml: subagent_max_steps，未配置为 15）")
	jsonOutput := flag.Bool("json", false, "经典模式输出 JSONL 事件")
	quiet := flag.Bool("quiet", false, "经典模式仅输出关键结果和错误")
	webshellMode := flag.Bool("webshell", false, "WebShell/非 TTY 友好模式（提交后台执行，立即返回报告/进度路径）")
	noColor := flag.Bool("no-color", false, "禁用彩色输出（也可设置 NO_COLOR=1 或 DEEPSENTRY_NO_COLOR=1）")
	schedulerMode := flag.Bool("scheduler", false, "仅运行本地定时任务调度器")
	showVersion := flag.Bool("version", false, "显示版本")
	showHelp := flag.Bool("h", false, "显示帮助")
	showHelpLong := flag.Bool("help", false, "显示帮助")
	flag.Usage = printUsage
	flag.Parse()
	if *noColor {
		_ = os.Setenv("DEEPSENTRY_NO_COLOR", "1")
		_ = os.Setenv("NO_COLOR", "1")
	}
	configureSurveyCompatibility()
	tui.ConfigureTerminalPreferences()
	if *webshellMode {
		*noTUI = true
		*quiet = true
		*batchMode = true
		*autoYes = true
	}
	if *schedulerMode {
		*noTUI = true
		*quiet = true
	}
	if *noTUI {
		*tuiMode = false
	}
	nonInteractive := *jsonOutput || *quiet
	if nonInteractive && !flagWasPassed("tui") {
		*tuiMode = false
	}

	if *showHelp || *showHelpLong {
		printUsage()
		return
	}
	if *showVersion {
		fmt.Printf("DeepSentry v%s Ultimate (build %s)\n", ui.Version, ui.BuildTime)
		return
	}

	if !*tuiMode && !nonInteractive {
		ui.PrintBanner()
		fmt.Println(ui.Prefix("💡", "[TIP]") + "提示: 默认会进入全屏 Agent 面板；使用 --no-tui 切换经典输出")
		fmt.Println(ui.Prefix("📖", "[DOC]") + "完整手册: docs/操作手册.md  ·  --help 查看命令")
		fmt.Println()
	}

	if *listSessions {
		ids, err := harness.ListSessions()
		if err != nil {
			if *jsonOutput {
				printJSON(map[string]any{"error": err.Error()})
			} else {
				fmt.Printf("%s列出会话失败: %v\n", ui.Prefix("❌", "[ERR]"), err)
			}
			ui.Exit(1)
			return
		}
		if *jsonOutput {
			printJSON(map[string]any{"sessions": ids})
			return
		}
		if len(ids) == 0 {
			fmt.Println("无可恢复会话")
			return
		}
		fmt.Println("可恢复会话:")
		for _, id := range ids {
			fmt.Printf("  - %s\n", id)
		}
		return
	}

	// 3. 配置加载
	err := config.InitConfig(*configFile)
	needWizard := *reconf
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			needWizard = true
		} else {
			fmt.Printf("%s配置文件加载失败: %v\n", ui.Prefix("❌", "[ERR]"), err)
			ui.Exit(1)
		}
	}
	startup := tui.StartupInfo{
		Version:   ui.Version,
		BuildTime: ui.BuildTime,
	}
	if wd, err := os.Getwd(); err == nil {
		startup.WorkDir = wd
	}
	if *tuiMode {
		startup.ToolCount = tools.CountEnabled()
	}

	if needWizard {
		if nonInteractive || !isInteractiveTerminal() {
			if *jsonOutput {
				printJSON(map[string]any{
					"error":   "missing_config",
					"message": "未检测到配置文件；请先运行 deepsentry --init，或通过 -c 指定配置文件。",
				})
			} else {
				fmt.Println(ui.Prefix("❌", "[ERR]") + "未检测到配置文件。请先运行: deepsentry --init")
			}
			ui.Exit(1)
		}
		fmt.Println(ui.Prefix("⚠️", "[WARN]") + "未检测到配置文件或请求重新初始化，进入向导模式...")
		if err := runElegantWizard(); err != nil {
			fmt.Printf("%s向导中断: %v\n", ui.Prefix("❌", "[ERR]"), err)
			ui.Exit(1)
		}
	} else {
		msg := fmt.Sprintf("已加载配置: %s", viper.ConfigFileUsed())
		if *tuiMode {
			startup.ConfigPath = viper.ConfigFileUsed()
		} else if !*jsonOutput {
			fmt.Printf("%s%s\n", ui.Prefix("📂", "[CFG]"), ui.StripANSIIfPlain("\033[1;32m"+msg+"\033[0m"))
		}
	}

	// 4. 获取用户需求 / 恢复会话
	var history []analyzer.Message
	sessionID := *resumeSession
	awaitGoal := false
	resumeSupplement := resumeUserSupplement(*taskFlag, *taskShort, flag.Args())

	if *pickSession && *tuiMode {
		id, cancelled, err := tui.PickSession()
		if err != nil {
			fmt.Printf("%s会话选择失败: %v\n", ui.Prefix("❌", "[ERR]"), err)
			return
		}
		if cancelled {
			return
		}
		sessionID = id
	}

	if sessionID != "" {
		cp, err := harness.LoadCheckpoint(sessionID)
		if err != nil {
			fmt.Printf("%s恢复会话失败: %v\n", ui.Prefix("❌", "[ERR]"), err)
			return
		}
		history = cp.History
		if len(history) == 0 {
			history = []analyzer.Message{{Role: "user", Content: "继续之前的任务"}}
		}
		if strings.TrimSpace(resumeSupplement) != "" {
			history = append(history, analyzer.Message{
				Role:    "user",
				Content: "用户补充：" + strings.TrimSpace(resumeSupplement),
			})
		}
		if !*tuiMode {
			fmt.Printf("%s已恢复会话 %s (step %d)\n", ui.Prefix("♻️", "[RESUME]"), sessionID, cp.StepNum)
			if strings.TrimSpace(resumeSupplement) != "" {
				fmt.Println(ui.Prefix("💡", "[TIP]") + "已追加本次 --task/参数作为用户补充并继续执行")
			}
		}
	} else {
		userGoal := ""
		args := flag.Args()
		if strings.TrimSpace(*taskFlag) != "" {
			userGoal = *taskFlag
		} else if strings.TrimSpace(*taskShort) != "" {
			userGoal = *taskShort
		} else if len(args) < 1 {
			if *tuiMode {
				awaitGoal = true
			} else if *schedulerMode {
				userGoal = ""
			} else if nonInteractive {
				if *jsonOutput {
					printJSON(map[string]any{
						"error":   "missing_task",
						"message": "非交互模式需要 --task/-q 或任务描述参数。",
						"example": "deepsentry --json --task \"审计 SSH 登录日志\"",
					})
				} else {
					fmt.Println(ui.Prefix("❌", "[ERR]") + "非交互模式需要任务描述。示例: deepsentry --quiet --task \"审计 SSH 登录日志\"")
				}
				ui.Exit(1)
			} else {
				prompt := &survey.Input{
					Message: ui.Prefix("🎯", "[TASK]") + "请输入您的安全应急需求:",
					Help:    "示例: 排查内存异常 | 审计监听端口 | 分析 auth.log 暴力破解 | 查找 webshell",
					Suggest: func(toComplete string) []string {
						hints := []string{
							"排查目标机内存与监听端口",
							"分析 SSH 登录失败记录",
							"审计网络暴露面与异常连接",
							"在 Web 目录狩猎 webshell",
							"读取 /var/log/syslog 最近错误",
						}
						if toComplete == "" {
							return hints
						}
						var out []string
						for _, h := range hints {
							if strings.Contains(h, toComplete) {
								out = append(out, h)
							}
						}
						return out
					},
				}
				if err := askOne(prompt, &userGoal); err != nil {
					fmt.Println("\n" + ui.Prefix("❌", "[ERR]") + "操作已取消")
					return
				}
				ui.ResetTerminalState()
				if strings.TrimSpace(userGoal) == "" {
					fmt.Println(ui.Prefix("❌", "[ERR]") + "未提供需求，程序退出。")
					return
				}
			}
		} else {
			userGoal = strings.Join(args, " ")
		}
		if userGoal != "" {
			history = []analyzer.Message{
				{Role: "user", Content: fmt.Sprintf("需求：%s", userGoal)},
			}
		}
	}

	if *webshellMode && os.Getenv("DEEPSENTRY_WEBSHELL_CHILD") != "1" {
		reportPath, progressPath, latestPath, err := launchDetachedWebShell(logger.TitleFromHistory(history))
		if err != nil {
			fmt.Printf("[WEB] 后台任务启动失败: %v\n", err)
			ui.Exit(1)
			return
		}
		printWebShellDetachedNotice(reportPath, progressPath, latestPath)
		return
	}

	// 5. 初始化执行环境
	if *jsonOutput {
		executor.SetModeOutputEnabled(false)
	}
	for {
		if *tuiMode {
			out := captureStdout(func() {
				err = executor.Init(config.GlobalConfig)
			})
			absorbStartupOutput(&startup, out)
		} else {
			err = executor.Init(config.GlobalConfig)
		}
		if err == nil {
			break
		}

		if config.GlobalConfig.SSHHost != "" {
			if nonInteractive || !isInteractiveTerminal() {
				emitInitFailure(*jsonOutput, "ssh_connect_failed", fmt.Sprintf("SSH 连接失败: %v", err))
				ui.Exit(1)
			}
			fmt.Printf("\n%s%s\n", ui.Prefix("❌", "[ERR]"), ui.StripANSIIfPlain(fmt.Sprintf("\033[1;31mSSH 连接失败: %v\033[0m", err)))
			choice := ""
			prompt := &survey.Select{
				Message: "检测到 SSH 连接失败，请选择操作:",
				Options: []string{
					ui.Prefix("🔧", "[CFG]") + "修改 SSH 配置 (重新输入密码)",
					ui.Prefix("💻", "[LOCAL]") + "切换为 本地模式 (清除 SSH 配置)",
					ui.Prefix("❌", "[EXIT]") + "退出程序",
				},
			}
			if err := askOne(prompt, &choice); err != nil {
				fmt.Printf("%sSSH 连接失败且未选择处理方式: %v\n", ui.Prefix("❌", "[ERR]"), err)
				ui.Exit(1)
			}
			ui.ResetTerminalState()
			if strings.Contains(choice, "修改 SSH 配置") {
				runSSHWizard(false)
				continue
			} else if strings.Contains(choice, "切换为 本地模式") {
				config.GlobalConfig.SSHHost = ""
				viper.Set("ssh_host", "")
				continue
			} else {
				ui.Exit(1)
			}
		}
		emitInitFailure(*jsonOutput, "executor_init_failed", fmt.Sprintf("初始化执行环境失败: %v", err))
		ui.Exit(1)
	}
	defer executor.Current.Close()

	schedRunner := scheduler.NewRunner(config.GlobalConfig)
	schedRunner.ConfigPath = viper.ConfigFileUsed()
	schedCtx, schedCancel := context.WithCancel(context.Background())
	defer schedCancel()
	if *schedulerMode {
		fmt.Printf("%sDeepSentry 定时任务调度器已启动，store=%s interval=%s\n", ui.Prefix("⏱️", "[TIME]"), schedRunner.Store.Path, schedulerInterval())
		schedRunner.Start(schedCtx, schedulerInterval())
		waitForSignal()
		return
	}
	if config.GlobalConfig.SchedulerEnabled {
		schedRunner.Start(schedCtx, schedulerInterval())
		if *tuiMode {
			startup.Notices = append(startup.Notices, fmt.Sprintf("定时任务调度已启用：%s", schedRunner.Store.Path))
		}
	}

	// 6. Batch Mode 确认
	if *batchMode && !*autoYes && !*tuiMode {
		fmt.Println("\n" + ui.TerminalText("\033[41;37m ⚠️  警告：无人值守模式 (BATCH MODE) 已开启 ⚠️ \033[0m"))
		confirm := false
		prompt := &survey.Confirm{
			Message: "确认要在无人值守模式下运行吗?",
			Default: false,
		}
		_ = askOne(prompt, &confirm)
		ui.ResetTerminalState()
		if !confirm {
			return
		}
	}
	if *batchMode && *tuiMode {
		startup.Notices = append(startup.Notices, "Batch 模式已开启：高风险操作会自动批准，请确认目标环境可接受。")
	}
	if *planMode && *tuiMode {
		startup.Notices = append(startup.Notices, "计划模式已开启：Agent 会先澄清/规划，再继续执行。")
	}

	// 7. 初始化报告
	reporter, reportPath, _ := logger.NewReporterWithTitle(logger.TitleFromHistory(history))
	if reporter != nil {
		defer reporter.Close()
		if *tuiMode {
			startup.ReportPath = reportPath
		} else if !*jsonOutput {
			fmt.Printf("[*] 审计日志: %s\n", reportPath)
		}
	}

	// 8. 环境感知
	if !*tuiMode && !*jsonOutput {
		fmt.Println(ui.Prefix("🔍", "[SCAN]") + "正在采集系统指纹...")
	}
	sysCtx := collector.GetSystemContext()

	connInfo := "本地模式"
	switch executor.CurrentMode() {
	case "ssh":
		connInfo = fmt.Sprintf("SSH -> %s", config.GlobalConfig.SSHHost)
	case "telnet":
		connInfo = fmt.Sprintf("Telnet -> %s", config.GlobalConfig.TelnetHost)
	case "ftp":
		connInfo = fmt.Sprintf("FTP -> %s", config.GlobalConfig.FTPHost)
	}
	if len(config.GlobalConfig.Targets) > 0 && executor.CurrentMode() == "local" {
		connInfo = fmt.Sprintf("Fleet 多目标: %d 台", len(config.GlobalConfig.Targets))
	}

	if *tuiMode {
		startup.ConnInfo = connInfo
		startup.OS = sysCtx.OS
		startup.Arch = sysCtx.Arch
		startup.Username = sysCtx.Username
		startup.Hostname = sysCtx.Hostname
		startup.ModelInfo = fmt.Sprintf("%s / %s", config.GlobalConfig.Provider, config.GlobalConfig.ModelName)
		startup.TargetCount = len(config.GlobalConfig.Targets)
		startup.MCPCount = len(config.GlobalConfig.MCPServers)
		startup.NativeTools = config.GlobalConfig.UseNativeTools
		executor.SetModeOutputEnabled(false)
	} else {
		executor.SetModeOutputEnabled(!*jsonOutput)
		if !*jsonOutput {
			fmt.Println("--------------------------------------------------")
			fmt.Printf("[+] 连接状态: %s\n", ui.StripANSIIfPlain("\033[1;33m"+connInfo+"\033[0m"))
			fmt.Printf("[+] 目标系统: %s / %s\n", sysCtx.OS, sysCtx.Arch)
			fmt.Printf("[+] 用户信息: %s\n", sysCtx.Username)
			fmt.Printf("[+] LLM: %s / %s\n", config.GlobalConfig.Provider, config.GlobalConfig.ModelName)
			fmt.Println("--------------------------------------------------")
		}
	}

	// 9. 启动 Deep Agent Harness 分析循环
	var agent *harness.DeepAgent
	if *tuiMode {
		out := captureStdout(func() {
			agent, err = harness.NewDeepAgent(harness.Config{
				BatchMode: *batchMode,
				SessionID: sessionID,
			})
		})
		absorbStartupOutput(&startup, out)
	} else {
		agent, err = harness.NewDeepAgent(harness.Config{
			BatchMode: *batchMode,
			SessionID: sessionID,
		})
	}
	if err != nil {
		if *jsonOutput {
			printJSON(map[string]any{"error": "agent_init_failed", "message": err.Error()})
		} else {
			fmt.Printf("%sDeep Agent 初始化失败: %v\n", ui.Prefix("❌", "[ERR]"), err)
		}
		ui.Exit(1)
	}

	if sessionID != "" {
		if cp, err := harness.LoadCheckpoint(sessionID); err == nil {
			agent.RestoreFromCheckpoint(cp)
		}
	}

	maxSteps := viper.GetInt("max_steps")
	if maxSteps <= 0 {
		maxSteps = 30
	}
	subAgentMaxSteps := viper.GetInt("subagent_max_steps")
	if *subAgentMaxStepsFlag > 0 {
		subAgentMaxSteps = *subAgentMaxStepsFlag
	}
	if subAgentMaxSteps <= 0 {
		subAgentMaxSteps = 15
	}

	confirmFn := func(action *harness.AgentAction) bool {
		confirm := false
		reason := action.Reason
		if action.Type == harness.ActionExecute {
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("%s风险: 高 (%s) -> 是否执行?", ui.Prefix("🔴", "[HIGH]"), reason),
				Default: false,
			}
			_ = askOne(prompt, &confirm)
		} else {
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("%s确认执行 %s?", ui.Prefix("🔴", "[HIGH]"), action.Type),
				Default: false,
			}
			_ = askOne(prompt, &confirm)
		}
		ui.ResetTerminalState()
		return confirm
	}

	loopCfg := harness.RunLoopConfig{
		SysCtx:           sysCtx,
		History:          &history,
		Reporter:         reporter,
		ReportPath:       reportPath,
		BatchMode:        *batchMode,
		NonInteractive:   nonInteractive,
		PauseOnAskUser:   false,
		MaxSteps:         maxSteps,
		SubAgentMaxSteps: subAgentMaxSteps,
		PlanMode:         *planMode,
		ConfirmFn:        confirmFn,
	}
	if !*tuiMode && !nonInteractive {
		loopCfg.AwaitUserFn = func(action *harness.AgentAction) (string, bool) {
			question := action.Question
			if strings.TrimSpace(question) == "" {
				question = "请补充继续任务所需的信息。"
			}
			if len(action.Options) > 0 {
				var b strings.Builder
				b.WriteString(question)
				for i, opt := range action.Options {
					b.WriteString(fmt.Sprintf("\n%d. %s", i+1, opt))
				}
				question = b.String()
			}
			answer := ""
			_ = askOne(&survey.Input{Message: question}, &answer)
			ui.ResetTerminalState()
			return strings.TrimSpace(answer), strings.TrimSpace(answer) != ""
		}
	}

	if *tuiMode {
		startup.MaxSteps = maxSteps
		startup.BatchMode = *batchMode
		startup.SessionID = sessionID
		startup.AwaitGoal = awaitGoal
		startup.ToolCount = tools.CountEnabled()
		startup.SubAgentCount = subagent.Count()
		if agent.Catalog != nil {
			startup.SkillCount = len(agent.Catalog.Skills)
		}
		if err := tui.Run(tui.SessionConfig{
			Agent:            agent,
			SysCtx:           sysCtx,
			History:          &history,
			Reporter:         reporter,
			ReportPath:       reportPath,
			BatchMode:        *batchMode,
			MaxSteps:         maxSteps,
			SubAgentMaxSteps: subAgentMaxSteps,
			ConnInfo:         connInfo,
			ModelInfo:        fmt.Sprintf("%s / %s", config.GlobalConfig.Provider, config.GlobalConfig.ModelName),
			Startup:          startup,
			AwaitGoal:        awaitGoal,
			MultiTurn:        true,
			PlanMode:         *planMode,
		}); err != nil {
			fmt.Printf("%sTUI 退出: %v\n", ui.Prefix("❌", "[ERR]"), err)
		}
		return
	}

	if *jsonOutput && *quiet {
		fmt.Fprintln(os.Stderr, ui.Prefix("⚠️", "[WARN]")+"--json 与 --quiet 同时使用时，--quiet 会抑制部分 JSONL 事件。")
	}
	var outSink harness.UISink = harness.NewStdoutSink()
	if *jsonOutput {
		outSink = harness.NewJSONSink()
	}
	if *webshellMode {
		outSink = harness.NewWebShellSink(outSink)
	} else if *quiet {
		outSink = harness.NewQuietSink(outSink)
	}
	loopCfg.UI = outSink
	agent.RunLoop(loopCfg)
	if !*jsonOutput && !*quiet {
		printExitHint()
	}
}

func flagWasPassed(name string) bool {
	seen := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			seen = true
		}
	})
	return seen
}

func isInteractiveTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(v)
}

func emitInitFailure(jsonOutput bool, code, message string) {
	if jsonOutput {
		printJSON(map[string]any{
			"error":   code,
			"message": message,
		})
		return
	}
	fmt.Printf("%s%s\n", ui.Prefix("❌", "[ERR]"), message)
}

func launchDetachedWebShell(title string) (string, string, string, error) {
	if err := os.MkdirAll("reports", 0755); err != nil {
		return "", "", "", err
	}
	timestamp := time.Now().Format("20060102_150405")
	reportPath, err := filepath.Abs(filepath.Join("reports", fmt.Sprintf("report_%s.md", timestamp)))
	if err != nil {
		return "", "", "", err
	}
	progressPath, err := filepath.Abs(filepath.Join("reports", fmt.Sprintf("webshell_progress_%s.log", timestamp)))
	if err != nil {
		return "", "", "", err
	}
	latestPath, err := filepath.Abs(filepath.Join("reports", "latest_webshell.txt"))
	if err != nil {
		return "", "", "", err
	}

	progressFile, err := os.OpenFile(progressPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return "", "", "", err
	}

	notice := webShellNoticeText(reportPath, progressPath, latestPath)
	_, _ = progressFile.WriteString(notice + "\n\n")
	_ = os.WriteFile(latestPath, []byte(notice+"\n"), 0644)

	exe, err := os.Executable()
	if err != nil {
		_ = progressFile.Close()
		return "", "", "", err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	if wd, err := os.Getwd(); err == nil {
		cmd.Dir = wd
	}
	cmd.Env = append(os.Environ(),
		"DEEPSENTRY_WEBSHELL_CHILD=1",
		"DEEPSENTRY_REPORT_PATH="+reportPath,
		"DEEPSENTRY_WEBSHELL_PROGRESS_PATH="+progressPath,
		"DEEPSENTRY_NO_COLOR=1",
		"NO_COLOR=1",
	)
	cmd.Stdin = nil
	cmd.Stdout = progressFile
	cmd.Stderr = progressFile
	configureDetachedProcess(cmd)

	if err := cmd.Start(); err != nil {
		_ = progressFile.Close()
		return "", "", "", err
	}
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}
	_ = progressFile.Close()

	if strings.TrimSpace(title) != "" {
		_ = os.WriteFile(latestPath, []byte(notice+"\n任务标题: "+logger.NormalizeReportTitle(title)+"\n"), 0644)
	}
	return reportPath, progressPath, latestPath, nil
}

func printWebShellDetachedNotice(reportPath, progressPath, latestPath string) {
	fmt.Print(webShellNoticeText(reportPath, progressPath, latestPath) + "\n")
	_ = os.Stdout.Sync()
}

func webShellNoticeText(reportPath, progressPath, latestPath string) string {
	return fmt.Sprintf("[WEB] DeepSentry 任务已提交后台执行\n"+
		"[WEB] 执行结果报告: %s\n"+
		"[WEB] 实时进度日志: %s\n"+
		"[WEB] 固定索引文件: %s\n"+
		"[WEB] 查看进度: cat %s\n"+
		"[WEB] 查看报告: cat %s",
		reportPath, progressPath, latestPath, progressPath, reportPath)
}

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		fn()
		return ""
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String()
}

func appendLogLines(dst []string, raw string) []string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(stripANSI(line))
		if line != "" {
			dst = append(dst, line)
		}
	}
	return dst
}

func absorbStartupOutput(info *tui.StartupInfo, raw string) {
	for _, line := range appendLogLines(nil, raw) {
		if strings.Contains(line, "[模式切换]") {
			info.ModeLine = line
			continue
		}
		info.Notices = append(info.Notices, line)
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	inSeq := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inSeq {
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				inSeq = false
			}
			continue
		}
		if ch == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			inSeq = true
			i++
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func printExitHint() {
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	exe, _ = filepath.Abs(exe)
	if _, err := os.Stat(exe); err != nil {
		fmt.Println("\n" + ui.Prefix("⚠️", "[WARN]") + "可执行文件已被删除或移动（常见于运行期间执行了 build.sh 重建 build/ 目录）。")
		fmt.Println("   请重新编译后运行: bash build.sh && cd build && ./deepsentry -c config.yaml")
		return
	}
	dir := filepath.Dir(exe)
	fmt.Printf("\n%s继续任务: %s --tui -c config.yaml\n", ui.Prefix("💡", "[TIP]"), exe)
	if dir != "" {
		fmt.Printf("   (当前目录: %s)\n", dir)
	}
}

func schedulerInterval() time.Duration {
	sec := config.GlobalConfig.SchedulerIntervalSec
	if sec <= 0 {
		sec = 30
	}
	if sec < 5 {
		sec = 5
	}
	return time.Duration(sec) * time.Second
}

func waitForSignal() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Println("\n" + ui.Prefix("⏹️", "[STOP]") + "定时任务调度器已退出")
}

// ---------------------------------------------------------------------
// 辅助函数：向导与循环
// ---------------------------------------------------------------------

// runSSHWizard 统一的 SSH 配置向导
func runSSHWizard(skipHostName bool) {
	// 🟢 动态标题：根据场景显示不同标题，体验更流畅
	if skipHostName {
		fmt.Println("\n" + ui.Prefix("🔐", "[SSH]") + ui.StripANSIIfPlain("\033[1;34mSSH 身份认证\033[0m")) // 初次设置显示这个
	} else {
		fmt.Println("\n" + ui.Prefix("🛠️", "[CFG]") + ui.StripANSIIfPlain("\033[1;34mSSH 配置修正\033[0m")) // 只有出错重连时才显示这个
	}

	// 🟢 只有在"非跳过"模式下，才询问主机名
	if !skipHostName {
		var host string
		askOne(&survey.Input{
			Message: "SSH 主机 (IP:Port):",
			Default: config.GlobalConfig.SSHHost,
		}, &host)
		viper.Set("ssh_host", host)
		config.GlobalConfig.SSHHost = host // 立即更新内存变量
	}

	var user string
	askOne(&survey.Input{
		Message: "SSH 用户名:",
		Default: "root", // 给个默认值 root，方便一点
	}, &user)
	viper.Set("ssh_user", user)

	authMethod := ""
	askOne(&survey.Select{
		Message: "认证方式:",
		Options: []string{"Password", "Private Key"},
		Default: "Password",
	}, &authMethod)

	if authMethod == "Password" {
		var pwd string
		askOne(&survey.Password{Message: "密码:"}, &pwd)
		viper.Set("ssh_password", pwd)
		viper.Set("ssh_key_path", "")
	} else {
		var keyPath string
		defKey := config.GlobalConfig.SSHKeyPath
		if defKey == "" {
			if home, err := os.UserHomeDir(); err == nil && home != "" {
				defKey = filepath.Join(home, ".ssh", "id_rsa")
			} else {
				defKey = filepath.Join(".ssh", "id_rsa")
			}
		}
		askOne(&survey.Input{Message: "私钥路径:", Default: defKey}, &keyPath)
		viper.Set("ssh_key_path", keyPath)
		viper.Set("ssh_password", "")
	}

	// 保存并刷新配置
	if err := config.SaveConfig(); err != nil {
		fmt.Printf("%s配置保存失败: %v\n", ui.Prefix("⚠️", "[WARN]"), err)
	}
	// 刷新全局变量
	config.GlobalConfig.SSHUser = viper.GetString("ssh_user")
	config.GlobalConfig.SSHPassword = viper.GetString("ssh_password")
	config.GlobalConfig.SSHKeyPath = viper.GetString("ssh_key_path")
	ui.ResetTerminalState()
}

func runSingleTargetWizard() config.TargetConfig {
	targets := runTargetEntriesWizard(1)
	if len(targets) == 0 {
		return config.TargetConfig{Protocol: "ssh"}
	}
	return targets[0]
}

func runTargetsWizard() []config.TargetConfig {
	countText := "3"
	_ = askOne(&survey.Input{
		Message: "要录入几台服务器:",
		Default: "3",
	}, &countText)
	count := 3
	fmt.Sscanf(countText, "%d", &count)
	if count <= 0 {
		count = 1
	}
	if count > 100 {
		count = 100
	}
	return runTargetEntriesWizard(count)
}

func runTargetEntriesWizard(count int) []config.TargetConfig {
	targets := make([]config.TargetConfig, 0, count)
	used := map[string]bool{}
	for i := 1; i <= count; i++ {
		var t config.TargetConfig
		defaultName := fmt.Sprintf("target-%02d", i)
		_ = ask([]*survey.Question{
			{Name: "name", Prompt: &survey.Input{Message: fmt.Sprintf("第 %d 台名称:", i), Default: defaultName}},
			{Name: "protocol", Prompt: &survey.Select{Message: "连接协议:", Options: []string{"ssh", "telnet", "ftp"}, Default: "ssh"}},
			{Name: "host", Prompt: &survey.Input{Message: "主机 (IP[:Port]):"}, Validate: survey.Required},
			{Name: "user", Prompt: &survey.Input{Message: "用户名:", Default: "root"}},
		}, &t)
		t.Name = uniqueTargetName(firstNonEmptyString(t.Name, defaultName), used)
		t.Host = normalizeTargetHost(t.Protocol, t.Host)
		switch t.Protocol {
		case "ssh":
			auth := ""
			_ = askOne(&survey.Select{Message: "SSH 认证方式:", Options: []string{"Password", "Private Key"}, Default: "Password"}, &auth)
			if auth == "Private Key" {
				defKey := ""
				if home, err := os.UserHomeDir(); err == nil {
					defKey = filepath.Join(home, ".ssh", "id_rsa")
				}
				_ = askOne(&survey.Input{Message: "私钥路径:", Default: defKey}, &t.KeyPath)
			} else {
				_ = askOne(&survey.Password{Message: "密码:"}, &t.Password)
			}
		case "telnet":
			_ = askOne(&survey.Password{Message: "Telnet 密码:"}, &t.Password)
			_ = askOne(&survey.Input{Message: "Telnet Prompt (可空):"}, &t.Prompt)
		case "ftp":
			if t.User == "" {
				t.User = "anonymous"
			}
			_ = askOne(&survey.Password{Message: "FTP 密码 (匿名可空):"}, &t.Password)
		}
		tags := ""
		_ = askOne(&survey.Input{Message: "标签 (逗号分隔，可空):"}, &tags)
		t.Tags = splitTags(tags)
		targets = append(targets, t)
	}
	return targets
}

func applySingleTargetConfig(t config.TargetConfig) {
	clearSingleTargetConfig()
	viper.Set("target_protocol", t.Protocol)
	switch t.Protocol {
	case "telnet":
		viper.Set("telnet_host", t.Host)
		viper.Set("telnet_user", firstNonEmptyString(t.User, "root"))
		viper.Set("telnet_password", t.Password)
		viper.Set("telnet_prompt", t.Prompt)
	case "ftp":
		viper.Set("ftp_host", t.Host)
		viper.Set("ftp_user", firstNonEmptyString(t.User, "anonymous"))
		viper.Set("ftp_password", t.Password)
	default:
		viper.Set("target_protocol", "ssh")
		viper.Set("ssh_host", t.Host)
		viper.Set("ssh_user", firstNonEmptyString(t.User, "root"))
		viper.Set("ssh_password", t.Password)
		viper.Set("ssh_key_path", t.KeyPath)
	}
}

func clearSingleTargetConfig() {
	for _, key := range []string{
		"ssh_host", "ssh_user", "ssh_password", "ssh_key_path",
		"telnet_host", "telnet_user", "telnet_password", "telnet_prompt",
		"ftp_host", "ftp_user", "ftp_password",
	} {
		viper.Set(key, "")
	}
}

func normalizeTargetHost(protocol, host string) string {
	host = strings.TrimSpace(host)
	if host == "" || strings.Contains(host, ":") {
		return host
	}
	switch protocol {
	case "telnet":
		return host + ":23"
	case "ftp":
		return host + ":21"
	default:
		return host + ":22"
	}
}

func uniqueTargetName(name string, used map[string]bool) string {
	base := strings.TrimSpace(name)
	if base == "" {
		base = "target"
	}
	out := base
	for i := 2; used[out]; i++ {
		out = fmt.Sprintf("%s-%d", base, i)
	}
	used[out] = true
	return out
}

func splitTags(raw string) []string {
	var tags []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			tags = append(tags, part)
		}
	}
	return tags
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func resumeUserSupplement(taskFlag, taskShort string, args []string) string {
	if strings.TrimSpace(taskFlag) != "" {
		return strings.TrimSpace(taskFlag)
	}
	if strings.TrimSpace(taskShort) != "" {
		return strings.TrimSpace(taskShort)
	}
	if len(args) > 0 {
		return strings.TrimSpace(strings.Join(args, " "))
	}
	return ""
}

// runElegantWizard 完整初始化向导
func runElegantWizard() error {
	fmt.Println("\n" + ui.Prefix("🛠️", "[INIT]") + ui.StripANSIIfPlain("\033[1;34mDeepSentry 初始化向导\033[0m"))
	fmt.Println("-------------------------------------------")

	// 1. 第一步：选择 AI 提供商 (用于生成智能默认值)
	var providerLabel string
	providerPrompt := &survey.Select{
		Message: ui.Prefix("🤖", "[AI]") + "请选择您的 AI 模型服务商:",
		Options: []string{
			"DeepSeek (deepseek-v4-pro)",
			"Qwen / 阿里百炼 (qwen-plus)",
			"中国电信星辰 TeleAI (GLM-5-Pro)",
			"腾讯混元 Hunyuan (hunyuan-turbos-latest)",
			"OpenAI (gpt-5.5)",
			"Anthropic Claude (claude-opus-4-8)",
			"Google Gemini (gemini-3.5-flash)",
			"MiniMax (MiniMax-M3)",
			"智谱 GLM (glm-5.2)",
			"Xiaomi MiMo (mimo-v2.5-pro)",
			"xAI Grok (grok-4)",
			"Ollama (本地运行)",
			"LM Studio (本地运行)",
			"其他 (自定义/中转)",
		},
		Default: "DeepSeek (deepseek-v4-pro)",
	}
	if err := askOne(providerPrompt, &providerLabel); err != nil {
		return err
	}

	providerID := "custom"
	defaultURL := ""
	defaultModel := ""
	urlHelp := "请输入 API Base URL（可只填 /v1，自动补全 chat/completions）"

	switch {
	case strings.Contains(providerLabel, "DeepSeek"):
		providerID = "deepseek"
	case strings.Contains(providerLabel, "Qwen"):
		providerID = "qwen"
	case strings.Contains(providerLabel, "星辰") || strings.Contains(providerLabel, "TeleAI"):
		providerID = "teleai"
		urlHelp = "电信星辰/TokenHub OpenAI 兼容 Base URL；如控制台分配了专属 endpoint，请覆盖此值"
	case strings.Contains(providerLabel, "混元") || strings.Contains(providerLabel, "Hunyuan"):
		providerID = "hunyuan"
	case strings.Contains(providerLabel, "OpenAI"):
		providerID = "openai"
	case strings.Contains(providerLabel, "Anthropic"):
		providerID = "anthropic"
	case strings.Contains(providerLabel, "Gemini"):
		providerID = "google"
	case strings.Contains(providerLabel, "MiniMax"):
		providerID = "minimax"
	case strings.Contains(providerLabel, "GLM"):
		providerID = "glm"
	case strings.Contains(providerLabel, "MiMo"):
		providerID = "mimo"
	case strings.Contains(providerLabel, "Grok"):
		providerID = "xai"
	case strings.Contains(providerLabel, "Ollama"):
		providerID = "ollama"
	case strings.Contains(providerLabel, "LM Studio"):
		providerID = "lmstudio"
		urlHelp = "LM Studio 默认端口 1234"
	default:
		providerID = "custom"
	}

	if preset, ok := config.FindProvider(providerID); ok && defaultURL == "" {
		defaultURL = preset.APIURL
		defaultModel = preset.Model
		if providerID == "ollama" {
			urlHelp = "Ollama OpenAI 兼容端点"
		}
	}

	// 3. 构建核心配置问题 (带动态默认值)
	var qs = []*survey.Question{
		{
			Name: "api_protocol",
			Prompt: &survey.Select{
				Message: ui.Prefix("🔌", "[API]") + "API 协议:",
				Options: []string{"auto", "openai_chat", "anthropic_messages", "openai_responses"},
				Default: "auto",
				Help:    "大多数国产/本地模型选 auto/openai_chat；Claude 选 anthropic_messages；OpenAI Responses 可手动选择 openai_responses",
			},
		},
		{
			Name: "api_url",
			Prompt: &survey.Input{
				Message: ui.Prefix("🌐", "[URL]") + "API 地址 (Endpoint):",
				Default: defaultURL,
				Help:    urlHelp,
			},
			Validate: survey.Required,
		},
		{
			Name: "model_name",
			Prompt: &survey.Input{
				Message: ui.Prefix("🧠", "[MODEL]") + "模型名称 (Model ID):",
				Default: defaultModel,
				Help:    "例如: deepseek-v4-pro, qwen-plus, hunyuan-turbos-latest, GLM-5-Pro 等",
			},
			Validate: survey.Required,
		},
		{
			Name: "api_key",
			Prompt: &survey.Password{
				Message: ui.Prefix("🔑", "[KEY]") + "API Key (本地模型可回车跳过):",
				Help:    "OpenAI/DeepSeek 必填；Ollama/LM Studio 可直接回车留空",
			},
		},
		// 🟢 1. 在向导中增加最大轮数配置
		{
			Name: "max_steps",
			Prompt: &survey.Input{
				Message: ui.Prefix("🔄", "[STEP]") + "最大对话轮数 (Max Steps):",
				Default: "30",
				Help:    "防止 AI 陷入死循环的最大交互次数",
			},
		},
		{
			Name: "subagent_max_steps",
			Prompt: &survey.Input{
				Message: ui.Prefix("🔀", "[SUB]") + "子 Agent 最大步数上限:",
				Default: "15",
				Help:    "AI 可按任务难度估算子 Agent 步数，但不会超过这个用户上限",
			},
		},
	}

	answers := struct {
		ApiUrl           string `survey:"api_url"`
		Protocol         string `survey:"api_protocol"`
		ModelName        string `survey:"model_name"`
		ApiKey           string `survey:"api_key"`
		MaxSteps         string `survey:"max_steps"`
		SubAgentMaxSteps string `survey:"subagent_max_steps"`
	}{}

	// 执行问答
	err := ask(qs, &answers)
	if err != nil {
		return err
	}

	if answers.ApiKey == "" {
		answers.ApiKey = "none"
	}

	// 4. 保存配置
	viper.Set("provider", providerID)
	viper.Set("api_protocol", answers.Protocol)
	viper.Set("api_url", answers.ApiUrl)
	viper.Set("model_name", answers.ModelName)
	viper.Set("api_key", answers.ApiKey)
	// 🟢 2. 保存最大轮数 (Viper 会自动处理类型，这里存为字符串或数字均可被 GetInt 读取)
	viper.Set("max_steps", answers.MaxSteps)
	viper.Set("subagent_max_steps", answers.SubAgentMaxSteps)

	mode := ""
	fmt.Println(ui.Prefix("💡", "[TIP]") + "管理模式默认本地任务；Windows cmd 若上下键无效，可用 Tab / Shift+Tab 切换，Enter 确认。")
	if err := askOne(&survey.Select{
		Message: ui.Prefix("🖥️", "[MODE]") + "管理模式:",
		Options: []string{"本地任务", "远程管理 1 台服务器", "远程管理多台服务器 (Fleet)"},
		Default: "本地任务",
		Help:    "Windows cmd 里方向键可能被终端拦截，可用 Tab / Shift+Tab 切换选项。",
	}, &mode); err != nil {
		return err
	}

	var saveErr error
	switch {
	case strings.Contains(mode, "多台"):
		targets := runTargetsWizard()
		viper.Set("targets", targets)
		viper.Set("target_protocol", "local")
		clearSingleTargetConfig()
		if saveErr = config.SaveConfig(); saveErr != nil {
			fmt.Printf("%s配置保存失败: %v\n", ui.Prefix("❌", "[ERR]"), saveErr)
		} else {
			fmt.Printf("%s已保存 %d 台 Fleet 目标至 config.yaml\n", ui.Prefix("✅", "[OK]"), len(targets))
		}
	case strings.Contains(mode, "1 台"):
		target := runSingleTargetWizard()
		viper.Set("targets", []config.TargetConfig(nil))
		applySingleTargetConfig(target)
		if saveErr = config.SaveConfig(); saveErr != nil {
			fmt.Printf("%s配置保存失败: %v\n", ui.Prefix("❌", "[ERR]"), saveErr)
		} else {
			fmt.Println(ui.Prefix("✅", "[OK]") + "单台远程配置已保存至 config.yaml")
		}
	default:
		viper.Set("target_protocol", "local")
		viper.Set("targets", []config.TargetConfig(nil))
		clearSingleTargetConfig()
		if saveErr = config.SaveConfig(); saveErr != nil {
			fmt.Printf("%s配置保存失败: %v\n", ui.Prefix("❌", "[ERR]"), saveErr)
		} else {
			fmt.Println(ui.Prefix("✅", "[OK]") + "配置已保存至 config.yaml")
		}
	}
	if saveErr != nil {
		return saveErr
	}

	// 刷新全局配置
	viper.Unmarshal(&config.GlobalConfig)
	fmt.Println("-------------------------------------------")
	ui.ResetTerminalState()
	return nil
}
