package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec" 
	"runtime"
	"strings"

	"ai-edr/internal/analyzer"
	"ai-edr/internal/collector"
	"ai-edr/internal/config"
	"ai-edr/internal/executor"
	"ai-edr/internal/logger"
	"ai-edr/internal/security"
	"ai-edr/internal/ui"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/viper"
)

func main() {
	// 1. 跨平台控制台初始化
	enableWindowsANSI()

	// 🟢 [核心增强] 强制设置 Windows 控制台代码页为 UTF-8
	// 这解决了即便开启了 ANSI 渲染，底层系统命令输出依然可能坚持使用 GBK 的问题
	if runtime.GOOS == "windows" {
		_ = exec.Command("cmd", "/c", "chcp 65001").Run()
	}

	ui.PrintBanner()

	// 2. Flag 解析
	configFile := flag.String("c", "", "指定配置文件路径")
	batchMode := flag.Bool("batch", false, "开启无人值守模式")
	reconf := flag.Bool("init", false, "强制重新配置")
	flag.Parse()

	// 3. 配置加载
	err := config.InitConfig(*configFile)
	needWizard := *reconf
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			needWizard = true
		} else {
			fmt.Printf("❌ 配置文件加载失败: %v\n", err)
			return
		}
	}

	if needWizard {
		fmt.Println("⚠️  未检测到配置文件或请求重新初始化，进入向导模式...")
		runElegantWizard()
	} else {
		fmt.Printf("📂 \033[1;32m已加载配置: %s\033[0m\n", viper.ConfigFileUsed())
	}

	// 4. 获取用户需求
	args := flag.Args()
	userGoal := ""
	if len(args) < 1 {
		prompt := &survey.Input{
			Message: "🎯 请输入您的需求:",
			Help:    "例如：检查系统为何负载过高 / 帮我把本地文件上传到服务器",
		}
		if err := survey.AskOne(prompt, &userGoal); err != nil {
			fmt.Println("\n❌ 操作已取消")
			return
		}
		if strings.TrimSpace(userGoal) == "" {
			fmt.Println("❌ 未提供需求，程序退出。")
			return
		}
	} else {
		userGoal = strings.Join(args, " ")
	}

	// 5. 初始化执行环境
	for {
		err = executor.Init(config.GlobalConfig)
		if err == nil {
			break
		}

		if config.GlobalConfig.SSHHost != "" {
			fmt.Printf("\n❌ \033[1;31mSSH 连接失败: %v\033[0m\n", err)
			choice := ""
			prompt := &survey.Select{
				Message: "检测到 SSH 连接失败，请选择操作:",
				Options: []string{
					"🔧 修改 SSH 配置 (重新输入密码)",
					"💻 切换为 本地模式 (清除 SSH 配置)",
					"❌ 退出程序",
				},
			}
			if err := survey.AskOne(prompt, &choice); err != nil {
				return
			}
			if strings.Contains(choice, "修改 SSH 配置") {
				runSSHWizard(false)
				continue
			} else if strings.Contains(choice, "切换为 本地模式") {
				config.GlobalConfig.SSHHost = ""
				viper.Set("ssh_host", "")
				continue
			} else {
				return
			}
		}
		fmt.Printf("❌ 初始化执行环境失败: %v\n", err)
		return
	}
	defer executor.Current.Close()

	// 6. Batch Mode 确认
	if *batchMode {
		fmt.Println("\n\033[41;37m ⚠️  警告：无人值守模式 (BATCH MODE) 已开启 ⚠️ \033[0m")
		confirm := false
		prompt := &survey.Confirm{
			Message: "确认要在无人值守模式下运行吗?",
			Default: false,
		}
		_ = survey.AskOne(prompt, &confirm)
		if !confirm {
			return
		}
	}

	// 7. 初始化报告
	reporter, reportPath, _ := logger.NewReporter()
	if reporter != nil {
		defer reporter.Close()
		fmt.Printf("[*] 审计日志: %s\n", reportPath)
	}

	// 8. 环境感知
	fmt.Println("🔍 正在采集系统指纹...")
	sysCtx := collector.GetSystemContext()

	connInfo := "本地模式"
	if executor.Current.IsRemote() {
		connInfo = fmt.Sprintf("SSH -> %s", config.GlobalConfig.SSHHost)
	}

	fmt.Println("--------------------------------------------------")
	fmt.Printf("[+] 连接状态: \033[1;33m%s\033[0m\n", connInfo)
	fmt.Printf("[+] 目标系统: %s / %s\n", sysCtx.OS, sysCtx.Arch)
	fmt.Printf("[+] 用户信息: %s\n", sysCtx.Username)
	fmt.Println("--------------------------------------------------")

	// 9. 启动分析循环
	history := []analyzer.Message{
		{Role: "user", Content: fmt.Sprintf("需求：%s", userGoal)},
	}
	reader := bufio.NewReader(os.Stdin)
	runAnalysisLoop(sysCtx, &history, reporter, reportPath, *batchMode, reader)
}

// ---------------------------------------------------------------------
// 辅助函数：向导与循环
// ---------------------------------------------------------------------

// runSSHWizard 统一的 SSH 配置向导
func runSSHWizard(skipHostName bool) {
	// 🟢 动态标题：根据场景显示不同标题，体验更流畅
	if skipHostName {
		fmt.Println("\n🔐 \033[1;34mSSH 身份认证\033[0m") // 初次设置显示这个
	} else {
		fmt.Println("\n🛠️  \033[1;34mSSH 配置修正\033[0m") // 只有出错重连时才显示这个
	}

	// 🟢 只有在"非跳过"模式下，才询问主机名
	if !skipHostName {
		var host string
		survey.AskOne(&survey.Input{
			Message: "SSH 主机 (IP:Port):",
			Default: config.GlobalConfig.SSHHost,
		}, &host)
		viper.Set("ssh_host", host)
		config.GlobalConfig.SSHHost = host // 立即更新内存变量
	}

	var user string
	survey.AskOne(&survey.Input{
		Message: "SSH 用户名:",
		Default: "root", // 给个默认值 root，方便一点
	}, &user)
	viper.Set("ssh_user", user)

	authMethod := ""
	survey.AskOne(&survey.Select{
		Message: "认证方式:",
		Options: []string{"Password", "Private Key"},
		Default: "Password",
	}, &authMethod)

	if authMethod == "Password" {
		var pwd string
		survey.AskOne(&survey.Password{Message: "密码:"}, &pwd)
		viper.Set("ssh_password", pwd)
		viper.Set("ssh_key_path", "")
	} else {
		var keyPath string
		defKey := config.GlobalConfig.SSHKeyPath
		if defKey == "" {
			defKey = os.Getenv("HOME") + "/.ssh/id_rsa"
		}
		survey.AskOne(&survey.Input{Message: "私钥路径:", Default: defKey}, &keyPath)
		viper.Set("ssh_key_path", keyPath)
		viper.Set("ssh_password", "")
	}

	// 保存并刷新配置
	if err := config.SaveConfig(); err != nil {
		fmt.Printf("⚠️ 配置保存失败: %v\n", err)
	}
	// 刷新全局变量
	config.GlobalConfig.SSHUser = viper.GetString("ssh_user")
	config.GlobalConfig.SSHPassword = viper.GetString("ssh_password")
	config.GlobalConfig.SSHKeyPath = viper.GetString("ssh_key_path")
}

// runElegantWizard 完整初始化向导
func runElegantWizard() {
	fmt.Println("\n🛠️  \033[1;34mDeepSentry 初始化向导\033[0m")
	fmt.Println("-------------------------------------------")

	// 1. 第一步：选择 AI 提供商 (用于生成智能默认值)
	var provider string
	providerPrompt := &survey.Select{
		Message: "🤖 请选择您的 AI 模型服务商:",
		Options: []string{
			"DeepSeek (官方API)",
			"OpenAI / ChatGPT",
			"Ollama (本地运行)",
			"LM Studio (本地运行)",
			"其他 (自定义/中转)",
		},
		Default: "DeepSeek (官方API)",
	}
	_ = survey.AskOne(providerPrompt, &provider)

	// 2. 根据厂商设置 默认值 和 提示语
	defaultURL := ""
	defaultModel := ""
	urlHelp := ""

	switch provider {
	case "DeepSeek (官方API)":
		defaultURL = "https://api.deepseek.com/chat/completions"
		defaultModel = "deepseek-chat"
		urlHelp = "DeepSeek 官方 API 地址，通常无需修改"
	case "OpenAI / ChatGPT":
		defaultURL = "https://api.openai.com/v1/chat/completions"
		defaultModel = "gpt-4o"
		urlHelp = "OpenAI 官方地址，如果是中转站请修改此项"
	case "Ollama (本地运行)":
		defaultURL = "http://localhost:11434/v1/chat/completions"
		defaultModel = "llama3"
		urlHelp = "⚠️ 注意: Ollama 需保持 /v1/chat/completions 路径后缀"
	case "LM Studio (本地运行)":
		defaultURL = "http://localhost:1234/v1/chat/completions"
		defaultModel = "local-model"
		urlHelp = "LM Studio 默认端口为 1234，请确保服务已启动"
	default: // 自定义
		defaultURL = "https://api.deepseek.com/chat/completions"
		defaultModel = "deepseek-chat"
		urlHelp = "请输入完整的 API Endpoint (包含 /chat/completions)"
	}

	// 3. 构建核心配置问题 (带动态默认值)
	var qs = []*survey.Question{
		{
			Name: "api_url",
			Prompt: &survey.Input{
				Message: "🌐 API 地址 (Endpoint):",
				Default: defaultURL,
				Help:    urlHelp,
			},
			Validate: survey.Required,
		},
		{
			Name: "model_name",
			Prompt: &survey.Input{
				Message: "🧠 模型名称 (Model ID):",
				Default: defaultModel,
				Help:    "例如: deepseek-chat, gpt-4, llama3, qwen2.5 等",
			},
			Validate: survey.Required,
		},
		{
			Name: "api_key",
			Prompt: &survey.Password{
				Message: "🔑 API Key (本地模型可回车跳过):",
				Help:    "OpenAI/DeepSeek 必填；Ollama/LM Studio 可直接回车留空",
			},
		},
		// 🟢 1. 在向导中增加最大轮数配置
		{
			Name: "max_steps",
			Prompt: &survey.Input{
				Message: "🔄 最大对话轮数 (Max Steps):",
				Default: "30",
				Help:    "防止 AI 陷入死循环的最大交互次数",
			},
		},
		{
			Name: "ssh_host",
			Prompt: &survey.Input{
				Message: "💻 SSH 主机 (IP:Port ，只使用本地模式可回车跳过):",
				Help:    "留空则进入 [本地模式]，输入 IP:22 则管理远程服务器",
			},
		},
	}

	answers := struct {
		ApiUrl    string `survey:"api_url"`
		ModelName string `survey:"model_name"`
		ApiKey    string `survey:"api_key"`
		MaxSteps  string `survey:"max_steps"` // 🟢 新增字段
		SSHHost   string `survey:"ssh_host"`
	}{}

	// 执行问答
	err := survey.Ask(qs, &answers)
	if err != nil {
		fmt.Println("❌ 向导中断:", err)
		return
	}

	if answers.ApiKey == "" {
		answers.ApiKey = "none"
	}

	// 4. 保存配置
	viper.Set("api_url", answers.ApiUrl)
	viper.Set("model_name", answers.ModelName)
	viper.Set("api_key", answers.ApiKey)
	viper.Set("ssh_host", answers.SSHHost)
	// 🟢 2. 保存最大轮数 (Viper 会自动处理类型，这里存为字符串或数字均可被 GetInt 读取)
	viper.Set("max_steps", answers.MaxSteps)

	// 如果设置了 SSH Host，则进一步询问账号密码
	if answers.SSHHost != "" {
		config.GlobalConfig.SSHHost = answers.SSHHost
		runSSHWizard(true)
	} else {
		// 清理旧的 SSH 配置
		viper.Set("ssh_user", "")
		viper.Set("ssh_password", "")
		viper.Set("ssh_key_path", "")
		if err := config.SaveConfig(); err != nil {
			fmt.Printf("❌ 配置保存失败: %v\n", err)
		} else {
			fmt.Println("✅ 配置已保存至 config.yaml")
		}
	}

	// 刷新全局配置
	viper.Unmarshal(&config.GlobalConfig)
	fmt.Println("-------------------------------------------\n")
}

// runAnalysisLoop 主分析循环 (已修复空转死锁问题)
func runAnalysisLoop(sysCtx collector.SystemContext, history *[]analyzer.Message, reporter *logger.Reporter, reportPath string, batchMode bool, reader *bufio.Reader) {
	stepCount := 0

	// 🟢 3. 改为从配置中读取动态值，如果读取失败或为0则默认30
	maxSteps := viper.GetInt("max_steps")
	if maxSteps <= 0 {
		maxSteps = 30
	}

	consecutiveEmptyCount := 0

	for stepCount < maxSteps {
		stepCount++
		fmt.Printf("\n--- [Step %d / %d] -----------------\n", stepCount, maxSteps)
		fmt.Print("🧠 AI 正在思考... ")

		// 传入 history 指针
		resp, err := analyzer.RunAgentStep(sysCtx, history)
		fmt.Print("\r") // 清除思考提示

		if err != nil {
			fmt.Printf("❌ AI 错误: %v\n", err)
			break
		}

		if reporter != nil {
			reporter.Log("AI Thought", fmt.Sprintf("Idea: %s\nCmd: %s", resp.Thought, resp.Command))
		}

		// 打印思考
		if resp.Thought != "" {
			fmt.Printf("💡 想法: %s\n", resp.Thought)
		}

		// --- [修复开始] 空命令与结束处理逻辑 ---

		// 1. 如果 AI 认为完成了，直接结束
		if resp.IsFinished {
			// 兜底：如果 AI 说完成了但没写报告，用最后的想法填充
			if strings.TrimSpace(resp.FinalReport) == "" {
				resp.FinalReport = fmt.Sprintf("✅ 任务完成。总结: %s", resp.Thought)
			}
			printFinalReport(resp.FinalReport, reporter, reportPath)
			break
		}

		// 2. 空命令处理 (Watchdog)
		if resp.Command == "" {
			consecutiveEmptyCount++

			// 如果连续 3 次空转，强制结束
			if consecutiveEmptyCount >= 3 {
				fmt.Println("⚠️  AI 多次未给出行动，强制结束。")

				// 兜底：强制使用最后的 Thought 作为报告，防止空报告
				if strings.TrimSpace(resp.FinalReport) == "" {
					resp.FinalReport = fmt.Sprintf("❌ 异常终止：AI 陷入死循环。\n最后的思考线索: %s", resp.Thought)
				}
				printFinalReport(resp.FinalReport, reporter, reportPath)
				break
			}

			// ⚡ 关键修复：主动向 AI 注入警告，催促其行动
			fmt.Printf("⏳ (无指令) 正在催促 AI 执行操作 [%d/3]...\n", consecutiveEmptyCount)

			// 先把 AI 自己的“思考”记入历史，维持上下文连贯
			*history = append(*history, analyzer.Message{
				Role:    "assistant",
				Content: fmt.Sprintf(`{"thought": "%s", "command": "", "is_finished": false}`, resp.Thought),
			})

			// 插入系统级警告，强迫下一轮输出 Command
			*history = append(*history, analyzer.Message{
				Role:    "user",
				Content: "系统警告: 你没有输出 'command'。请立即执行具体的 Shell 命令来验证你的想法，或者如果任务已完成请设置 'is_finished': true。",
			})
			continue
		}
		// --- [修复结束] ---

		consecutiveEmptyCount = 0 // 重置计数器

		fmt.Printf("💻 命令: \033[36m%s\033[0m\n", resp.Command)

		// 执行判断逻辑
		shouldExecute := false
		if batchMode {
			fmt.Printf("⚡ [Batch] 自动执行\n")
			shouldExecute = true
		} else if resp.RiskLevel == "low" {
			fmt.Printf("🟢 风险: 低 -> 自动执行\n")
			shouldExecute = true
		} else {
			confirm := false
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("🔴 风险: 高 (%s) -> 是否执行?", resp.Reason),
				Default: false,
			}
			if err := survey.AskOne(prompt, &confirm); err != nil {
				fmt.Println("🚫 用户取消")
			}

			if confirm {
				shouldExecute = true
				security.RecordApproval(resp.Command)
			} else {
				fmt.Println("🚫 已拒绝执行")
				*history = append(*history, analyzer.Message{
					Role: "user", Content: "用户拒绝执行此命令，请尝试其他方案。",
				})
				continue
			}
		}

		if shouldExecute {
			output, err := security.SafeExecV3(resp.Command)

			display := strings.TrimSpace(output)
			if len(display) > 300 {
				display = display[:300] + "..."
			}
			if display == "" {
				display = "(无输出)"
			}

			if err != nil {
				fmt.Printf("⚠️  执行出错: %v\n", err)
				if display != "(无输出)" {
					fmt.Printf("   输出: %s\n", display)
				}
			} else {
				fmt.Printf("✅ 结果: %s\n", display)
			}

			if reporter != nil {
				reporter.LogCommand(resp.Command, output)
			}

			*history = append(*history, analyzer.Message{
				Role: "assistant", Content: fmt.Sprintf(`{"command": "%s"}`, resp.Command),
			})
			*history = append(*history, analyzer.Message{
				Role: "user", Content: fmt.Sprintf("Output:\n%s", output),
			})
		}
	}
}

func printFinalReport(content string, reporter *logger.Reporter, path string) {
	fmt.Println("\n📝 最终报告:\n" + strings.Repeat("=", 40))
	fmt.Println(content)
	fmt.Println(strings.Repeat("=", 40))
	if reporter != nil {
		reporter.Log("Final Report", content)
	}
	fmt.Printf("\n📂 日志: %s\n", path)
}
