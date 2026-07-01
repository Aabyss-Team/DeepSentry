package main

import "fmt"

func printUsage() {
	fmt.Print(`
DeepSentry — AI 安全应急 Agent

用法:
  deepsentry [选项] [任务描述...]

示例:
  deepsentry                                # 默认进入 TUI 面板
  deepsentry "排查服务器内存与监听端口"
  deepsentry --task "审计 SSH 登录日志"
  deepsentry --plan "配置每 10 分钟 CPU 监控并通知"
  deepsentry --no-tui -c config.yaml "审计 SSH 登录日志"
  deepsentry --no-tui --json --task "自动巡检目标机 /proc"
  deepsentry --webshell --task "读取最近登录日志"
  deepsentry --batch -y "自动巡检目标机 /proc"
  deepsentry --scheduler -c config.yaml       # 仅运行定时任务调度器
  deepsentry --resume session_abc123
  deepsentry --list-sessions
  deepsentry --list-sessions --json
  deepsentry --init                         # 重新运行配置向导

  deepsentry --tui --pick-session              # TUI 选择恢复会话
  go run ./cmd/benchmark/ -c config.yaml --tui # Benchmark 可视化

选项:
  -c string         配置文件路径 (默认搜索 ./config.yaml, ~/.deepsentry/)
  -tui              启用全屏 TUI（默认）
  -no-tui           使用经典 stdout CLI
  -task string      任务描述（agent/脚本推荐）
  -q string         任务描述（--task 简写）
  -plan             计划模式：必要时先追问，再生成 todo 计划并执行
  -subagent-max-steps int
                    子 Agent 最大步数上限（覆盖 config.yaml 的 subagent_max_steps）
  -json             经典模式输出 JSONL 事件
  -quiet            经典模式仅输出关键结果和错误
  -webshell         WebShell/非 TTY 友好模式（提交后台执行，立即返回报告/进度路径）
  --no-color        禁用彩色输出（默认启用颜色）
  -scheduler        仅运行本地定时任务调度器
  -version          显示版本
  -pick-session     配合 --tui，图形化选择 checkpoint 会话
  -batch            无人值守模式（自动批准操作）
  -y                配合 -batch，跳过 batch 模式二次确认
  -init             强制重新配置 LLM / SSH
  -resume string    从 checkpoint 恢复会话
  -list-sessions    列出可恢复的会话 ID

退出码:
  0                 正常结束
  1                 配置、会话、初始化或 Agent 创建失败

环境变量:
  DEEPSENTRY_*      覆盖 config.yaml 中的配置项
  target_protocol   local | ssh | telnet | ftp
  telnet_host       Telnet 目标 (IP:Port，默认 23)
  ftp_host          FTP 目标 (IP:Port，默认 21，仅文件/目录能力)

文档:
  docs/操作手册.md   完整操作手册
  README.md          架构与工具说明

`)
}
