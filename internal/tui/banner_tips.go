package tui

// bannerTips 启动 Banner 随机展示的使用小技巧（程序启动时抽取一条并固定）。
var bannerTips = []string{
	// 输入与快捷键
	"Tab 聚焦输入框，Enter 发送安全任务",
	"等待补充信息时，输入选项编号即可继续",
	"Agent 缺少信息时会一次只问一个关键问题",
	"任务运行中也可 Tab 输入新指令，Enter 打断并续跑",
	"Esc 退出输入模式，↑↓/jk 滚动日志",
	"Shift+Enter / Alt+Enter 可在输入框内换行",
	"Ctrl+U 清空当前输入，Ctrl+L 清屏",
	"按 G 快速跳到日志底部",
	"PgUp / PgDown 翻页浏览 Agent 输出",
	"鼠标滚轮可上下滚动日志区域",
	"输入 q 退出 TUI（需先 Esc 退出输入模式）",
	"粘贴千行日志会折叠显示，提交仍是完整内容",
	"中文输入法候选框会贴近底部输入行",

	// 斜杠命令
	"输入 /help 查看全部快捷键与斜杠命令",
	"/new 开启全新任务；/new <任务> 可直接启动",
	"/status 查看连接、模型与运行状态",
	"/cost 查看真实 token 用量，缺失 usage 时显示估算",
	"/clear 清空当前屏幕日志",
	"/model 查看当前 LLM 提供商与模型名",
	"/config 查看配置文件摘要",
	"/sessions 列出可恢复的 checkpoint 会话",
	"/resume <session_id> 在当前 TUI 直接恢复 checkpoint",
	"/memory list 查看已注入的结构化记忆",
	"/memory clear 一键清空结构化 Memory",
	"/agents clear 清空外部 AGENTS.md（内置默认保留）",
	"/compact 记录上下文整理提示",

	// 多轮与会话
	"任务完成后可直接追问，上下文会自动保留",
	"计划模式: deepsentry --plan \"你的任务\"",
	"--plan 会先澄清关键选择，再写 todo 并继续执行",
	"恢复会话: deepsentry --tui --resume <session_id>",
	"图形选会话: deepsentry --tui --pick-session",
	"列出会话: deepsentry --list-sessions",
	"Ctrl+C 有选区时复制，无选区时停止任务；再按一次强制退出",

	// 子 Agent 与 Fleet
	"按 e 展开或折叠子 Agent / 工具长输出",
	"子 Agent 委派适合多机并行排查同一类问题",
	"Fleet 多目标请在任务中指定 target_selector",
	"selector 支持 all、prod、web-01 等标签与名称",
	"fleet_exec / fleet_file 会按真实命令或文件动作动态判险",
	"混合 SSH/Telnet/FTP 目标会按协议自动拆分调度",
	"每台 Fleet 目标会显示 pending/running/ok/error 状态",

	// 模式与工具
	"本地模式：工具在控制端本机执行",
	"默认先用目标机原生 Shell，搞不定再调用内置工具",
	"远程 SSH：mem_info、port_listen 等在目标机执行",
	"控制端工具 ping、nmap_scan 从 DeepSentry 进程发起",
	"Native Tool Calling 已启用时可更稳定地调用内置工具",
	"高风险 Shell 会弹窗确认，按 Y 批准 / N 拒绝",
	"Batch 模式自动批准操作，仅建议在隔离环境使用",
	"审计报告自动写入 reports/ 目录，启动 Banner 可看到路径",
	"缺少 webhook、阈值或目标范围时，Agent 会暂停等待补充",
	"定时任务通知支持钉钉、飞书和 HTTP 邮件网关",
	"钉钉/飞书加签机器人需要配置对应 secret",

	// 任务示例
	"示例：排查目标机内存与监听端口",
	"示例：分析 auth.log / secure 中的暴力破解 IP",
	"示例：审计网络暴露面与异常 outbound 连接",
	"示例：在 Web 目录狩猎 webshell 与可疑 PHP/JSP",
	"示例：检查 cron、systemd 与启动项中的持久化",
	"示例：对比多机相同路径的配置是否被篡改",
	"示例：读取 /var/log/syslog 最近 ERROR 并归纳根因",
	"示例：对可疑进程做 cmdline、fd、网络连接关联分析",

	// CLI 与脚本
	"脚本/CI 建议: deepsentry --no-tui --task \"...\"",
	"JSONL 事件: deepsentry --no-tui --json --task \"...\"",
	"WebShell 场景: deepsentry --webshell --task \"mem_info 摘要\"",
	"首次使用可运行 deepsentry --init 进入配置向导",
	"指定配置: deepsentry -c /path/to/config.yaml --tui",

	// Skills 与 Memory
	"Agent 可按场景加载 Skills（日志分析、取证、漏洞扫描等）",
	"跨会话 Memory 会在有历史时自动注入上下文",
	"说“记一下/记住这个步骤”会触发 Agent 总结并保存 Memory",
	"内置 AGENTS.md 随单二进制注入，外部 AGENTS.md 可选扩展",

	// 确认与安全
	"Enter 不会批准高风险操作，必须按 Y 确认",
	"拒绝危险操作时按 N 或 Esc",
	"无人值守请加 -batch，生产环境务必先评估风险",
	"Telnet/FTP 目标仅适合文件与命令类排查，注意协议限制",

	// 评测与其他
	"Benchmark TUI: go run ./cmd/benchmark/ -c config.yaml --tui",
	"快速门禁: go run ./cmd/benchmark/ -skip-llm -skip-remote",
	"MCP 扩展工具可在 config.yaml 的 mcp_servers 中配置",
	"enabled_tools / disabled_tools 可精确控制内置工具集",
	"max_steps 可在 config.yaml 调整单任务最大推理步数",
	"思考流默认折叠，按 e 可展开 AI 推理与 JSON 动作",
	"Stream 输出完成后会自动折叠为摘要，减少刷屏",
	"目标切换时状态栏会显示当前 @ 主机与协议",
	"委派任务时尽量写清范围：路径、时间窗、成功标准",
	"追问时引用上一步结论，Agent 会继续同一 checkpoint",
	"长任务中断后可 --resume 从上次步数继续，不必重来",
}
