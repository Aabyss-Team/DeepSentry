# 更新日志

本文档记录 DeepSentry 各正式版本的重要变化。

版本日期以 GitHub Release 的首次发布时间为准。项目当前使用带有
`Ultimate` 后缀的 Release 标签，因此下文保留对应的正式版本名称。

## [未发布]

尚无已记录的未发布变更。

## [2.0.2 Ultimate] - 2026-07-22

### Agent 运行时

- 默认启用 Runtime v3，并保留 `agent_runtime: legacy` 兼容模式。
- 增加结构化 Agent 消息块，支持 text、reasoning、tool call、tool result 和 artifact reference，并为运行、轮次、步骤与工具调用分配稳定 ID。
- 修复 TUI 流式路径绕过 native tool calling 和单次响应只处理第一个 tool call 的问题；流式响应现在保留完整的 tool-call 增量、reasoning、usage 和局部错误。
- 兼容部分模型网关把旧版 `agent_action.tool_args` 包进原生工具参数的响应，能够安全解包匹配工具并避免一次无效重试。
- 支持同一模型响应中的多个工具调用；仅对低风险、只读、幂等调用受限并行，修改型或高风险操作仍串行审批。
- 增加按需工具发现，只向模型提供当前任务相关的候选工具，降低工具误选和上下文开销。
- 增加 dangling tool-call 修补，在取消、恢复丢失、执行失败或历史不完整时补入结构化 tool result，避免供应商拒绝后续消息。
- 增加模型路由和故障切换：对 rate limit、timeout、server error、connection 和 invalid output 进行结构化分类、退避重试及 fallback，并根据备选模型能力移除不兼容参数。
- 新增 `models[]` 与 `model_routing.failover_on`，旧的单模型配置会自动映射为 primary，保持配置兼容。
- 建立统一、脱敏的 RunEvent/JSONL trace，覆盖模型、工具、子 Agent、审批、压缩、重试、failover 和 checkpoint，记录耗时、Token、错误分类和 artifact 引用而不记录密钥或完整敏感输出。
- Checkpoint 升级为带 `schema_version`、完整性哈希、前一份可恢复快照、待处理/已完成工具调用和事件游标的执行快照；旧 checkpoint 只从真实轮次边界迁移。
- 在模型完成与一轮工具完成后增加安全取消点；恢复后不会重复执行已标记完成的修改型工具。
- 巨大工具结果会落盘为带来源、目标、SHA-256 和摘要的 artifact，长上下文摘要仍保留原始证据引用。
- 新增确定性 `host_incident_baseline` 和 `webshell_hunt` workflow，先并行收集固定证据，再交给模型研判，减少漏步骤和重复探测。
- 内置工具由 65 个扩展至 70 个，新增主机应急、WebShell 排查、网络设备快诊和比赛答案校验等确定性能力。

### 网络设备与远程协议

- 重写 Telnet 连接/登录状态机，兼容 Username、Login、Password、Passcode 等提示，支持可配置认证正则、自动提取 CLI prompt 和特权密码。
- SSH/Telnet 增加华为 VRP、H3C Comware、锐捷 RGOS 与 Cisco IOS 设备类型；SSH 在 Linux/SFTP 特征不成立时可回退到 PTY 交互 CLI。
- 华为/H3C 支持在配置特权密码后自动执行 `super`，并持续跟踪 `system-view`、子配置视图及 `quit`/`return` 引起的 prompt 变化；配置态仍需高风险审批。
- 自动识别 `<Huawei>`、`[Huawei]`、`<H3C>`、`Ruijie#` 等 prompt，支持自定义 prompt，并根据厂商自动执行 `screen-length 0 temporary`、`terminal length 0` 等关闭分页指令。
- 增加华为/H3C/锐捷/Cisco 常见 `---- More ----`、`More`、`Press Q to break` 分页处理，按设备语义发送空格或回车，避免长输出卡住。
- 执行器会继续排空设备输出直到找回 prompt，即使达到展示上限也不会污染下一条命令的边界。
- 区分设备端过滤投影与真实字节截断：`projection=filtered, output_truncated=false` 表示 `include/exclude/begin/section` 只返回匹配行，仅 `output_truncated=true` 表示真正超限。
- 新增 `network_device_baseline` 与 `network_device_diagnose`，支持版本、板卡、接口、路由、STP、日志及 interfaces/routing/l2/logs 限时快诊。
- 完善初始化向导与 Fleet 配置，SSH/Telnet 均可设置 `device_type`、`prompt`、认证提示及 enable password。
- 强化对控制端裸 `ssh/scp/sftp` 的拦截与引导，使已配置密码/私钥的目标统一走内置 Fleet，避免子进程卡在交互式密码提示。
- 重构 FTP 登录和数据通道：优先 EPSV，不支持时回退 PASV；PASV 复用控制连接对端 IP，不盲信服务端广播地址，降低 NAT 错址和 FTP bounce 风险。
- FTP 连接器新增显式 FTPS（AUTH TLS）和隐式 FTPS，默认校验证书链/主机名，支持私有 CA，并强制 `PBSZ 0` + `PROT P` 加密数据通道。
- FTP 数据通道新增主动和自动回退模式：优先 EPRT，IPv4 老服务端回退 PORT；主动回连限制为控制连接对端，且明确拒绝与控制端代理混用。
- FTP 增加连接、命令、传输分阶段超时，完整读取多行响应和最终状态，严格校验路径/参数以阻止 CRLF 命令注入。
- FTP 下载先写入 `0600` 临时文件，仅在成功终态后原子替换目标；中断、超时或截断不会留下伪完整证据。
- FTP 目标模式支持使用 `local_run` 在控制端复核已下载文件，避免传输成功后因目标协议不提供 Shell 而中断证据校验。

### 比赛与任务效果

- 新增 `--competition` 比赛模式，针对 6 题/60 分钟的「AI 智运」节奏，强化 10 分钟限时快诊、证据绑定、最小处置、复验和回滚。
- 新增 `competition_answer_check`，按任务完成度、技术准确性、AI 应用效率、输出规范、证据覆盖和 AI 幻觉纠正检查答案。
- 完善通用比赛模式的限时快诊、设备输出截断判断、证据绑定和答案自检流程。
- 保留「上下文隔离子 Agent + 有界线索共享」设计，强化子 Agent 任务参数、目标绑定、并行任务和结果聚合。
- 优化工具选择、证据完整度检查和故障恢复流程，降低漏步骤、无依据结论和重复调用。

### 代理与连接

- 新增类 fscan 的原生启动参数：`-proxy http://127.0.0.1:8080` 和 `-socks5 socks5://127.0.0.1:1080`，两者互斥且只影响当前进程。
- 新增持久化 `controller_proxy`，支持 HTTP、HTTPS、SOCKS5 和 SOCKS5H；命令行参数优先但不回写配置。
- 统一代理 LLM、MCP HTTP、普通 HTTP/Web、浏览器、TCP/CIDR/数据库探测和 SSH/Telnet/FTP 控制端连接；HTTP CONNECT 和 SOCKS5 均支持 TCP 隧道。
- 代理用户名、密码和完整 URL 会在 Banner、模型上下文、报告、trace 和 MCP 环境中脱敏。

### TUI 与交互体验

- 新增终端背景自适应主题：默认通过 OSC 11 / `COLORFGBG` 识别深浅背景并选择高对比色板，初始化向导、`terminal_theme` 和 `--theme` 支持 `auto|dark|light`。
- 优化 Markdown 正文和表格中的 Emoji 排版，数字键帽、状态图标与中英文保持稳定间距，且不影响原始命令、审计证据和中文输入法光标。
- 修复长时运行后 TUI 出现重复行、旧边框残留和板块错位的问题；内容刷新、滚动、窗口缩放与输入换行现在失效整帧物理缓存。
- 保留逐帧精确的 macOS/中文输入法光标锚点；用于强制重绘的私有标记在写入终端前移除，不影响字符宽度或候选框位置。
- 合并供应商/运行时重复上报的相邻思考和重复询问展示，但不修改原始审计或 checkpoint 内容。
- 修复后台 Web/HTTP 服务保持运行时 Agent 永久等待 stdout/stderr 管道 EOF 的问题；前台 shell 结束后 Agent 可继续下一步，已正确脱离的服务不必被关闭。
- 高风险确认升级为 `Y` 仅本次、`A` 本会话允许同类范围、`N/Esc` 拒绝，`Enter` 继续默认拒绝。
- 会话授权采用保守指纹：文件修改按“动作类型 + 精确路径”，Shell 按“目标 + 完整命令”，工具按“目标 + 工具 + 完整参数”匹配；授权不进入 checkpoint，新建或恢复会话时清空。
- 移除旧的进程级 Shell 批准缓存；`Y` 现在真正只批准当前一次，不再跨 `/new` 或恢复会话隐式放行。

### 兼容性与稳定性

- 改进 OpenAI Chat Completions、OpenAI Responses 和 Anthropic 协议兼容性，完整处理多工具调用、流式参数、usage、响应中断和取消。
- 加强 429、服务端错误、超时、连接重置、空响应、工具超时、MCP 断连、SSH 中断及 checkpoint 损坏时的错误提示和恢复能力。
- 修复多工具批次中单个调用失败却被 checkpoint 标记为完成的问题；失败的低风险调用可正常重试，结果不确定的修改型调用仍保守防重放。
- 同一交互式目标会话的只读工具保持模型顺序执行，独立控制端工具仍可受限并行，避免 SSH/Telnet/FTP 响应串线。
- 修复 `golang.org/x/text` 的 GO-2026-5970 以及 `golang.org/x/net` 的 DNS/HTML/IDNA 解析漏洞，升级到已修复依赖，并在 CI 增加二进制符号级可达漏洞扫描。
- 发布构建启用 `-trimpath` 并关闭 VCS 自动注入，避免公开二进制泄露构建机本地路径，提高可复现性。
- 公开 `SHA256SUMS` 与 Release ZIP 严格对齐为 7 个跨平台主程序，不再混入仅开发机使用的 benchmark/smoke 和本机别名。
- 修复初始化和远程配置向导中断后仍可能保存半成品配置的问题；现在取消任一关键输入都会中止且不继续落盘。
- 收紧控制端证据文件与目录权限为 `0600/0700`，处理 SFTP 远端目录创建错误，并让 MCP 热刷新和工具调用随连接关闭而取消。
- 发布配置模板默认使用本地模式且不预填远程主机，防止用户直接复制后误连外部目标。
- 进一步将 Memory、checkpoint、报告、调度、浏览器 artifact、WebShell 进度和新建的本地 Agent 文件收紧为 `0700/0600`；无法收紧内部证据目录时明确失败，而编辑已存在的业务文件仍保留原权限，避免影响 Web/服务账号读取。
- 修复部分内置工具直接读取本地超大文件时绕过 2 MiB 安全上限的问题，避免误读巨大日志或镜像时导致进程内存异常。
- 修复极快本地命令退出时流式输出偶发丢失的竞态，同时保持后台服务继承管道时的有界返回。
- WebShell/非 TTY 日志现在始终移除 ANSI 控制序列，避免在 Web 日志、CI 和文本审计中出现乱码。
- 受控容器可显式启用 Chromium 无 sandbox 兼容模式，默认仍保持 sandbox，并在降级时给出明确安全警告。
- CI 新增 gosec 高危静态分析门禁，并加入配置模板、TUI 命令与全部 70 个工具的公开文档一致性测试。
- GitHub CI 覆盖实际默认分支 `2.0`，并升级到 Node.js 24 代的官方 Actions，避免发布分支绕过门禁或触发弃用警告。
- 移除未被运行时调用的早期内置 Skill 命令实现，避免与当前 `SKILL.md`/中间件体系形成两套行为。

## [2.0.1 Ultimate] - 2026-07-15

> 2026-07-18：该 Release 原位刷新了修正版源码和全平台二进制，版本号与
> Release 标签保持不变；下载后请使用 Release 中的 `SHA256SUMS` 校验。

### 新增

- 增加 Skill 搜索、审查、安装、更新、冻结、卸载和回滚能力，并在安装前执行安全检查。
- 增加隔离的浏览器会话、页面快照以及点击和输入等浏览器交互能力。
- MCP 改用官方 Go SDK，支持 stdio、Streamable HTTP、Resources、Prompts、OAuth 和能力热刷新。
- 增加分层长上下文整理、会话核心线索板、并发子 Agent 协作和 checkpoint 完整恢复。
- 增加钉钉、飞书和 HTTP 邮件网关通知，以及定时任务意图门控和幂等处理。
- 增加百度千帆 Coding Plan、火山方舟 Coding Plan 和 Xiaomi MiMo Token Plan / MiMo Claw 初始化预设。

### 改进

- 内置工具扩展至 65 个，补充参数契约、别名归一化和按需发现机制。
- 改进 TUI 历史翻阅、输入区、中文输入法光标、询问面板和折叠内容显示。
- 初始化向导支持自动、64K、128K、256K、512K、1M、2M 及自定义上下文窗口，并在 TUI 显示有效窗口及其来源。
- 配置修改前自动备份，并对 Skill、MCP 和 Fleet 配置执行受控写入与敏感字段脱敏。
- 改进 Fleet 多目标管理、TSecBench 跑分、模型普通 Markdown 响应恢复和工具调用可靠性。

### 安全

- Shell 高风险命令采用规则判断与 AI 复核的双层风险检查；复核不可用时失败关闭。
- 本机提权使用系统 `sudo -v` 完成密码验证，实际执行统一使用非交互式 `sudo -n`。
- 增加归档路径逃逸、解压炸弹、配置文件误覆盖和远程 sudo 交互卡死等防护。

## [2.0 Ultimate] - 2026-07-01

### 新增

- 默认提供交互式 TUI，支持多轮输入、任务中断、会话恢复和斜杠命令。
- 内置 59 个安全应急、运维和取证工具，覆盖网络、进程、日志、文件、Web、数据库、pcap、Fleet、定时任务和配置管理等场景。
- 增加本地、SSH、Telnet、FTP 和 Fleet 多目标执行模式。
- 增加 WebShell/非 TTY 后台运行模式，持续写入进度日志和 Markdown 报告。
- 增加 Fleet 目标清单、批量命令和文件操作能力。
- 增加 CTF、AWD 和 AWD-Plus 辅助工具与使用流程。
- 提供 Windows、macOS 和 Linux 多架构预编译二进制。

### 改进

- SSH 长任务改为流式输出，不再等待命令完全结束后才更新进度。
- 文件上传与下载支持包含空格或引号的路径。
- Fleet 根据实际命令和文件动作动态判断风险，减少只读操作的重复确认。
- 已配置目标上的裸 `ssh`、`scp` 和 `sftp` 操作会提示改用 Fleet，避免交互式密码输入导致任务卡住。

## [1.0 Ultimate] - 2026-01-30

### 新增

- 首次正式发布 DeepSentry。
- 提供由大语言模型驱动的自然语言任务理解、步骤规划和工具调用流程。
- 支持本地与 SSH 远程目标执行。
- 增加命令风险评估与高风险操作确认机制。
- 自动生成包含任务步骤、执行输出和结论的 Markdown 报告。
- 提供内置 SSH/SFTP 能力和 Windows、macOS、Linux 多架构单文件程序。

[未发布]: https://github.com/asaotomo/DeepSentry/compare/DeepSentry_v2.0.2_Ultimate...HEAD
[2.0.2 Ultimate]: https://github.com/asaotomo/DeepSentry/releases/tag/DeepSentry_v2.0.2_Ultimate
[2.0.1 Ultimate]: https://github.com/asaotomo/DeepSentry/releases/tag/DeepSentry_v2.0.1_Ultimate
[2.0 Ultimate]: https://github.com/asaotomo/DeepSentry/releases/tag/DeepSentry_v2.0_Ultimate
[1.0 Ultimate]: https://github.com/asaotomo/DeepSentry/releases/tag/DeepSentry_v1.0_Ultimate
