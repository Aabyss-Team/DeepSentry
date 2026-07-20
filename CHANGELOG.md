# 更新日志

本文档记录 DeepSentry 各正式版本的重要变化。

版本日期以 GitHub Release 的首次发布时间为准。项目当前使用带有
`Ultimate` 后缀的 Release 标签，因此下文保留对应的正式版本名称。

## [未发布]

尚无已记录的未发布变更。

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

[未发布]: https://github.com/asaotomo/DeepSentry/compare/DeepSentry_v2.0.1_Ultimate...HEAD
[2.0.1 Ultimate]: https://github.com/asaotomo/DeepSentry/releases/tag/DeepSentry_v2.0.1_Ultimate
[2.0 Ultimate]: https://github.com/asaotomo/DeepSentry/releases/tag/DeepSentry_v2.0_Ultimate
[1.0 Ultimate]: https://github.com/asaotomo/DeepSentry/releases/tag/DeepSentry_v1.0_Ultimate
