# DeepSentry v2.0 Ultimate

DeepSentry 是一个 AI 安全应急与智能运维 Agent。你只需要用自然语言描述任务，它会自动规划步骤、调用 Shell 或内置 Go 原生工具、连接本地或远程目标、持续观察结果，并生成可审计的 Markdown 报告。

> 仅允许在你拥有或已获得明确授权的系统中使用。请不要将 DeepSentry 用于未授权扫描、入侵、破坏、绕过访问控制或任何违法用途。

---

## 目录

- [一眼看懂](#一眼看懂)
- [最新版本亮点](#最新版本亮点)
- [下载哪个文件](#下载哪个文件)
- [5 分钟快速开始](#5-分钟快速开始)
- [配置文件说明](#配置文件说明)
- [常用运行模式](#常用运行模式)
- [WebShell / 蚁剑 / 非交互环境用法](#webshell--蚁剑--非交互环境用法)
- [TUI 全屏界面用法](#tui-全屏界面用法)
- [内置工具清单](#内置工具清单)
- [多目标 Fleet 用法](#多目标-fleet-用法)
- [报告、会话与记忆](#报告会话与记忆)
- [外部 MCP 与 Skills 扩展](#外部-mcp-与-skills-扩展)
- [定时任务与多通道通知](#定时任务与多通道通知)
- [从源码构建](#从源码构建)
- [常见问题](#常见问题)
- [安全建议](#安全建议)
- [项目结构](#项目结构)

---

## 一眼看懂

| 你想做什么 | DeepSentry 怎么做 |
| --- | --- |
| 排查服务器状态 | 自动查看系统版本、CPU/内存/磁盘、进程、监听端口、网络连接 |
| 分析安全事件 | 自动读取日志、筛选异常登录、排查可疑进程和网络连接 |
| 做 Web / 数据库探测 | 使用 `http_probe`、`web_snapshot`、`mysql_probe`、`redis_probe` 等内置工具 |
| 在 WebShell 里运行 | `--webshell` 立即返回，后台执行，进度和报告可用 `cat` 查看 |
| 多台服务器巡检 | 配置 `targets[]`，使用 Fleet 或多目标子 Agent 批量执行 |
| 复杂任务分工 | 子 Agent 可按任务难度动态估步，也支持多个子 Agent 并行协作 |
| 需要审计留痕 | 每次任务生成 `reports/report_<时间>.md` Markdown 报告 |
| 极简目标机没有工具 | 大量能力用 Go 原生实现，很多场景不依赖目标机安装 `ps/netstat/nmap/file/strings/tcpdump` |

核心特性：

- 中文 UI、中文提示、中文报告。
- 默认进入类 Claude Code / Codex 的 TUI 全屏界面。
- 支持本地、SSH、Telnet、FTP、Fleet 多目标。
- 内置 59 个安全应急/运维/取证工具。
- 支持 WebShell 非 TTY 场景，后台运行并实时写进度日志。
- 支持 checkpoint 恢复、多轮追问、记忆、定时任务。

---

## 最新版本亮点

当前构建版本：

```bash
./build/deepsentry --version
```

示例输出：

```text
DeepSentry v2.0 Ultimate (build 2026-07-01)
```

v2.0 Ultimate 重点能力：

| 模块 | 说明 |
| --- | --- |
| TUI 默认模式 | 默认进入全屏 Agent 面板，支持多轮输入、任务中断、恢复会话、斜杠命令 |
| WebShell 模式 | `--webshell` 提交后台执行，立即打印报告和进度路径，使用 `cat` 查看 |
| 59 个内置工具 | 覆盖网络、进程、日志、文件、文档、Web、数据库、pcap、Fleet、代理转发、定时任务、配置管理 |
| SSH 输出流修复 | 长任务不再等全部结束才输出，后台进度日志会逐步写入 |
| 文件传输修复 | `file_upload` / `file_download` 支持带空格路径和引号路径 |
| 扫描类工具修复 | 远程配置扫描、secret 扫描、service unit 审计更稳更快 |
| Fleet 体验优化 | `fleet_exec` / `fleet_file` 按真实命令或文件动作动态判险，只读操作不再反复确认 |
| 裸 SSH 防卡死 | 控制端裸 `ssh/scp/sftp` 连接已配置目标时会被拦截并提示改用 Fleet，避免卡在交互式密码输入 |

---

## 下载哪个文件

按自己的系统下载一个主程序即可。一般只需要下载 `deepsentry-*` 主程序。

CPU 架构简单判断：

- `amd64`：也叫 `x86_64` / `x64` / 64 位 x86。绝大多数 Intel / AMD 台式机、笔记本、云服务器都选这个。
- `386`：32 位 x86。只有非常老的 32 位系统才选；如果系统是 64 位，不要选 386。
- `arm64`：ARM 64 位。Apple Silicon Mac（M1/M2/M3/M4）、部分 ARM 服务器或树莓派 64 位系统选这个。

| 系统 | CPU | Release 文件名 | 运行方式 |
| --- | --- | --- | --- |
| macOS Apple Silicon | `arm64`，M1/M2/M3/M4 | `deepsentry-darwin-arm64` | `chmod +x deepsentry-darwin-arm64` |
| macOS Intel | `amd64`，Intel Mac | `deepsentry-darwin-amd64` | `chmod +x deepsentry-darwin-amd64` |
| Linux 64 位 x86 | `amd64` / `x86_64` / `x64` | `deepsentry-linux-amd64` | `chmod +x deepsentry-linux-amd64` |
| Linux ARM 64 位 | `arm64` / `aarch64` | `deepsentry-linux-arm64` | `chmod +x deepsentry-linux-arm64` |
| Linux 32 位 x86 | `386` / `i386` / `i686` | `deepsentry-linux-386` | `chmod +x deepsentry-linux-386` |
| Windows 64 位 x86 | `amd64` / `x64`，常见 Windows 电脑 | `deepsentry-windows-amd64.exe` | 双击或 PowerShell 运行 |
| Windows 32 位 x86 | `386` / `x86`，老 32 位系统 | `deepsentry-windows-386.exe` | 双击或 CMD 运行 |

建议把下载的主程序重命名为 `deepsentry`：

```bash
mv deepsentry-linux-amd64 deepsentry
chmod +x deepsentry
./deepsentry --version
```

macOS 如果提示“无法打开，因为无法验证开发者”，可以在终端执行：

```bash
xattr -d com.apple.quarantine ./deepsentry 2>/dev/null || true
chmod +x ./deepsentry
./deepsentry --version
```

Windows 推荐使用 Windows Terminal 或 PowerShell 7：

```powershell
.\deepsentry-windows-amd64.exe --version
```

---

## 5 分钟快速开始

### 第 1 步：下载或编译二进制

如果你下载的是 Release：

```bash
chmod +x ./deepsentry
./deepsentry --version
```

如果你从源码构建：

```bash
git clone <你的仓库地址>
cd DeepSentry-deepagent
bash build.sh
./build/deepsentry --version
```

### 第 2 步：创建配置文件

推荐先复制模板：

```bash
cp config.example.yaml config.yaml
```

也可以用向导生成：

```bash
./deepsentry --init
```

如果你使用 `build/` 目录里的二进制：

```bash
cd build
./deepsentry --init
```

### 第 3 步：填入 AI 模型配置

打开 `config.yaml`，至少填写：

```yaml
provider: mimo
api_protocol: auto
api_url: https://token-plan-cn.xiaomimimo.com/v1
api_key: YOUR_API_KEY
model_name: mimo-v2.5-pro
```

如果你使用其他兼容 OpenAI Chat Completions 的模型服务，可以这样写：

```yaml
provider: custom
api_protocol: auto
api_url: https://your-llm.example.com/v1
api_key: YOUR_API_KEY
model_name: your-model-name
```

### 第 4 步：选择目标模式

本地模式：

```yaml
target_protocol: local
ssh_host: ""
telnet_host: ""
ftp_host: ""
```

SSH 远程模式：

```yaml
target_protocol: ssh
ssh_host: "1.2.3.4:22"
ssh_user: root
ssh_password: "YOUR_PASSWORD"
ssh_key_path: ""
```

SSH 密钥模式：

```yaml
target_protocol: ssh
ssh_host: "1.2.3.4:22"
ssh_user: root
ssh_password: ""
ssh_key_path: "/Users/me/.ssh/id_rsa"
```

### 第 5 步：运行第一个任务

TUI 模式，适合日常使用：

```bash
./deepsentry -c config.yaml
```

进入界面后输入：

```text
排查当前服务器系统版本、内存、磁盘、监听端口和最近登录情况，最后给出风险结论。
```

经典命令行模式，适合脚本：

```bash
./deepsentry --no-tui -c config.yaml --task "查看当前系统版本和监听端口"
```

WebShell 模式，适合蚁剑、冰蝎、哥斯拉、网页终端等非交互环境：

```bash
./deepsentry --webshell -c config.yaml --task "查看当前系统版本和监听端口"
```

---

## 配置文件说明

完整示例见 [config.example.yaml](./config.example.yaml)。

### 最小可用配置

```yaml
provider: custom
api_protocol: auto
api_url: https://your-api.example.com/v1
api_key: YOUR_API_KEY
model_name: your-model-name

target_protocol: ssh
ssh_host: "1.2.3.4:22"
ssh_user: root
ssh_password: "YOUR_PASSWORD"
ssh_key_path: ""

use_native_tools: true
max_steps: 30
subagent_max_steps: 15
llm_timeout_sec: 120
llm_retries: 3
ssh_command_timeout_sec: 90
ssh_max_output_bytes: 524288
```

### AI 服务商字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `provider` | 是 | 服务商名称，如 `mimo`、`openai`、`deepseek`、`qwen`、`custom` |
| `api_protocol` | 建议填 | `auto` 会自动识别常见协议 |
| `api_url` | 是 | API 地址，可只填到 `/v1` |
| `api_key` | 云模型必填 | API Key，不要提交到 GitHub |
| `model_name` | 建议填 | 模型名称，留空时使用 provider 预设 |
| `llm_timeout_sec` | 否 | 单次 LLM 超时时间，建议 120 |
| `llm_retries` | 否 | LLM 重试次数，建议 3 |

### Agent 步数控制

| 字段 | 默认值 | 说明 |
| --- | ---: | --- |
| `max_steps` | `30` | 主 Agent 单次任务最大推理步数 |
| `subagent_max_steps` | `15` | 子 Agent 步数用户上限。AI 会按任务难度估算 `task_max_steps`，但最终不会超过该值 |

临时提高复杂任务的子 Agent 上限：

```bash
./deepsentry -c config.yaml --subagent-max-steps 30 --task "完整分析 auth.log 和 syslog，输出登录时间线、可疑 IP、提权行为和证据链"
```

复杂任务中，主 Agent 会优先把独立方向拆给子 Agent。例如日志、网络、Webshell 三个方向可以并行执行，完成后由主 Agent 合并证据链、去重结论并继续下一步。

支持的 provider：

```text
openai, anthropic, google, deepseek, qwen, hunyuan, tencent_hy,
teleai, ctyun, minimax, mimo, glm, xai, grok, ollama, lmstudio, custom
```

### 目标连接字段

| 模式 | 关键字段 | 说明 |
| --- | --- | --- |
| 本地 | `target_protocol: local` | 所有命令在控制端本机执行 |
| SSH | `target_protocol: ssh`、`ssh_host`、`ssh_user` | 推荐模式，支持 Shell 和文件读写 |
| Telnet | `target_protocol: telnet`、`telnet_host` | 老设备/极简环境 |
| FTP | `target_protocol: ftp`、`ftp_host` | 仅文件/目录能力，无 Shell |
| Fleet | `targets[]` | 多台目标批量运维 |

### 让 Agent 管理 config.yaml

DeepSentry 内置 `config_manage` 工具，Agent 可以在用户明确要求时维护控制端本机的 `config.yaml`。所有写操作都会先在同目录创建备份：

```text
.deepsentry_backups/config_<timestamp>.yaml
```

支持的常见管理动作：

| 需求 | 工具动作 |
| --- | --- |
| 查看当前配置摘要 | `action=status` |
| 读取指定配置项 | `action=get`，参数 `key` |
| 校验 YAML 是否可读 | `action=validate` |
| 手动创建备份 | `action=backup` |
| 添加外部 Skill 目录 | `action=add_skill_source`，参数 `source`，也兼容 `path/dir` 表示 Skill 目录 |
| 添加 stdio MCP Server | `action=add_mcp_server`，参数 `spec` 或 `name/command/args` |
| 导入 Claude Desktop MCP JSON | `action=import_claude_mcp`，参数 `import_path` 或 `content` |
| 启用/禁用 MCP Server | `action=enable_mcp_server` / `action=disable_mcp_server`，参数 `name` |
| 启用/禁用 Skill 来源 | `action=enable_skill_source` / `action=disable_skill_source`，参数 `source` |
| 添加/更新 Fleet 目标 | `action=add_target`，参数 `protocol/host/user/password/key_path/tags` |
| 将已有单台配置转为 Fleet | `action=enable_fleet`，会把当前单台目标纳入 `targets` 并切到控制端模式 |
| 设置单台 SSH 目标 | `action=set_ssh`，参数 `host/user/password/key_path` |
| 修改允许的单值字段 | `action=set`，参数 `key/value` |
| 修复并替换整份配置 | `action=replace_yaml`，参数 `content` |

示例自然语言：

```text
把 /opt/deepsentry-skills 添加到 config.yaml 的 skill_sources，修改前先备份。
```

```text
把这台 SSH 机器添加为 Fleet 目标：host=10.0.0.8:22，user=root，password=xxx，tag=prod。
```

工具输出会隐藏密码、Token、Secret 等敏感值，但配置文件本身仍可能包含凭据，请保护好 `config.yaml` 和备份目录。

如果 `config.yaml` 已经损坏到无法解析，Agent 可以读取原文件、生成修复后的完整 YAML，再用 `replace_yaml` 校验并替换；替换前仍会保留旧文件备份。

### 不想把密钥写进 config.yaml？

可以用环境变量覆盖：

```bash
export DEEPSENTRY_API_KEY="你的 API Key"
export DEEPSENTRY_SSH_HOST="1.2.3.4:22"
export DEEPSENTRY_SSH_USER="root"
export DEEPSENTRY_SSH_PASSWORD="你的 SSH 密码"
./deepsentry -c config.yaml
```

建议：

- `config.yaml` 放本机使用，不提交 Git。
- 对外发布只提交 `config.example.yaml`。
- CI 或服务器环境使用环境变量注入密钥。

---

## 常用运行模式

### 1. 默认 TUI

```bash
./deepsentry -c config.yaml
```

适合人工值守排查、持续追问、多轮分析。

### 2. 直接带任务进入 TUI

```bash
./deepsentry -c config.yaml "排查目标机内存、磁盘和监听端口"
```

### 3. 经典 stdout 模式

```bash
./deepsentry --no-tui -c config.yaml --task "审计 SSH 登录失败记录"
```

适合普通终端、脚本、CI。

### 4. JSONL 自动化模式

```bash
./deepsentry --no-tui --json -c config.yaml --task "mem_info + port_listen" > events.jsonl
```

适合外部程序消费事件流。

### 5. 静默模式

```bash
./deepsentry --quiet -c config.yaml --task "查看当前系统状态"
```

### 6. 计划模式

```bash
./deepsentry --plan -c config.yaml --task "配置每天 9 点巡检 CPU、内存、磁盘并生成报告"
```

### 7. 无人值守模式

```bash
./deepsentry --batch -y -c config.yaml --task "自动巡检目标机 /proc"
```

`--batch -y` 会自动批准高风险动作，请只在受控环境使用。

### 8. 恢复会话

```bash
./deepsentry --list-sessions
./deepsentry --resume session_xxx -c config.yaml
```

TUI 图形化选择恢复：

```bash
./deepsentry --tui --pick-session -c config.yaml
```

---

## WebShell / 蚁剑 / 非交互环境用法

很多 WebShell 环境不适合 TUI，也不适合长时间阻塞等待。DeepSentry 提供 `--webshell` 专用模式。

### 基本命令

```bash
./deepsentry --webshell -c config.yaml --task "查看当前系统版本"
```

前台会立即返回类似：

```text
[WEB] DeepSentry 任务已提交后台执行
[WEB] 执行结果报告: /path/to/reports/report_20260630_145544.md
[WEB] 实时进度日志: /path/to/reports/webshell_progress_20260630_145544.log
[WEB] 固定索引文件: /path/to/reports/latest_webshell.txt
[WEB] 查看进度: cat /path/to/reports/webshell_progress_20260630_145544.log
[WEB] 查看报告: cat /path/to/reports/report_20260630_145544.md
```

注意这里推荐用 `cat`，不是 `tail -f`。很多 WebShell 对长连接和持续输出不友好，`cat` 更稳。

### 查看进度

```bash
cat reports/latest_webshell.txt
cat reports/webshell_progress_20260630_145544.log
```

### 查看报告

```bash
cat reports/report_20260630_145544.md
```

### WebShell 模式特点

- 父进程立即返回，不会卡住 WebShell 页面。
- 子进程后台执行，进度写入 `webshell_progress_<时间>.log`。
- 最终报告写入 `report_<时间>.md`。
- `reports/latest_webshell.txt` 永远指向最近一次任务路径。
- 等同于后台启用 `--no-tui --batch -y`，高风险动作会自动批准。
- 如果 Agent 必须追问，任务会保存 checkpoint，可用 `--resume` 补充信息继续。

### WebShell 恢复任务

```bash
./deepsentry --webshell -c config.yaml --resume session_xxx --task "补充信息：目标 Web 目录是 /var/www/html"
```

---

## TUI 全屏界面用法

TUI 是默认模式：

```bash
./deepsentry -c config.yaml
```

常用快捷键：

| 快捷键 | 功能 |
| --- | --- |
| `Tab` | 聚焦输入框 |
| `Enter` | 发送任务或追问 |
| `Shift+Enter` / `Alt+Enter` / `Ctrl+J` | 输入换行 |
| `Esc` | 中断当前任务或退出输入状态 |
| `Ctrl+L` | 清屏 |
| `Ctrl+U` | 清空输入 |
| `e` | 展开/折叠思考或子 Agent 结果 |
| `Y` | 批准高风险操作 |
| `N` | 拒绝高风险操作 |
| `q` | 空闲时退出 |

斜杠命令：

| 命令 | 说明 |
| --- | --- |
| `/help` | 查看帮助 |
| `/new` | 新建任务 |
| `/restart` | 重新开始 |
| `/clear` | 清屏 |
| `/status` | 查看状态 |
| `/cost` | 查看 token 使用量 |
| `/model` | 查看当前模型 |
| `/compact` | 压缩长上下文提示 |
| `/sessions` | 查看可恢复会话 |
| `/resume` | 查看恢复提示 |
| `/config` | 查看配置摘要 |
| `/exit` / `/quit` | 退出 |

输入 `/` 会显示命令联想，输入 `/c` 可快速补全 `/clear`。

---

## 内置工具清单

当前版本注册 59 个内置工具。它们由 Go 原生实现或统一调度，Agent 会按需发现和调用，不会每轮把全部工具塞进 prompt。

### 按场景分类

| 场景 | 工具 |
| --- | --- |
| 网络连通 | `ping`、`traceroute`、`dns_lookup`、`bandwidth_test` |
| 连接审计 | `net_connections`、`port_listen`、`route_table`、`arp_table`、`firewall_status` |
| 系统应急 | `mem_info`、`process_list`、`target_health_summary`、`disk_usage`、`file_tail`、`login_audit`、`service_units`、`file_hash` |
| 取证分析 | `file_ident`、`file_strings`、`read_gzip`、`read_log`、`pcap_analyze`、`sqlite_inspect` |
| 文档解析 | `document_parse` |
| 端口和内网 | `nmap_scan`、`cidr_scan`、`netcat_probe`、`service_fingerprint` |
| HTTP / Web | `http_probe`、`http_fetch`、`web_snapshot`、`headless_browser` |
| 抓包和流量 | `flow_snapshot`、`packet_capture` |
| 数据库探测 | `redis_probe`、`mysql_probe`、`postgres_probe`、`oracle_probe` |
| 配置审计 | `app_config_discover`、`db_config_audit`、`db_log_read`、`secret_scan`、`service_unit_audit`、`container_inventory` |
| CTF / AWD | `flag_scan`、`awd_service_check` |
| 脚本和文件 | `script_run`、`file_download`、`file_upload`、`archive_pack`、`archive_extract` |
| 代理转发 | `tcp_forward`、`socks5_proxy` |
| 自动化任务 | `schedule_task` |
| Fleet 批量 | `fleet_inventory`、`fleet_exec`、`fleet_file` |

### 工具风险等级

| 风险 | 含义 |
| --- | --- |
| low | 只读或低影响操作 |
| medium | 会主动连接目标、读取较敏感信息或产生明显探测行为 |
| high | 可能执行脚本、上传文件、扫描端口、抓包、代理转发或批量执行 |

交互 TUI 模式下，高风险动作会请求确认。`--batch` 和 `--webshell` 会自动批准，请谨慎使用。

Fleet 工具有动态判险逻辑：

- `fleet_exec` 会看真实 `command` / `cmd` 内容。`ls`、`cat`、`df -h`、`uptime` 等只读命令可自动执行；`rm`、写重定向、重启、提权等高风险命令仍会确认。
- `fleet_file` 的 `ls`、`read`、`download` 可自动执行；`upload` 会写入目标文件，需要确认。

### 工具启用/禁用

默认全部启用。可以在配置中控制：

```yaml
enabled_tools: []
disabled_tools:
  - tcp_forward
  - socks5_proxy
  - file_upload
  - script_run
```

如果 `enabled_tools` 非空，它会作为白名单：

```yaml
enabled_tools:
  - mem_info
  - port_listen
  - net_connections
  - read_log
  - secret_scan
```

---

## 多目标 Fleet 用法

Fleet 适合一次管理多台服务器、网络设备或 FTP 证据机。

### 配置示例

```yaml
targets:
  - name: web-01
    protocol: ssh
    host: "10.0.0.11:22"
    user: root
    password: ""
    key_path: "/Users/me/.ssh/id_rsa"
    tags: ["prod", "web"]

  - name: legacy-router
    protocol: telnet
    host: "10.0.0.2:23"
    user: admin
    password: admin
    prompt: ">"
    tags: ["legacy", "network"]

  - name: ftp-backup
    protocol: ftp
    host: "10.0.0.50:21"
    user: backup
    password: "YOUR_PASSWORD"
    tags: ["backup", "evidence"]
```

### selector 规则

| selector | 命中 |
| --- | --- |
| `all` | 全部目标 |
| `web-01` | 按 name |
| `10.0.0.11` | 按 host |
| `ssh` / `telnet` / `ftp` | 按协议 |
| `prod` / `web` | 按 tag |
| `prod,ssh` | 同时匹配多个条件 |

### 常见任务

列出目标：

```text
列出当前 Fleet 目标清单
```

批量巡检：

```text
对 prod 标签的 SSH 主机执行内存、磁盘、监听端口巡检，最后汇总异常。
```

批量命令：

```text
对 selector=prod,ssh 的目标执行 uptime 和 df -h，并汇总结果。
```

### 连接和密码注意事项

如果目标已经写在 `targets[]` 或单台 SSH 配置里，不要让 Agent 在控制端手写裸 `ssh/scp/sftp root@host ...`。这些系统命令不会读取 DeepSentry 的 `config.yaml` 密码/私钥，可能直接卡在 OpenSSH 的交互式密码提示里。

正确方式：

```text
对 target-01 执行 echo SSH_OK
```

Agent 应调用：

```json
{"action":"tool","tool_name":"fleet_exec","tool_args":{"selector":"target-01","command":"echo SSH_OK","concurrency":"1"}}
```

下载文件应走 `fleet_file`：

```json
{"action":"tool","tool_name":"fleet_file","tool_args":{"selector":"target-01","action":"download","remote_path":"/tmp/flag.txt","local_path":"~/.deepsentry/workspace/flag.txt"}}
```

需要每台机器独立分析时，优先使用子 Agent 的 `target_selector`，例如让 `log-analyst` 分别分析 `prod` 目标并汇总。

---

## 报告、会话与记忆

### 报告位置

每次任务都会生成 Markdown 报告：

```text
reports/report_<timestamp>.md
```

报告包含：

- 任务标题和启动时间。
- Agent 思考摘要。
- 执行动作。
- 命令和工具输出。
- 最终结论。

### 会话恢复

DeepSentry 会保存 checkpoint：

```text
~/.deepsentry/sessions/<session_id>/checkpoint.json
```

查看会话：

```bash
./deepsentry --list-sessions
```

恢复会话：

```bash
./deepsentry --resume session_xxx -c config.yaml
```

### 记忆层

| 记忆 | 位置 | 说明 |
| --- | --- | --- |
| 内置 AGENTS.md | 二进制内置 | 默认行为准则 |
| 用户 AGENTS.md | `~/.deepsentry/AGENTS.md` | 用户级偏好 |
| 项目 AGENTS.md | `.deepsentry/AGENTS.md` | 项目级偏好 |
| KV 记忆 | `~/.deepsentry/memory/store.json` | Agent 保存的结构化事实 |

明显的密码、Token、私钥、Webhook 密钥会被记忆系统拒绝保存。

---

## 外部 MCP 与 Skills 扩展

DeepSentry 支持加载一部分 Claude / Codex / OpenClaw / Hermes 生态中常见的外部能力，但不是所有格式都能无缝通用。

### 外部 Skills

DeepSentry 的 Skill 加载规则很简单：一个目录就是一个 Skill，目录里必须有 `SKILL.md`。

默认加载目录：

```text
./skills
~/.deepsentry/skills
```

推荐目录结构：

```text
~/.deepsentry/skills/
└── log-audit/
    └── SKILL.md
```

`SKILL.md` 示例：

```markdown
---
name: log-audit
description: Linux 登录日志审计与异常来源分析
license: Apache-2.0
---

# Log Audit

当用户需要分析 auth.log、secure、syslog 登录异常时，按以下流程执行……
```

如果你的外部 Skill 本身就是 `SKILL.md` + YAML frontmatter 结构，通常可以直接复制到 `~/.deepsentry/skills/<skill-name>/SKILL.md` 使用。如果外部项目使用的是其他清单文件或打包格式，需要先转换成上面的目录结构。

也可以在 `config.yaml` 指定额外来源目录：

```yaml
skill_sources:
  - "skills"
  - "~/.deepsentry/skills"
  - "/opt/deepsentry-skills"
disabled_skill_sources:
  - "/opt/old-skills"
```

TUI 快捷命令：

```text
/skill list
/skill load log-audit
/skill unload log-audit
/skill add /opt/deepsentry-skills
/skill off /opt/old-skills
/skill on /opt/old-skills
/skill remove /opt/old-skills
```

`load/unload` 作用于当前会话已加载 Skill；`add/off/on/remove` 作用于 `config.yaml` 的 Skill 来源目录，通常在新会话生效。

### 外部 MCP

DeepSentry 当前支持 stdio 类型的 MCP tools。旧短格式仍兼容：

```yaml
mcp_servers:
  - "fs:npx:-y,@modelcontextprotocol/server-filesystem,/tmp"
```

含义是：

```text
名称:启动命令:参数1,参数2,参数3
```

Agent 会在启动时连接 MCP Server，读取 `tools/list`，之后可以通过 `mcp:<工具名>` 调用外部工具。

推荐使用结构化格式，支持 `env`、`cwd` 和禁用开关：

```yaml
mcp_server_configs:
  - name: fs
    type: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    cwd: "/tmp"
    env:
      EXAMPLE_TOKEN: "xxx"
    disabled: false
```

TUI 快捷命令：

```text
/mcp list
/mcp import ~/Library/Application Support/Claude/claude_desktop_config.json
/mcp add fs npx -y,@modelcontextprotocol/server-filesystem,/tmp
/mcp off fs
/mcp on fs
/mcp remove fs
```

当前支持：

| 能力 | 状态 |
| --- | --- |
| stdio MCP tools/list | 支持 |
| stdio MCP tools/call | 支持 |
| Claude Desktop JSON 配置直接导入 | 支持，使用 `/mcp import <json路径>` 或 `config_manage action=import_claude_mcp` |
| env / cwd 细粒度启动参数 | 支持，使用 `mcp_server_configs` |
| MCP resources / prompts | 暂不支持 |
| HTTP / SSE MCP Server | 暂不支持 |

---

## 定时任务与多通道通知

DeepSentry 的定时任务可以在生成本地报告后发送外部通知。当前支持：

| 通道 | notify 值 | 配置 |
| --- | --- | --- |
| 钉钉机器人 | `dingtalk` | `dingtalk_webhook`，可选 `dingtalk_secret` |
| 飞书/Lark 机器人 | `feishu` | `feishu_webhook`，可选 `feishu_secret` |
| HTTP 邮件网关 | `email` | `email_gateway_url`、`email_to`，可选 token/header/from |

`notify` 支持逗号多选，例如 `dingtalk,feishu,email`，会按顺序同时发送。

基础配置：

```yaml
scheduler_enabled: true
scheduler_store: reports/schedules/tasks.json
scheduler_interval_sec: 30
scheduler_timezone: Local

# 钉钉机器人
dingtalk_webhook: ""
dingtalk_secret: ""

# 飞书/Lark 自定义机器人
feishu_webhook: ""
feishu_secret: ""

# HTTP 邮件网关
email_gateway_url: ""
email_gateway_token: ""
email_gateway_header: Authorization
email_to: "secops@example.com"
email_from: "deepsentry@example.com"
```

创建钉钉任务：

```text
每天 9 点巡检服务器 CPU、内存、磁盘和监听端口，生成报告并发钉钉。
```

创建飞书任务：

```text
每天 9 点巡检服务器 CPU、内存、磁盘和监听端口，生成报告并发飞书。
```

创建多通道任务：

```text
每天 9 点巡检生产服务器，生成报告，同时发钉钉、飞书和邮件通知。
```

也可以显式调用工具：

```text
使用 schedule_task 添加任务：每天9点巡检，notify=dingtalk,feishu,email，kind=inspection。
```

邮件网关请求格式为 HTTP JSON POST：

```json
{
  "to": ["secops@example.com"],
  "from": "deepsentry@example.com",
  "subject": "DeepSentry 定时任务: 巡检",
  "markdown": "# 报告正文",
  "text": "报告正文",
  "source": "DeepSentry"
}
```

鉴权规则：

- `email_gateway_header: Authorization` 时，`email_gateway_token` 会以 `Bearer <token>` 发送。
- 如果你的网关使用 API Key，可设置 `email_gateway_header: X-API-Key`。
- 如果需要自定义完整 header，可写成 `email_gateway_header: "X-Token: {token}"`。

只运行调度器：

```bash
./deepsentry --scheduler -c config.yaml
```

查看、添加、删除、立即运行调度任务，也可以让 Agent 调用 `schedule_task` 工具完成。

## 从源码构建

### 环境要求

- Go 1.21 或更高版本。
- macOS、Linux 或 Windows。
- 如需远程模式，需要目标 SSH/Telnet/FTP 可达。

### 拉取代码

```bash
git clone <你的仓库地址>
cd DeepSentry-deepagent
```

中国大陆网络可配置 Go 代理：

```bash
go env -w GOPROXY=https://goproxy.cn,direct
```

### 构建当前平台

这种方式适合开发调试。它不会注入 `build.sh` 里的发布日期 ldflags，所以 `--version` 看到的 build 日期可能是代码默认值；正式发布请使用下一节的 `bash build.sh`。

macOS / Linux：

```bash
go build -o deepsentry ./cmd/main.go ./cmd/usage.go ./cmd/survey_compat.go ./cmd/console_other.go
```

Windows：

```powershell
go build -o deepsentry.exe ./cmd/main.go ./cmd/usage.go ./cmd/survey_compat.go ./cmd/console_windows.go
```

### 一键交叉编译发布包

```bash
bash build.sh
```

输出目录：

```text
build/
  deepsentry-darwin-amd64
  deepsentry-darwin-arm64
  deepsentry-linux-amd64
  deepsentry-linux-arm64
  deepsentry-linux-386
  deepsentry-windows-amd64.exe
  deepsentry-windows-386.exe
  deepsentry
```

---

## 常见问题

### 1. 提示找不到配置文件

运行：

```bash
./deepsentry --init
```

或显式指定：

```bash
./deepsentry -c config.yaml
```

### 2. SSH 连接失败

检查：

- `ssh_host` 是否包含端口，例如 `1.2.3.4:22`。
- `ssh_user` 是否正确。
- 密码或 `ssh_key_path` 是否正确。
- 在系统终端里单独测试 `ssh root@1.2.3.4 -p 22` 是否可达。注意不要让 DeepSentry Agent 通过裸 `ssh/scp/sftp` 访问已配置目标；应使用 `fleet_exec` / `fleet_file`。
- 云服务器安全组是否放行。

### 3. 已经在 config.yaml 写了密码，为什么还提示 `root@host's password:`？

通常是 Agent 生成了控制端裸 `ssh/scp/sftp` 命令。OpenSSH 子进程不会读取 DeepSentry 的配置文件，也不会把密码提示交给 TUI 输入框。

解决办法：

- 退出当前卡住的进程，重新启动新版二进制。
- 把多目标访问改成 `fleet_exec` / `fleet_file`。
- 单台远程模式下直接执行目标命令，不要再包一层 `ssh root@host`。

### 4. WebShell 没有持续输出

WebShell 模式不会在前台持续刷屏，而是写入进度文件：

```bash
cat reports/latest_webshell.txt
cat reports/webshell_progress_<timestamp>.log
cat reports/report_<timestamp>.md
```

### 5. WebShell 报告没有生成

优先看进度日志：

```bash
cat reports/webshell_progress_<timestamp>.log
```

常见原因：

- `config.yaml` 路径不对。
- API Key 无效。
- SSH 连接失败。
- 目标命令超时。

### 6. LLM 报 429 / rate limit

说明模型服务商限流或高负载。可以：

- 稍后重试。
- 增大 `llm_retries`。
- 增大 `llm_timeout_sec`。
- 更换模型或服务商。

### 7. 终端乱码或显示错位

尝试：

```bash
DEEPSENTRY_PLAIN=1 ./deepsentry -c config.yaml
DEEPSENTRY_ASCII=1 ./deepsentry --no-tui -c config.yaml --task "查看系统状态"
./deepsentry --no-color -c config.yaml
```

Windows 推荐 Windows Terminal 或 PowerShell 7。

### 8. TUI 退出后终端状态不正常

运行：

```bash
reset
stty sane
```

### 9. 不想让 Agent 执行高风险工具

在 `config.yaml` 禁用：

```yaml
disabled_tools:
  - script_run
  - file_upload
  - archive_extract
  - tcp_forward
  - socks5_proxy
  - nmap_scan
  - cidr_scan
  - packet_capture
```

---

## 安全建议

- 只在授权环境使用。
- 不要把真实 `config.yaml`、API Key、SSH 密码提交到 GitHub。
- 分享项目或压缩包时只带 `config.example.yaml`，不要带真实配置。
- 生产环境慎用 `--batch -y`。
- WebShell 模式会自动批准动作，建议只在隔离环境或应急授权场景使用。
- 高风险工具如 `script_run`、`file_upload`、`tcp_forward`、`socks5_proxy` 默认存在确认机制；无人值守时请先配置 `disabled_tools`。
- 已配置目标请使用 `fleet_exec` / `fleet_file` / `target_selector`，不要在 Agent 内裸跑 `ssh/scp/sftp` 访问目标。
- 生成报告可能包含敏感路径、主机名、日志片段，公开前请脱敏。

---

## 项目结构

```text
cmd/                    CLI 入口、TUI/经典/WebShell 参数处理
internal/analyzer/      LLM 协议、JSON/action 解析
internal/harness/       Agent 循环、动作执行、中间件、checkpoint
internal/tui/           全屏 TUI 界面
internal/builtin/       Go 原生内置工具实现
internal/tools/         工具注册表与调度
internal/executor/      Local / SSH / Telnet / FTP / Fleet 执行器
internal/memory/        内置 AGENTS.md、用户记忆、KV 记忆
internal/scheduler/     本地定时任务
internal/security/      命令风险评估
docs/操作手册.md          详细中文操作手册
config.example.yaml      配置模板
build.sh                 一键交叉编译脚本
```

---

## License

本项目采用 Apache License 2.0 开源协议，详见 [LICENSE](./LICENSE)。

---

## Credits

DeepSentry v2.0 Ultimate is developed by Hx0 Team.

Author: asaotomo
