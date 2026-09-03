# DeepSentry × Hx0 HawkEye MCP 深度适配

DeepSentry 不复制 HawkEye 的浏览器能力，而是把 HawkEye MCP 当作“真实浏览器 + 抓包拦截 + 安全取证”执行层：DeepSentry 负责任务规划、多步证据链、风险审批、视觉回灌和报告，HawkEye 负责在用户已登录的 Chrome / Firefox 中执行。适配全部在 DeepSentry 侧完成，不要求修改 HawkEye 代码。

## 1. 连接

先在 Chrome 或 Firefox 安装并启用 HawkEye，然后在 DeepSentry `config.yaml` 配置：

```yaml
mcp_server_configs:
  - name: hawkeye
    type: stdio
    command: node
    args:
      - /absolute/path/Hx0-HawkEye/mcp-server/hawkeye-mcp-server.mjs
    startup_timeout_sec: 30
    tool_timeout_sec: 0
    required: false
```

`tool_timeout_sec: 0` 或省略时，DeepSentry 会使用 HawkEye 分工具超时：`browser_research` 205 秒，Search / Fetch / Captcha / Fuzz 130 秒，快照/导航/截图等 100 秒，其余使用通用 60 秒。显式配置的超时值永远优先；如果需要 Research，不建议显式设得低于 205 秒。

也可先单独启动 HawkEye Server，再连接本机 Streamable HTTP：

```yaml
mcp_server_configs:
  - name: hawkeye
    type: streamable_http
    url: http://127.0.0.1:19016/mcp
```

DeepSentry 允许回环 HTTP，非回环远程 MCP 仍强制 HTTPS。执行 `/mcp status` 应看到 Server 已连接和 51 个 Tools；浏览器扩展也应显示 MCP 桥已连接。同一个 `19016` 端口不要重复启动多个 HawkEye Server。

Server 进程或本地桥重启后，可执行 `/mcp reconnect hawkeye` 原地重建会话并重新发现全部能力。DeepSentry 不会自动重放断线前的工具调用，因为修改型操作可能已经在浏览器端生效但响应丢失。

## 2. DeepSentry 识别的 HawkEye 1.0.6 能力面

| 能力链 | HawkEye MCP 工具 |
| --- | --- |
| 浏览与调研 | `browser_navigate/search/fetch/research/go_back/go_forward/tabs/reload` |
| 页面定位 | `browser_snapshot/find/read_text/wait/wait_for` |
| 真实交互 | `browser_click/hover/type/select_option/press_key/fill_form/drag/scroll/handle_dialog` |
| 文件与视觉 | `browser_screenshot/file_upload/download_file/captcha_assist/resize` |
| 浏览器证据 | `browser_security/get_console_logs/exam_questions/answer_questions` |
| 抓包取证 | `hawkeye_capture_start/stop/state/history/inspect` + `hawkeye_request_get` |
| 主动安全验证 | `hawkeye_scope/request_mutate/request_replay/fuzz_run/response_compare` |
| 拦截与审计 | `hawkeye_intercept/findings/sensitive_scan/darklink_scan` |
| 编解码与脚本 | `hawkeye_codec/script_list/script_run/script_upsert/evaluate` |

即使 MCP Server 被用户命名为 `browser` 而不是 `hawkeye`，DeepSentry 也会通过同一 Server 上的多个 HawkEye 专有工具签名识别。单独出现的通用 `browser_*` 不会被误判为 HawkEye。

## 3. 默认工作流

### 页面交互

1. 工具列表里已有 `hx0-hawkeye__*` 时，直接做用户任务，不要先检查 MCP 安装、端口或文件 MD5。
2. 已知 URL 用 `browser_navigate`；搜索结果拿到 BV 链接后再 navigate 到完整视频 URL。整次任务最多 `browser_tabs action=new` 一次。
3. `browser_snapshot` 取得 `ref` / 无障碍名称。只看本轮返回的树，不要 `read_file` snapshot artifact。
4. 精确点击必须同时传 `text=无障碍名称` 和 `ref`。`element` 只是说明。
5. 下拉/倍速/清晰度用 `browser_select_option`，`value` 传可见项（如 `2.0x`）。
6. `browser_snapshot diff=true` 验证结果。不要对同一页并行连点。

大页面优先 `browser_find` / `browser_read_text`。当 `complete=false` 时传入 `next_cursor`。DeepSentry 会丢掉 snapshot/click 返回里的巨大 `elements` JSON，只保留无障碍树和一行摘要，避免模型去读 artifact。

### 播放、倍速和全屏

B 站等播放器不要靠连点控件碰运气。HawkEye 已连通时，**第一步 `load_skill("bilibili-play")`**，禁止改用内置 `browser_browse`。推荐顺序：

1. `browser_navigate` 打开搜索页或视频 URL。拿到 BV 后再 navigate 到完整 `https://www.bilibili.com/video/BV.../`；合集第 N 集用 `?p=N`。优先按 URL 导航，不要点搜索卡片。整次任务最多 `browser_tabs action=new` 一次。
2. `hawkeye_evaluate` 读 `video` 的 `paused` / `currentTime` / `playbackRate`。`currentTime` 递增才算在播。
3. 倍速：**主路径**是一次 evaluate 设置 `video.playbackRate = 2`。不要点「倍速」菜单。`browser_select_option` 只用于清晰度等下拉。
4. 全屏：聚焦播放器后 `browser_press_key key=f`。未传 `inputMode` 时 DeepSentry 会自动补 `trusted`。用 `document.fullscreenElement` 验证（B 站常见 `bpx-player-container`）。
5. 全屏 GPU 层会导致 `browser_screenshot` 黑屏。这不是没在播。需要画面时用 evaluate 对 `video` 做 `canvas.drawImage`，不要反复截图。

需要 `userActivation` 的操作显式使用：

```json
{"key":"f","inputMode":"trusted"}
```

或：

```json
{"ref":"fullscreen-button","clickMode":"trusted"}
```

Chrome 由 HawkEye 通过 CDP trusted input 发送，Firefox 由 HawkEye native-input relay 发送真实 OS 输入。先选中/聚焦标签页，再发键或鼠标；必须用 `document.fullscreenElement` 或可见页面状态验证。`trusted` 返回失败时，不得退回 JS `dispatchEvent` 后声称已获得真实手势。

### 抓包和请求头/体

1. `hawkeye_capture_state` 确认抓包状态。
2. 需要时 `hawkeye_capture_start`。
3. 在目标页面触发请求。
4. `hawkeye_capture_history` 按 host / method / resourceType / channelType 筛选。
5. `hawkeye_capture_inspect` 看摘要，`hawkeye_request_get parts=[...]` 精确取 `request_headers` / `request_body` / `response_headers` / `response_body` / raw。

GET 通常本来就没有 request body；应区分“有请求行但无 body”与“请求头没有被捕获”。需要结束由本任务启动的抓包时调用 `hawkeye_capture_stop`。

### 主动测试和拦截

主动请求严格使用：

```text
scope get
  → 确认用户授权的 host / activeTestingEnabled / fuzzingEnabled
  → request_mutate（离线）
  → request_replay
  → response_compare
  → fuzz_run（仅 fuzzingEnabled=true）
```

拦截严格使用：

```text
intercept enable → 触发请求 → queue → release/drop → disable
```

`disable` 在 HawkEye 中同时停止拦截并放行队列。DeepSentry 在该 MCP 连接成功开启拦截后会记录状态；显式断开、Server 替换或程序退出时会在断连前尝试 `disable`，避免浏览器请求长期挂起。这是安全网，不代替 Agent 在正常任务流中完整收尾。

## 4. 动作级风险和确认

DeepSentry 不再把所有 HawkEye MCP 调用粗暴当成同一级风险：

| 级别 | 典型操作 |
| --- | --- |
| Low（不弹确认） | 普通 Navigate / Tabs New/Select / Click / Type / Trusted Input，Snapshot / Find / Read Text，Capture Start/Stop/History/Inspect/Request Get，Scope Get，Intercept Enable/Disable/Status/Queue，不落盘 Screenshot，Download Discover，离线 Mutate / Compare / Codec / Scan |
| Medium | Tabs Close、截图落盘、真正启动 Download、Captcha Solve、Findings 写入 |
| High | Scope Set / Add / Remove / Clear、Request Replay / Fuzz、Intercept Release / Drop、File Upload、Evaluate / Script Run / Upsert、Findings Clear |

服务端 `annotations` 会被完整保留，但只作为提示；风险降级必须同时命中 DeepSentry 本地 HawkEye 契约，避免任意第三方 Server 伪造 `readOnlyHint`。

## 5. 截图和视觉证据

- 不传 `save_to_file`：HawkEye 返回 MCP ImageContent，DeepSentry 以 `0600` 保存到 `reports/mcp-artifacts/`，校验哈希后回灌视觉模型。
- 传 `save_to_file=true`：HawkEye 还会按 `file_path` 落盘；模型应核对 `structuredContent.saved_to` / `file_bytes`。
- 两者不冲突：前者是 DeepSentry 的对话视觉 artifact，后者是用户指定的取证文件。

## 6. 故障定位

| 现象 | 检查 |
| --- | --- |
| `/mcp status` 无 51 个工具 | 确认 Node 路径、Server 文件路径，以及是否启动了匹配的 HawkEye Server |
| 状态显示 `disconnected` / `failed` | 先恢复 HawkEye Server 或桥，再执行 `/mcp reconnect hawkeye`；若使用 OAuth，则执行 `/mcp login hawkeye` |
| 提示 19016 被占用 | 停止重复 Server，或在 Server 和扩展两端使用相同 `HX0_MCP_WS_PORT` |
| Server 已连接但工具称扩展断开 | 检查扩展 MCP 桥状态、当前端口及扩展是否重载 |
| Firefox 普通点击可用但全屏失败 | 使用 `inputMode/clickMode=trusted`，确认系统辅助功能/输入权限与页面聚焦，不用 JS fallback 伪装 user activation |
| Research / Fetch 稳定在 60 秒断开 | 删除过低的显式 `tool_timeout_sec`，使用 0/省略让 DeepSentry 自动适配 |
| 只看到请求行 | 用 `hawkeye_request_get` 显式请求 `request_headers` / `request_body`；GET 的空 body 本身正常 |
| 大页面结果不全 | 检查 `structuredContent.context.complete/next_cursor`，分页继续取证 |
