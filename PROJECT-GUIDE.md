# RHEL Ops Agent 代码阅读指南

> 目标：让主人按顺序把这个项目读明白，而不是一上来扎进 1500 行的 `engine.py`。
> 读法建议：先看第 0、1、2 节建立地图，再按第 3 节选一条路线，最后用第 16 节自测。
>
> **2026-10-24 更新**：本指南写完后代码有一次安全加固——默认模式改为 `llm_first`（模型先规划、规则校验兜底），新增否定句拦截、规则加载自检、删除确认语带路径、LLM 熔断。细节见 `SECURITY.md`。

---

## 0. 30 分钟速览

### 0.1 一句话架构

```
用户输入（中文/英文）
   ↓
规则引擎 / LLM 规划器  →  生成「计划」（动作 + 参数 + 风险 + 确认语）
   ↓
提案入库（proposal，带过期时间）
   ↓
用户确认（输入确认语）
   ↓
执行器：白名单校验 → subprocess(shell=False) 逐条执行
   ↓
结果入库 + 审计事件
```

核心原则：**规划器和模型只“建议”，执行器只执行“白名单里的 argv”，任何变更都要二次确认。**

### 0.2 三条主线

| 主线 | 入口 | 关键文件 |
|---|---|---|
| 命令行 | `app.py` → `agent/cli.py` | cli.py、engine.py、executor.py |
| Web | `app.py web` → `agent/server.py` | server.py、web/app.js |
| 巡检/审计 | CLI `scan`/`audit`、Web 页面 | scanner.py、audit.py |

### 0.3 术语表

| 术语 | 含义 |
|---|---|
| action（动作） | 规则表里的一条受控操作，如 `show_disk`、`restart_service` |
| step（步骤） | 一次计划里的一个动作实例（含参数、风险、命令） |
| plan（计划） | 一次输入解析出来的结果，状态有 ready/needs_input/blocked/chat/unsupported 等 |
| proposal（提案） | 计划落库后的记录，带 `expires_at`，执行前必须仍有效 |
| confirmation（确认语） | 变更类操作执行前要输入的短语 |
| scan（巡检） | 只读漏洞/基线检查，30 条规则 |
| audit（审计） | 从日志里发现“另一个终端”执行的高危命令 |

---

## 1. 这个项目在做什么

- 面向 RHEL 8/9，把「查看磁盘」「重启服务」「改语言」这类运维意图，翻译成**受控命令**；
- 只允许规则表里定义的动作和参数化 argv，**不允许模型自由生成 shell 命令**；
- 支持中文/英文、CLI/Web、只读巡检、危险命令审计；
- Windows 下有 demo 模式：命令只模拟、不执行，方便演示。

代码规模：约 7000 行 Python + 规则 JSON + 原生 JS 前端 + 安装脚本。

---

## 2. 目录地图（按重要性排序）

| 文件 | 规模 | 一句话职责 | 优先级 |
|---|---|---|---|
| `agent/engine.py` | 1535 行 | 规则加载、意图匹配、参数校验、计划生成 | ★★★★★ |
| `agent/executor.py` | 403 行 | 命令白名单校验与真实执行 | ★★★★★ |
| `agent/llm.py` | 575 行 | LLM 接入、输出校验、混合规划 | ★★★★☆ |
| `agent/cli.py` | 589 行 | 命令行入口与各子命令 | ★★★★☆ |
| `agent/server.py` | 535 行 | Web HTTP 服务与 API | ★★★★☆ |
| `agent/scanner.py` | 644 行 | 30 条只读漏洞巡检 | ★★★☆☆ |
| `agent/audit.py` | 364 行 | 高危命令审计采集 | ★★★☆☆ |
| `agent/db.py` | 466 行 | SQLite 存储层 | ★★★☆☆ |
| `agent/auth.py` | 164 行 | 管理员密码、会话、登录限流 | ★★★☆☆ |
| `agent/config.py` | 159 行 | 环境变量与路径配置 | ★★★☆☆ |
| `rules/*.json` | 约 130KB | 动作、漏洞、审计规则数据 | ★★★★☆ |
| `web/*` | 约 90KB | 原生 JS 单页控制台 | ★★☆☆☆ |
| `tests/*` | 约 40KB | 单元测试与攻击矩阵 | ★★★★☆ |
| `scripts/*` | — | 安装、LLM 配置、演示、冒烟测试 | ★★☆☆☆ |
| `deploy/*` | — | systemd 服务文件 | ★☆☆☆☆ |

排除项：`.ui-test-profile/`（浏览器测试缓存）、`__pycache__/`、`.idea/`、`dist/`（打包产物）、`docs/screenshots/`。

---

## 3. 推荐阅读路线

### 路线 A：先跑起来（半天）
`run.sh` → `agent/cli.py: main` → `agent/cli.py: CliRuntime` → `agent/server.py: run_server`

### 路线 B：主链路（两天，最重要）
`engine.py: RuleEngine.plan` → `executor.py: Executor.execute` → `engine.py: plan_payload / rebuild_from_payload`

### 路线 C：安全线（一天）
`rules/commands.json` → `engine.py: _validate_param / _validate_semantics` → `executor.py: _validate_argv / run_argv` → `audit.py`

### 路线 D：LLM 线（一天）
`llm.py: LLMConfig` → `LLMClient._messages / _payload` → `_validate_interpretation` → `HybridPlanner.plan`

---

## 4. 入口层

### 4.1 `app.py`

```python
from agent.cli import main
raise SystemExit(main())
```

只有 6 行，一切从 `cli.main()` 开始。

### 4.2 `rhel-agent` / `run.sh` / `start-windows.bat`

- `rhel-agent`：安装到 `/usr/local/bin` 的启动壳，转调 `app.py`；
- `run.sh`：要求 root；没安装就先 `install.sh`，然后 `exec rhel-agent "$@"`；
- `start-windows.bat`：Windows 演示入口，设置 `RHEL_OPS_DEMO=1`，不执行真实命令。

### 4.3 `agent/config.py`

`Settings` 数据类，全部来自环境变量：

| 变量 | 作用 |
|---|---|
| `RHEL_OPS_HOST` / `PORT` | Web 监听，默认 127.0.0.1:8765 |
| `RHEL_OPS_DEMO` | 演示模式：命令只模拟 |
| `RHEL_OPS_NO_AUTH` | 关闭登录（仅限本机调试） |
| `RHEL_OPS_PROPOSAL_TTL` | 提案有效期，默认 900 秒 |
| `RHEL_OPS_LLM_*` | 模型开关、模式、地址、Key、阈值 |

路径规则：安装到 `/opt/rhel-ops-agent` 时数据放 `/var/lib/rhel-ops-agent`，否则放项目下 `data/`。

> 阅读提示：先看 `from_env()`，它决定了后面所有模块拿到的配置。

---

## 5. 数据层

### 5.1 `agent/db.py`

SQLite（WAL 模式），五张核心表：

| 表 | 用途 |
|---|---|
| `proposals` | 计划快照 + 过期时间 + 状态（pending/executing/completed/failed/expired） |
| `executions` | 每次执行的汇总与完整输出 |
| `scan_runs` / `findings` | 巡检批次与发现项（外键级联删除） |
| `audit_events` | 审计事件，`event_key` 唯一，防重复入库 |
| `app_state` | 键值状态（如审计文件偏移量） |

关键方法：

- `connect()`：上下文管理器，自动 commit/rollback；
- `create_proposal(payload, ttl)`：写入计划并算过期时间；
- `get_proposal / mark_proposal`：执行前检查状态与过期；
- `record_execution()`：执行结果落库；
- `insert_audit_event()`：靠 `event_key` 去重；
- `seed_demo()`：Windows/demo 模式灌演示数据。

### 5.2 `data/`

- `agent.db`：运行数据库（仓库里带了一份演示库）；
- `audit-state.json`：审计采集器的文件读取偏移，避免重复扫描。

---

## 6. 安全基础层

### 6.1 `agent/auth.py`

- 密码：PBKDF2-HMAC-SHA256 + 随机盐，存 JSON，文件 0600；
- 会话：`secret` 文件（32 字节）+ HMAC 签名 token，放 HttpOnly Cookie；
- `LoginRateLimiter`：5 次失败 / 300 秒窗口；
- 首次启动自动生成密码，写到 `initial_password_path`。

> 阅读提示：`issue_session / verify_session` 是 Web 登录的核心，和 `server.py` 的 `_require_auth` 对接。

### 6.2 `agent/executor.py`

**这是整个项目最该看懂的安全闸门。**

`Executor.__init__`：
- `allowed_binaries`：允许执行的二进制白名单（`df`、`systemctl`、`firewall-cmd`、`rm`……）；
- `environment`：固定 PATH/LANG/HOME，避免继承用户环境。

`_validate_argv(argv)`：
- 二进制必须在白名单；
- 参数不能含 `\x00`、换行；
- `rm` 必须严格是 `["-rf", "--", 绝对路径]`；
- `kill` 必须正好 3 个参数。

`run_argv()`：
- demo 模式直接返回模拟结果；
- `subprocess.run(shell=False, cwd="/", timeout=60)`；
- 输出截断 16K；
- 错误码映射：127 命令不存在、124 超时、126 启动失败；
- 支持 `accepted_exit_codes`（有些命令非 0 也算正常）。

`execute(proposal_id, selected_action_ids, confirmation)`：
1. 加锁（`threading.Lock`），防止并发执行；
2. 取 proposal，检查 `status == pending`、未过期；
3. `engine.rebuild_from_payload()` **重新校验**（不信任库里的旧命令）；
4. `select_steps()` 选出要执行的动作；
5. 校验确认语（`resolution_phrase`）；
6. 高风险步骤先写审计事件；
7. 逐条执行；某条失败就中断后续；
8. 执行 `post_check`（可选，非 0 退出也接受）；
9. 记录 `executions`，更新 proposal 状态。

> 阅读提示：先读 `_validate_argv`，再读 `execute`，最后回头看 `run_argv` 的错误分支。

---

## 7. 规则与规划核心

### 7.1 `rules/*.json`

**动作规则**（3 个文件合并）：

- `commands.json`：44 个动作 + 7 条 `blocked_patterns`；
- `extra_commands.json`：31 个；
- `extra_commands_more.json`：26 个。

单个动作的字段：

```json
{
  "id": "system_overview",
  "title_zh": "查看系统概况",
  "category": "system",
  "risk": "safe",                      // safe / caution / destructive
  "patterns": ["(查看|看看).*(系统|主机).*(概况|状态)"],
  "commands": [["hostnamectl"], ["uptime"], ["free", "-h"]],
  "params": {                          // 可选
    "service": {
      "label_zh": "服务名",
      "required": true,
      "pattern": "^[A-Za-z0-9_.@-]+$",
      "extractor": "service"
    }
  },
  "group": "network",                  // 同组动作只取一个
  "priority": 5,
  "requires_restart": false,
  "network_disconnect": true,
  "post_check": [["systemctl", "is-active", "{{service}}"]],
  "accepted_exit_codes": [0, 3],
  "confirmation_phrase": "确认重启服务"
}
```

命令里的 `{{param}}` 由 `_hydrate_argv` 替换；没替换干净会抛 `RuleError`。

**其他规则**：

- `vulnerabilities.json`：30 条巡检规则（`id` 对应 `scanner.py` 里的 checker 方法名）；
- `audit_patterns.json` + `extra_audit_patterns.json`：44 条高危命令正则。

> 阅读提示：先挑 `show_disk`、`restart_service`、`delete_path` 三个动作看，能覆盖只读/变更/危险三类。

### 7.2 `agent/engine.py`（核心，1535 行）

按函数分块读：

#### ① 常量与文案（文件开头）
- `RISK_ORDER = {"safe":0, "caution":1, "destructive":2}`
- `PLAN_MESSAGES`：中英文提示语（ready/needs_input/blocked…）
- `SEMANTIC_ALIASES`：口语同义词（“机器有点卡”→“show_processes”）
- `SMALL_TALK_REPLIES`：寒暄/自我介绍

#### ② `RuleEngine.reload()`
- 合并三个 commands 文件；
- 检查重复 id、非法 risk；
- 预编译所有正则，存到 `_compiled_actions` / `_compiled_blocked`。

#### ③ `_search()`
- 先跑 `blocked_patterns`，命中直接返回 blocked；
- 再逐动作 `pattern.search`，得分 = 匹配长度 + `priority * 100`；
- 都没命中时走 `_alias_search()` 语义别名。

#### ④ `_extract_entities()`
从自然语言里抽：IPv4、前缀、路径、端口、服务名、用户名、包名、PID、时区、时间、主机名。
这是“参数从哪来”的答案。

#### ⑤ `_validate_param()` / `_validate_semantics()`
- 参数必填、不能以 `-` 开头、必须匹配 `pattern`；
- 语义校验：IPv4 合法性、端口 1–65535、**删除路径黑名单**（`/`、`/etc`、`/usr`、`/var/log` 等）。

#### ⑥ `plan()`（919 行开始，主流程）
状态机：

```
空输入 → empty
blocked 命中 → blocked
无匹配 → 寒暄 chat / unsupported
参数缺失 → needs_input（带 fields，供前端补填）
全部就绪 → ready（steps + 风险 + 确认语 + 重启提示）
```

细节：
- 多动作按分数排序，按 `group` 去重；
- 每个动作生成 step：参数、风险、摘要、影响、命令、`matched_text`；
- `_hydrate_step()` 追加 SSH 断连、重启中断等警告；
- 按最高风险决定确认语。

#### ⑦ `build_commands()` / `_hydrate_argv()`
把规则里的 argv 模板 + 参数拼成最终命令，占位符没解析完直接报错。

#### ⑧ `plan_payload()` / `rebuild_from_payload()` / `select_steps()`
- `plan_payload` 只存 `action_id + params`，不存命令；
- 执行时 `rebuild_from_payload` 重新跑一遍规划与校验；
- `select_steps` 按用户勾选的 id 过滤。

> 阅读提示：`engine.py` 里还有一个 `_plan_legacy()`（1179 行起），是旧实现，当前主流程不走它，读的时候可以跳过，但要知道它存在。

---

## 8. LLM 层

### 8.1 `agent/llm.py`

#### 配置
`LLMConfig.from_settings()`：enabled / mode(hybrid|always|off) / provider(ollama|qwen|openai-compatible) / base_url / model / timeout / confidence。

#### 传输
- `_validate_base_url()`：只允许 https，或本机 http（SSRF 防护）；
- `_http_json()`：`urllib` POST，超时、HTTP 错误、非 JSON 都有明确异常；
- `LLMClient._endpoint()`：Ollama 用 `/api/chat`，其他用 `/chat/completions`。

#### 提示词
- `_candidate_actions()`：先按中文/英文 token 粗筛 24 个候选动作，缩小提示词；
- `_tool_schema()`：把动作目录转成 JSON Schema；
- `_messages()`：system 提示 + 候选动作 + 本地规则计划；
- `_payload()`：组装请求体（Ollama 与 OpenAI 格式不同）。

#### 输出解析与校验（重点）
`_extract_json()`：兼容 `tool_calls` 和 content 里的 JSON。
`_validate_interpretation()`：
- confidence 必须是 0–1 且高于阈值；
- `operations` 数量 ≤ `max_actions`；
- `action_id` 必须在动作目录里；
- 参数名必须在动作定义里，值必须是标量；
- 每个参数走 `engine._validate_param()`。

**模型只能“选动作 + 填参数”，不能生成命令。**

#### `HybridPlanner.plan()`
```python
local_plan = engine.plan(message)          # 规则先跑，作为上下文与兜底
if not active: return local_plan
if status in {blocked, chat, empty}: return local_plan
if mode in {"always", "llm_first"} or status in {unsupported, needs_input}:
    interpretation = llm.interpret(...)    # 模型先规划
    merged = 模型参数 + 用户覆盖
    llm_plan = engine.plan(message, overrides=merged, forced_action_ids=...)
```
默认 `llm_first`：模型先出计划，规则引擎重新校验；`hybrid` 仍是规则优先。失败时 `llm.status = fallback`，返回规则结果——API 挂了不影响主流程；连续 3 次失败会熔断 60 秒。

> 阅读提示：先读 `_validate_interpretation`，这是“LLM 不能乱来”的关键；再读 `HybridPlanner.plan` 搞清调用时机。

---

## 9. 只读能力

### 9.1 `agent/scanner.py`

- `VulnerabilityScanner.__init__`：加载 `vulnerabilities.json`，建立 `id → checker 方法` 的映射；
- 每个 checker 返回 `CheckResult(status, detail, evidence)`，状态 `ok / vulnerable / skipped`；
- `scan()`：`ThreadPoolExecutor(max_workers=4)` 并发跑所有 checker；
- 计分：`100 - Σ(严重度权重 × 数量)`，夹在 0–100；
- demo 模式返回固定 fixtures（root 登录、防火墙关闭、补丁未打等）；
- `ScanManager`：后台线程跑一次巡检，写入 `scan_runs / findings`。

> 阅读提示：先看 `_check_one` 和 `scan`，再挑 `_sshd_root_login`、`_firewalld_inactive` 两个 checker 看写法。

### 9.2 `agent/audit.py`

- `AuditAnalyzer`：加载审计正则，`classify(command)` 按“严重度 + 匹配长度”选最优命中；
- `AuditCollector`：
  - 定时轮询（默认 20 秒）；
  - 读 `/var/log/secure`、auditd 日志、用户 history；
  - 用 `event_key`（用户+命令+时间桶）去重；
  - `inject_simulation()` 只写模拟事件，不执行命令（Web 演示用）。

> 阅读提示：`_read_new_bytes` 的增量读取 + `_file_state` 偏移，是“不重复审计”的关键。

---

## 10. 服务与界面

### 10.1 `agent/server.py`

`ThreadingHTTPServer` + 自定义 `BaseHTTPRequestHandler`。

API 一览：

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/health` | 健康检查 |
| GET | `/api/auth/status` | 登录状态 |
| GET | `/api/overview` | 仪表盘聚合数据 |
| GET | `/api/rules` | 规则库 |
| GET | `/api/llm/status` | 模型状态 |
| GET | `/api/findings` / `/api/scan/latest` / `/api/scans/<id>` | 巡检结果 |
| GET | `/api/audit` | 审计事件 |
| POST | `/api/auth/login` / `logout` | 登录/登出 |
| POST | `/api/plan` | 生成计划（可能建 proposal） |
| POST | `/api/execute` | 执行计划 |
| POST | `/api/scan` | 触发巡检 |
| POST | `/api/audit/refresh` / `/api/audit/<id>/ack` | 刷新/确认审计 |
| POST | `/api/lab/simulate` | 仅本机：注入模拟审计事件 |

安全细节：`_check_origin()` 校验来源；Cookie `HttpOnly; SameSite=Strict`；`_require_auth()` 保护除健康检查和登录外的接口。

### 10.2 `web/`

- `index.html`：单页骨架 + 模板；
- `app.js`：无框架 SPA，`state` 保存数据，`api()` 封装 fetch，`setView()` 切页；
- 视图：总览、对话（计划卡片 + 勾选 + 确认）、漏洞、审计、规则、登录；
- `loadOverview/loadFindings/loadAudit/loadRules` 对应后端接口。

> 阅读提示：前端不用逐行读，抓住 `api()`、`setView()`、计划卡片的渲染即可。

---

## 11. 测试与攻击矩阵

- `tests/test_engine.py`：22 个用例，覆盖中文/英文、同义词、缺参、危险路径、确认语本地化；
- `tests/test_executor.py`：白名单、rm 参数、失败码、demo 模式；
- `tests/test_llm.py`：输出校验、置信度、未知动作、参数注入；
- `tests/test_scanner.py` / `test_audit.py` / `test_auth.py`：各自模块；
- `agent/attack_tests.py`：`PLANNER_CASES` 攻击/越权用例矩阵，`run_attack_matrix()` 批量跑；
- `scripts/api_smoke_test.py` / `ui_smoke_test.js`：接口与界面冒烟。

> 阅读提示：**测试是最好的规格文档。** 先读 `test_engine.py` 的用例名，能快速知道系统承诺了什么。

---

## 12. 安装与部署

- `scripts/install.sh`：复制到 `/opt/rhel-ops-agent`、建用户/权限、装 systemd；
- `scripts/setup-qwen-api.sh` / `scripts/setup-ollama.sh`：写入 `/etc/rhel-ops-agent/agent.env`；
- `scripts/install-audit-rules.sh`：装 auditd 定向规则；
- `scripts/demo.sh` / `live-audit-test.sh`：演示与实测脚本；
- `deploy/rhel-ops-agent.service`：root 运行，`UMask=0077`，`PrivateTmp=true`。

---

## 13. 三条端到端调用链

### 链 1：CLI 只读「查看磁盘空间」

```
rhel-agent "查看磁盘空间"
→ cli.main → CliRuntime（Database/RuleEngine/Executor/HybridPlanner）
→ planner.plan → engine.plan
   → _search 命中 show_disk（risk=safe）
   → 无参数缺失 → status=ready
→ _print_plan 打印命令预览
→ execute_plan → plan_payload → create_proposal
→ executor.execute → rebuild → 确认语为空 → run_argv("df","-hT")
→ 结果打印 + record_execution
```

### 链 2：Web 变更「把系统语言改成中文」

```
POST /api/plan
→ HybridPlanner.plan → engine.plan（命中 set_language，risk=caution）
→ plan_payload + create_proposal(pending, 900s)
→ 前端显示计划卡片 + 确认语
POST /api/execute {proposal_id, selected, confirmation}
→ executor.execute
   → 检查 pending / 未过期
   → rebuild_from_payload 重新校验
   → 确认语比对
   → 写审计事件（高风险）
   → localectl set-locale ...
   → post_check（可选）
→ 更新 proposal=completed，写 executions
```

### 链 3：巡检 / 审计

```
CLI: scan_command → ScanManager.start → 后台线程 scan()
→ 30 个 checker 并发 → findings + 评分 → 入库
Web: POST /api/scan → 202 → 前端轮询 /api/scans/<id>

audit: AuditCollector 轮询日志 → 增量读 → AuditAnalyzer.classify
→ insert_audit_event（event_key 去重）→ Web /api/audit 展示
```

---

## 14. 设计亮点（值得借鉴）

1. **计划-确认-执行三段式**：模型/规则只产出计划，执行器只认提案 + 确认语；
2. **命令模板化**：命令写在规则里，参数只做占位符替换，模型无法注入新命令；
3. **执行前重建**：不信任数据库里的旧命令，执行时重新规划校验；
4. **LLM 白名单约束**：只能选 action_id + 填参数，且参数走同一套校验；
5. **审计去重**：`event_key` + 文件偏移，避免重复告警；
6. **demo 模式**：Windows 下可完整演示，不碰真实系统。

---

## 15. 已知短板（配合 `AGENT-ROADMAP.md` 看）

已修复（2026-10-24）：

- ~~规则优先、LLM 兜底~~ → 默认 `llm_first`，模型先规划、规则校验兜底；
- ~~否定句未处理~~ → `_detect_negation`，中英文否定语义直接 blocked；
- ~~确认语是固定短语~~ → 删除类操作要求复述目标路径；
- ~~坏规则无自检~~ → `_validate_actions` 启动时拒绝不安全模板。

仍然存在：

- **`engine.py` 过大**：规则/校验/文案/计划混在一起，建议拆分；
- **`_plan_legacy` 是旧实现**：留在文件里容易误读；
- **缺少评测指标**：没有成功率/拦截率/延迟的量化数据；
- **Web 层是 root 攻击面**：默认只绑 127.0.0.1，远程访问请用 SSH 隧道。

---

## 16. 自测题（能答出来就算读懂）

1. 一次请求从 `app.py` 到命令执行，经过哪些函数？
2. `blocked_patterns` 和普通 action 的匹配顺序是什么？
3. 参数为什么不允许以 `-` 开头？
4. `rm` 在 `_validate_argv` 里被限制成什么形式？
5. 执行前为什么要 `rebuild_from_payload`，而不是直接用库里的命令？
6. 确认语为空代表什么？
7. LLM 返回一个不存在的 `action_id` 会怎样？
8. `HybridPlanner` 在什么情况下才会调用模型？
9. 巡检评分公式是什么？skipped 的规则怎么处理？
10. 审计事件如何避免重复入库？
11. Web 登录态存在哪里，怎么校验？
12. `proposal` 过期后执行会发生什么？

---

## 17. 一周阅读计划

| 天 | 读什么 | 产出 |
|---|---|---|
| 1 | 第 0–4 节 + `config.py` / 入口 | 画出启动链路 |
| 2 | `db.py` + `auth.py` | 画出表关系和登录流程 |
| 3 | `engine.py` 前半（reload/_search/_extract） | 写 3 条规则的匹配路径 |
| 4 | `engine.py` 后半（plan/hydrate/payload） | 画出 plan 状态机 |
| 5 | `executor.py` + `rules/*.json` | 列出危险动作清单 |
| 6 | `llm.py` | 画出 hybrid 决策图 |
| 7 | `server.py` + 前端 + 测试 | 跑一遍 demo，改一个规则验证 |

---

> 读完这份，主人应该能回答：“这个项目为什么敢让 LLM 参与运维？”
> 答案在 `engine._validate_param`、`llm._validate_interpretation`、`executor._validate_argv` 这三道闸门里。
