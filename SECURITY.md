# 安全说明（Security）

本文记录 RHEL Ops Agent 的安全设计、本次加固内容、仍然存在的风险，以及规则作者必须遵守的约束。

---

## 1. 设计原则

1. **模型没有执行权**：LLM 只能从动作表里选 `action_id` 并填参数，不能生成 shell 命令；
2. **最小动作面**：只允许 `rules/*.json` 里定义的动作和参数化 argv；
3. **计划与执行分离**：先生成计划、落库为 proposal，确认后才执行，执行前重新校验；
4. **默认不暴露**：Web 只监听 `127.0.0.1`，远程访问走 SSH 隧道；
5. **全程留痕**：blocked、高风险执行、审计事件都入库。

---

## 2. 五层防线

| 层 | 位置 | 作用 |
|---|---|---|
| 规则加载自检 | `engine._validate_actions` | 坏规则拒绝启动：空命令、未定义占位符、shell 元字符、不安全的 `rm` 模板、非法参数正则 |
| 紧急事件升级 | `engine._detect_emergency` / `escalate_plan` | 删库/数据丢失 → `escalate`，不生成计划，返回应急清单 |
| 否定语义拦截 | `engine._detect_negation` | 「别删 / 不要重启 / don't delete」直接 blocked，不生成计划 |
| 参数与语义校验 | `engine._validate_param` / `_validate_semantics` | 必填、格式、禁止 `-` 开头、IPv4/端口、删除路径黑名单 |
| 命令模板 | `engine.build_commands` | 命令来自规则，参数只做 `{{name}}` 替换；替换不干净直接报错 |
| 执行闸门 | `executor._validate_argv` / `run_argv` | 二进制白名单、`shell=False`、固定环境、超时、输出截断 |
| 人工确认 | `engine.resolution_phrase` | 变更类操作必须输入确认语；删除类操作必须复述目标路径 |
| Web 防护 | `server._send_headers` / `_check_origin` / `auth` | CSP、nosniff、frame DENY、SameSite=Strict、Origin 校验、PBKDF2、登录限流 |

---

## 3. 本次加固（2026-10-24）

1. **LLM 主规划**：新增 `llm_first` 模式（默认）。模型先规划，规则引擎用 `forced_action_ids + overrides` 重新校验、重建命令；模型失败/超时/置信度不足时回退规则。
2. **否定句保护**：中英文否定语义命中即 `blocked`，并写入审计事件。
3. **规则加载自检**：`RuleEngine.reload()` 在启动时校验所有动作，坏规则直接 `RuleError`，避免“规则写错 = 运行期漏洞”。
4. **删除确认升级**：`delete_path` 的确认语从固定「确认删除文件」改为「确认删除 <目标路径>」，必须复述路径。
5. **LLM 熔断**：连续 3 次调用失败后暂停 60 秒，避免每个请求都等超时。
6. **Web 响应头**：新增 `Cross-Origin-Opener-Policy` 与 `Permissions-Policy`。
7. **自由回复通道**：非操作类输入由模型生成展示文本，不进入执行器，也不会被解析成命令。
8. **systemd**：新增 `NoNewPrivileges=yes`。
9. **紧急事件升级**：删库/数据丢失关键词直接 `escalate`，不进入 LLM，返回 6 步应急清单；模型侧也新增 `intent`（operate/advice/emergency）分类，非 operate 不允许返回操作。

---

## 4. 仍然存在的风险

- **规则表就是安全边界**：一条规则写错（宽泛的 `pattern`、危险命令模板）就会打穿防线；规则必须 review。
- **服务以 root 运行**：Web 层任何 RCE 都等于 root；不要监听公网，务必用 SSH 隧道。
- **没有命令沙箱**：白名单里有 `rm`、`shutdown`、`passwd` 等“受控的刀”，依赖规则和确认语约束。
- **确认语可被社工**：删除类已要求复述路径，但其他变更仍是固定短语。
- **提示注入**：模型可能被诱导选择“合法但危险”的动作；最后一道是人确认。
- **审计是事后发现**，不是事前阻止。

---

## 5. 规则作者检查清单

新增或修改动作时，逐条确认：

- [ ] `id` 唯一，`risk` 是 `safe/caution/destructive` 之一；
- [ ] `patterns` 足够具体，不会把普通聊天误判成动作；
- [ ] `params` 每个都有 `pattern` 或明确的 `extractor`；
- [ ] 参数不能以 `-` 开头（框架已强制）；
- [ ] `commands` 里没有 `; | & $ > < \`` 和换行；
- [ ] 占位符 `{{name}}` 都能在 `params` 里找到；
- [ ] `rm` 模板必须是 `["rm", "-rf", "--", "<绝对路径或 {{path}}>"]`；
- [ ] 变更类动作有 `confirmation_phrase`；删除类会由框架自动要求复述路径；
- [ ] 需要重启/断网的动作标了 `requires_restart` / `network_disconnect`；
- [ ] 更新 `tests/` 或 `attack_tests.py` 覆盖新动作。

---

## 6. 验证

```bash
# 全部回归
python -m unittest discover -s tests -v

# 只跑安全加固
python -m unittest tests.test_security -v
```

覆盖点：

- 中文/英文否定句拦截；
- 删除确认语包含目标路径；
- 坏规则（shell 元字符、未知占位符、不安全 `rm`）在加载时被拒绝；
- `llm_first` 优先采用模型计划，失败回退规则；
- `hybrid` 保持规则优先。
