# RHEL Ops Agent 功能清单

本文是项目的完整功能说明。面向 Red Hat Enterprise Linux（RHEL 8/9）本地运行，支持中文、英文、命令行和 Web。

## 1. 当前规模

| 能力 | 数量 | 说明 |
|---|---:|---|
| 受控运维操作 | 101 | 只允许规则表中的动作 ID 和参数化 argv |
| 只读操作 | 67 | 不修改系统配置 |
| 谨慎变更 | 22 | 需要确认语 |
| 高风险变更 | 12 | 删除、重启、关防火墙、结束进程等，需要明确确认 |
| 漏洞/基线巡检 | 30 | 只读检查常见 RHEL 安全风险 |
| 高危命令审计规则 | 44 | 识别另一个终端及历史日志中的危险命令 |
| 对话与攻击测试用例 | 104 | 覆盖中英文意图、危险请求、审计命中 |
| 本地口语化同义词 | 21 组 | 补充规则正则，提高自然语言召回 |

机器可读规则位于：

- `rules/commands.json`
- `rules/extra_commands.json`
- `rules/extra_commands_more.json`
- `rules/vulnerabilities.json`
- `rules/audit_patterns.json`
- `rules/extra_audit_patterns.json`

## 2. 使用入口

### 一键安装并进入命令行

```bash
cd rhel-ops-agent
sudo bash run.sh
```

首次运行会自动安装到 `/opt/rhel-ops-agent`，安装 auditd 定向规则，启动 systemd 服务，并进入：

```text
rhel-agent>
```

### 命令行单次执行

```bash
sudo rhel-agent "查看磁盘空间"
sudo rhel-agent "show disk usage"
sudo rhel-agent "把系统语言改成中文"
sudo rhel-agent "change system language to Chinese"
```

### 命令行交互

```bash
sudo rhel-agent
```

支持：

```text
/scan    只读漏洞巡检
/audit   采集并查看高危命令
/rules   查看规则规模
/help    帮助
/exit    退出
```

英文交互命令：

```text
scan
audit
rules
help
quit
```

### Web 控制台

```bash
sudo rhel-agent web
```

默认地址：

```text
http://127.0.0.1:8765
```

Web 包含：

- 总览仪表盘
- 对话操作与计划审核
- 漏洞巡检
- 高危日志
- 规则库
- 管理员登录

### Windows 预览

双击：

```text
start-windows.bat
```

Windows 模式只运行演示数据和模拟日志，不会执行真实系统命令，也不需要 root。

## 3. 中英文自然语言

### 自动语言选择

- 输入包含中文字符：返回中文计划、中文错误、中文风险提示和中文确认语。
- 输入不包含中文字符：返回英文计划、英文错误、英文风险提示和英文确认语。
- 中英文可以混用技术词，例如 `把 ens160 改成 192.168.1.50/24`。

### 中文示例

```text
你好
吃了吗
你是谁
你能做什么
帮我看下磁盘还剩多少
机器有点卡，谁占 CPU 高
有没有安全补丁
现在几点了
哪些端口开着
网络通不通
查看最近谁登录
检查 SSH 安全配置
把系统语言改成中文
```

### 英文示例

```text
hello
what can you do?
show disk usage
how much disk space is left
show failed services
show top memory processes
show recent logins
show firewall zones
show service logs sshd
test DNS resolution for example.com
change system language to Chinese
```

### 口语化同义词

系统内置一层语义别名，在普通正则未命中时启用。例如：

| 用户说法 | 识别结果 |
|---|---|
| 磁盘还剩多少 | `show_disk` |
| 机器有点卡 | `show_processes` |
| 有没有安全补丁 | `show_updates` |
| 现在几点了 | `show_time` |
| 哪些端口开着 | `show_listening_ports` |
| who is online | `show_logged_in_users` |
| how much disk space is left | `show_disk` |
| what is the kernel version | `show_kernel_version` |

## 4. 小型对话与自我介绍

当前支持本地规则回复，不依赖外部模型：

- 问候：`你好`、`hello`、`hi`
- 闲聊：`吃了吗`、`have you eaten`
- 身份介绍：`你是谁`、`who are you`
- 能力介绍：`你能做什么`、`what can you do?`
- 感谢：`谢谢`、`thanks`

小聊只返回解释和推荐操作，不会生成或执行命令。

## 5. LLM 语义理解升级

LLM 是可选层，默认关闭。推荐使用支持 Function Calling 和结构化输出的 Qwen2.5-Instruct。

### 支持模式

- `off`：不启用 LLM。
- `hybrid`：优先本地规则；未命中或缺少参数时调用 LLM。
- `always`：本地安全拦截通过后，优先使用 LLM 解释；失败时回退规则引擎。

### 硬性安全约束

1. LLM 优先通过原生 `tools/tool_calls` 返回 `submit_operations`。
2. 支持严格 JSON 内容作为兼容路径，但不从自由文本中正则抠 JSON。
3. 工具参数必须通过 `json_schema` 约束。
4. 只能选择规则表中的动作 ID，未知动作直接拒绝。
5. 只能返回规则中声明的参数，未知参数直接拒绝。
6. LLM 不能返回 Shell、二进制路径或自定义命令。
7. LLM 不参与最终执行；执行器仍使用白名单 argv。
8. 危险操作仍需确认语。
9. `rm -rf /` 等硬拦截在调用 LLM 之前完成，LLM 不会收到这类请求。
10. API 密钥不返回给 Web、不写入计划 JSON。

### OpenAI 兼容接口配置

```bash
export RHEL_OPS_LLM_ENABLED=1
export RHEL_OPS_LLM_MODE=hybrid
export RHEL_OPS_LLM_PROVIDER=openai-compatible
export RHEL_OPS_LLM_BASE_URL=https://your-provider.example/v1
export RHEL_OPS_LLM_MODEL=qwen2.5-7b-instruct
export RHEL_OPS_LLM_API_KEY=your-key
```

### 本机 Ollama 配置

```bash
ollama pull qwen2.5:7b-instruct
ollama serve

export RHEL_OPS_LLM_ENABLED=1
export RHEL_OPS_LLM_MODE=hybrid
export RHEL_OPS_LLM_PROVIDER=ollama
export RHEL_OPS_LLM_BASE_URL=http://127.0.0.1:11434
export RHEL_OPS_LLM_MODEL=qwen2.5:7b-instruct
```

远程模型必须使用 HTTPS；明文 HTTP 只允许本机回环地址。

## 6. 受控操作清单

### 系统

- 查看系统概况 `system_overview`
- 查看内存使用 `show_memory`
- 查看系统语言 `show_locale`
- 查看/设置主机名 `show_hostname` / `set_hostname`
- 切换系统语言为中文/英文 `set_locale_zh` / `set_locale_en`
- 查看内核版本 `show_kernel_version`
- 查看 CPU 信息 `show_cpu_info`
- 查看 tuned 配置 `show_tuned_profile`
- 查看运行时长 `show_uptime_detail`

### 存储

- 查看磁盘空间 `show_disk`
- 查看块设备 `show_block_devices`
- 查看 inode `show_disk_inodes`
- 查看挂载参数 `show_mount_options`
- 查看挂载信息 `show_mounts`
- 创建目录 `create_directory`
- 查看文件或目录 `inspect_path`
- 删除文件或目录 `delete_path`

### 网络

- 查看网络配置 `show_network`
- 查看 IPv4/IPv6 `show_ipv4_addresses` / `show_ipv6_addresses`
- 查看网卡详情 `show_network_devices`
- 查看监听端口 `show_listening_ports`
- 查看活动连接 `show_active_connections`
- 查看 UDP 监听 `show_listening_udp`
- 查看套接字统计 `show_socket_summary`
- 查看路由表 `show_routes`
- 查看默认网关 `show_default_gateway`
- 查看 IP 策略路由 `show_ip_rules`
- 查看/修改 DNS `show_dns_config` / `show_dns_domains` / `set_dns`
- 测试 DNS 解析 `test_dns_resolution`
- 测试网络连通性 `test_network_connectivity`
- 设置静态 IPv4 `set_static_ipv4`
- 切换 DHCP `set_dhcp`

### 服务

- 查看异常服务 `show_failed_services`
- 查看服务状态 `show_service_status`
- 查看运行/开机自启服务 `show_running_services` / `show_enabled_services`
- 查看服务日志 `show_service_journal`
- 启动服务 `start_service`
- 停止服务 `stop_service`
- 重启服务 `restart_service`
- 启用并启动服务 `enable_service`
- 停止并禁用服务 `disable_service`

### 防火墙

- 查看规则 `show_firewall`
- 查看服务 `show_firewall_services`
- 查看开放端口 `show_firewall_ports`
- 查看活动区域 `show_firewall_zones`
- 开放/关闭端口 `open_firewall_port` / `close_firewall_port`
- 启用 firewalld `enable_firewalld`
- 重载规则 `reload_firewalld`

### 时间

- 查看时间和时区 `show_time`
- 查看当前时区 `show_timezone_detail`
- 查看 NTP/chrony 源 `show_chrony_sources`
- 设置时间 `set_datetime`
- 设置时区 `set_timezone`
- 启用/关闭时间同步 `enable_ntp` / `disable_ntp`

### 账户

- 查看系统用户 `show_users`
- 查看在线用户 `show_logged_in_users`
- 查看最近登录/失败登录 `show_recent_logins` / `show_failed_logins`
- 查看账户密码状态 `show_password_status`
- 创建用户 `create_user`
- 创建用户组 `create_group`
- 添加用户到组 `add_user_to_group`
- 查看组成员 `show_group_members`
- 锁定/解锁账户 `lock_user` / `unlock_user`
- 强制下次改密 `expire_user_password`

### 进程

- 查看高占用进程 `show_processes`
- 查看高内存进程 `show_top_memory_processes`
- 查看指定用户进程 `show_user_processes`
- 结束指定进程 `kill_process`

### 软件与补丁

- 查看安全更新 `show_updates`
- 安装安全更新 `update_security`
- 安装/卸载软件包 `install_package` / `remove_package`
- 查看软件包信息 `show_package_info`
- 查看已安装内核 `show_kernel_packages`
- 查看 DNF 历史 `show_dnf_history`
- 查看仓库 `show_repositories`
- 查看 RPM GPG 密钥 `show_rpm_gpg_keys`
- 查看 RHEL 订阅状态 `show_subscription_status`

### 安全、日志与计划任务

- 查看 SELinux 状态/模式/布尔值 `show_selinux` / `show_selinux_mode` / `show_selinux_booleans`
- 启用 SELinux 强制模式 `set_selinux_enforcing`
- 查看 SSH 安全配置 `show_ssh_config`
- 查看错误日志 `show_logs`
- 查看本次启动错误 `show_boot_errors`
- 查看审计子系统状态 `show_audit_status`
- 查看 cron 和 systemd timers `show_cron` / `show_systemd_timers`

### 电源

- 重启系统 `reboot`
- 关闭系统 `poweroff`

## 7. 漏洞与基线巡检

当前共 30 项只读检查，覆盖：

- SELinux 是否 Enforcing
- firewalld、chronyd、auditd、rsyslog 状态
- SSH root 登录、空密码、密码认证、MaxAuthTries、弱加密算法
- 防火墙默认区域与 trusted zone
- 待安装安全更新、GPG 校验、自动安全更新
- 用户密码有效期、重复 UID 0、空密码账户
- sudo NOPASSWD
- 敏感系统文件全局可写
- `/tmp` 隔离参数
- LEGACY 加密策略
- ASLR、IPv4 转发、SUID core dump
- NFS 导出范围
- Telnet/FTP 服务
- USBGuard、AIDE
- journald 持久化

巡检只读取配置和命令输出，不自动修复。

## 8. 高危命令审计

当前 44 条规则，覆盖：

- 根目录递归删除、强制删除
- 文件系统格式化、块设备覆写、wipefs
- 重启、关机
- 关闭 SELinux、清空防火墙、firewall panic、停止 firewalld/sshd
- 网络断开、清空 IP
- 危险 chmod/chown
- 清空 cron、停止 auditd、删除审计规则
- 删除用户、修改 sudoers、清空历史、删除日志
- 远程脚本管道执行、反弹 Shell、Netcat Shell
- 注入 authorized_keys
- Fork Bomb、网络扫描、口令爆破
- 特权容器、批量杀进程、卸载核心包/内核模块
- 弱化内核保护
- 禁用 GPG 校验、停止 NetworkManager
- 挖矿进程、删除 root 密码、创建 UID 0 账户

采集来源：

- auditd 定向 execve 规则
- root/用户 shell history
- `/var/log/secure` 中的 sudo 命令
- Web 中手动写入的模拟攻击事件

审计是“监测和告警”，不会阻断另一个终端里已经直接执行的命令。

## 9. 安全执行模型

```text
自然语言
  -> 本地硬拦截
  -> 本地规则 / 可选 LLM 意图理解
  -> 已知动作 ID
  -> 参数正则与语义校验
  -> 风险分级
  -> 命令预览
  -> 用户确认语
  -> 一次性提案
  -> 白名单 argv 执行
  -> 后置检查
  -> 审计记录
```

关键保护：

- `shell=False`
- 固定 PATH
- 固定工作目录
- 命令超时
- 输出长度限制
- 参数禁止控制字符
- 参数禁止以 `-` 开头
- 删除路径必须是绝对路径
- 关键系统目录禁止删除
- 一次性提案和过期时间
- 高风险确认语服务端复核
- API 会话签名和登录限速

## 10. Web 与 API

主要 API：

| 方法 | 路径 | 功能 |
|---|---|---|
| `GET` | `/api/overview` | 总览 |
| `GET` | `/api/rules` | 规则和 LLM 状态 |
| `GET` | `/api/llm/status` | LLM 状态 |
| `POST` | `/api/plan` | 生成计划 |
| `POST` | `/api/execute` | 确认执行 |
| `POST` | `/api/scan` | 启动漏洞巡检 |
| `GET` | `/api/findings` | 查看巡检结果 |
| `GET` | `/api/audit` | 查看高危事件 |
| `POST` | `/api/lab/simulate` | 写入模拟攻击事件 |

## 11. Windows 支持范围

Windows 可用于：

- 浏览器查看完整 Web 界面
- 演示数据
- 中英文规则演练
- 攻击矩阵
- 模拟审计事件

Windows 不执行真实 Linux 系统命令。

## 12. 当前边界

- 不是通用 Linux 发行版管理平台，主要面向 RHEL 8/9。
- 不是实时 CVE 扫描器；安全更新依赖 RHEL 仓库元数据。
- 不会自动修复漏洞。
- auditd/history 监测存在采集间隔。
- LLM 不随项目打包，需要外部 OpenAI 兼容服务或本机 Ollama。
- LLM 输出必须通过本地规则校验；校验失败时回退规则引擎。
- 真实 RHEL 环境仍需按 README 的虚拟机步骤完成最终验收。
