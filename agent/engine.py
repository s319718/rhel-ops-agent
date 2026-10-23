from __future__ import annotations

import ipaddress
import json
import os
import posixpath
import re
import shlex
import time
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Optional


RISK_ORDER = {"safe": 0, "caution": 1, "destructive": 2}
RISK_LABELS = {
    "safe": "只读",
    "caution": "谨慎",
    "destructive": "高风险",
}
RISK_LABELS_EN = {
    "safe": "Read-only",
    "caution": "Caution",
    "destructive": "High risk",
}

CONFIRMATION_PHRASES_EN = {
    "set_datetime": "Confirm date and time change",
    "set_timezone": "Confirm timezone change",
    "enable_ntp": "Confirm enabling time synchronization",
    "disable_ntp": "Confirm disabling time synchronization",
    "set_static_ipv4": "Confirm network change",
    "set_dhcp": "Confirm DHCP change",
    "set_dns": "Confirm DNS change",
    "set_hostname": "Confirm hostname change",
    "set_locale_zh": "Confirm locale change",
    "set_locale_en": "Confirm locale change",
    "open_firewall_port": "Confirm opening firewall port",
    "close_firewall_port": "Confirm closing firewall port",
    "restart_service": "Confirm service restart",
    "enable_service": "Confirm starting service",
    "disable_service": "Confirm stopping service",
    "install_package": "Confirm package installation",
    "remove_package": "Confirm package removal",
    "update_security": "Confirm security update installation",
    "create_user": "Confirm user creation",
    "lock_user": "Confirm user lock",
    "create_group": "Confirm group creation",
    "add_user_to_group": "Confirm group membership change",
    "unlock_user": "Confirm user unlock",
    "expire_user_password": "Confirm password expiry change",
    "create_directory": "Confirm directory creation",
    "delete_path": "Confirm deletion",
    "reboot": "Confirm reboot",
    "poweroff": "Confirm poweroff",
    "kill_process": "Confirm process termination",
    "start_service": "Confirm service start",
    "stop_service": "Confirm service stop",
    "enable_firewalld": "Confirm enabling firewall",
    "reload_firewalld": "Confirm firewall reload",
    "set_selinux_enforcing": "Confirm SELinux mode change",
    "install_security_update": "Confirm security update installation",
}

PLAN_MESSAGES = {
    "zh": {
        "empty": "请输入你想完成的操作，例如：查看磁盘空间。",
        "blocked": "已识别并拦截高风险操作，没有执行任何命令。",
        "unsupported": "没有找到受支持的操作。可以换一种说法，例如“查看磁盘空间”或“你好”，也可以在 /help 或规则库中查看可用指令。",
        "needs_input": "还需要补充一些信息，确认后我会生成完整操作计划。",
        "ready": "已生成操作计划。请先核对每一步，再决定是否执行。",
        "confirm_high": "确认执行高风险操作",
        "confirm_selected": "确认执行以上操作",
    },
    "en": {
        "empty": "Enter an operation, for example: show disk usage.",
        "blocked": "A high-risk operation was detected and blocked. No command was executed.",
        "unsupported": "No supported operation was found. Try a request such as \"show disk usage\" or \"hello\", or use /help to see available commands.",
        "needs_input": "More information is required before a complete operation plan can be generated.",
        "ready": "The operation plan is ready. Review every step before execution.",
        "confirm_high": "Confirm high-risk operations",
        "confirm_selected": "Confirm selected operations",
    },
}

SMALL_TALK_REPLIES = {
    "identity": {
        "patterns": [
            r"(你是谁|你叫什么|介绍(一下)?你自己|你是什么|who\s+are\s+you|what\s+are\s+you|ni\s+shi\s+shui|ni\s+jiao\s+shenme)",
        ],
        "zh": (
            "我是 RHEL 护航员，一个运行在 Linux 本机的安全运维 Agent。"
            "我能把中文或英文要求转换成受控命令计划，先解释风险，再等待确认。"
            "我还会巡检常见配置风险并采集高危命令日志。"
        ),
        "en": (
            "I am RHEL Ops Agent, a local security-operations assistant for Linux. "
            "I turn Chinese or English requests into reviewed command plans, explain risk, "
            "and wait for confirmation before making changes. I also scan baseline risks "
            "and collect high-risk command events."
        ),
    },
    "meal": {
        "patterns": [
            r"(吃了吗|吃饭了吗|你吃饭了|吃过饭了吗|吃了没|chi\s+le\s+ma|ni\s+chi\s+le\s+ma|chi\s+fan\s+le\s+ma)",
            r"\b(have you eaten|did you eat|are you hungry)\b",
        ],
        "zh": "我不用吃饭，电源和稳定的网络就是我的“口粮”。你吃了吗？需要我顺便检查一下系统状态吗？",
        "en": "I do not eat, but stable power and networking keep me happy. Have you eaten? I can also check the system for you.",
    },
    "help": {
        "patterns": [
            r"(帮助|怎么用|如何使用|你能做什么|你会什么|有什么功能|能帮我做什么|使用说明|neng\s+zuo\s+shenme|bang\s+zhu|zen\s+me\s+yong)",
            r"\b(help|how\s+to\s+use|what\s+can\s+you\s+do|capabilities|features)\b",
        ],
        "zh": (
            "你可以直接描述目标，例如“查看磁盘空间”“检查 SSH 安全配置”"
            "或“把系统语言改成中文”。涉及修改、删除、重启或断网时，我会先给出计划、"
            "风险提醒和确认语。你也可以使用 /scan、/audit 和 /rules。"
        ),
        "en": (
            "Describe the outcome you want, for example \"show disk usage\", "
            "\"check SSH security configuration\", or \"change system language to Chinese\". "
            "For changes, deletion, reboots, or connectivity risks, I show a plan and require "
            "an explicit confirmation phrase. You can also use /scan, /audit, and /rules."
        ),
    },
    "thanks": {
        "patterns": [
            r"(谢谢|感谢|辛苦了|多谢|xie\s*xie|duo\s*xie)",
            r"\b(thanks|thank you|appreciate it)\b",
        ],
        "zh": "不客气。需要检查系统、查看风险或执行受控操作时，直接告诉我即可。",
        "en": "You are welcome. Tell me whenever you need a system check, risk review, or controlled operation.",
    },
    "greeting": {
        "patterns": [
            r"(^|[，,。.!！\s])(你好|您好|嗨|哈喽|在吗)([，,。.!！\s]|$)",
            r"\b(hello|hi|hey|good morning|good afternoon|good evening|ni\s*hao|nin\s*hao)\b",
        ],
        "zh": "你好，我是 RHEL 护航员。你可以告诉我想查看什么，或者直接说“你能做什么”。",
        "en": "Hello. I am RHEL Ops Agent. Tell me what you want to inspect, or ask \"what can you do?\"",
    },
    "goodbye": {
        "patterns": [
            r"(再见|拜拜|回头见)",
            r"\b(goodbye|bye|see you)\b",
            r"\b(zai\s*jian|bai\s*bai)\b",
        ],
        "zh": "再见。需要检查系统或执行受控操作时再叫我。",
        "en": "Goodbye. Call me when you need a system check or a controlled operation.",
    },
}

SMALL_TALK_SUGGESTIONS = {
    "zh": ["查看系统状态", "检查 SSH 安全配置", "查看最近登录", "你能做什么"],
    "en": ["show system status", "check SSH security configuration", "show recent logins", "what can you do"],
}

SEMANTIC_ALIASES = {
    "show_cpu_processes": {
        "action_id": "show_processes",
        "patterns": [
            r"(CPU|cpu|内存|运存).*(占用|占|吃|用).*(高|大|多).*(进程)?",
            r"(机器|电脑|系统).*(卡顿|很卡|有点卡|变慢|慢)",
            r"\b(high cpu|cpu usage|memory hog|slow|system is slow|lags?)\b",
        ],
    },
    "show_disk_alias": {
        "action_id": "show_disk",
        "patterns": [
            r"(磁盘|硬盘).*(还剩|剩余|剩多少|满|不够|空间|占用|容量)",
            r"\b(disk|storage)\s+(space|usage|full|free|left)\b",
            r"\bhow much (disk )?space\b",
        ],
    },
    "show_memory_alias": {
        "action_id": "show_memory",
        "patterns": [
            r"(内存|运存).*(还剩|剩余|够用|够不够|满|不够|占用|多少)",
            r"\b(memory|ram)\s+(usage|free|available|full)\b",
        ],
    },
    "show_time_alias": {
        "action_id": "show_time",
        "patterns": [
            r"(现在|当前|系统).*(几点|时间)",
            r"\b(what time|current time|system time|what date)\b",
        ],
    },
    "show_users_alias": {
        "action_id": "show_logged_in_users",
        "patterns": [
            r"(谁|哪些人).*(在线|登录|连着|连接)",
            r"\b(who is (online|logged in)|logged.?in users?|active users?)\b",
        ],
    },
    "show_logins_alias": {
        "action_id": "show_recent_logins",
        "patterns": [
            r"(最近|近期).*(谁|哪些).*(登录|访问)",
            r"\b(recent|last)\s+(logins?|login history)\b",
        ],
    },
    "show_logs_alias": {
        "action_id": "show_logs",
        "patterns": [
            r"(系统|服务).*(报错|错误|异常|故障)",
            r"\b(errors?|something wrong|system problems?|error logs?)\b",
        ],
    },
    "show_failed_alias": {
        "action_id": "show_failed_services",
        "patterns": [
            r"(哪些|什么).*(服务|service).*(坏|失败|异常|挂了)",
            r"\b(which|what).*(services?).*(failed|broken|down)\b",
        ],
    },
    "show_firewall_alias": {
        "action_id": "show_firewall",
        "patterns": [
            r"(防火墙|firewall).*(状态|规则|开了|放行)",
            r"\b(firewall|firewalld)\s+(status|rules?)\b",
        ],
    },
    "show_ports_alias": {
        "action_id": "show_listening_ports",
        "patterns": [
            r"(哪些|什么).*(端口|port).*(开着|监听|开放)",
            r"\b(open ports?|listening ports?|ports? (open|listening))\b",
        ],
    },
    "show_network_alias": {
        "action_id": "show_network",
        "patterns": [
            r"(网络|网卡|ip).*(状态|配置|地址|多少|怎么样)",
            r"\b(network|interface|ip).*(status|configuration|address)\b",
        ],
    },
    "show_route_alias": {
        "action_id": "show_routes",
        "patterns": [
            r"(路由|下一跳).*(表|规则|怎么走|是什么)",
            r"\b(routing table|route table|next hop)\b",
        ],
    },
    "show_ssh_alias": {
        "action_id": "show_ssh_config",
        "patterns": [
            r"ssh.*(安全|配置|设置|允许.*root)",
            r"\b(ssh)\s+(security|config|configuration)\b",
        ],
    },
    "show_update_alias": {
        "action_id": "show_updates",
        "patterns": [
            r"(补丁|安全更新|系统更新).*(有没有|有哪些|待安装|需要|检查)",
            r"(有没有|有哪些|检查).*(补丁|安全更新|系统更新)",
            r"\b(updates?|patches?|patching).*(available|pending|need|missing)\b",
        ],
    },
    "show_selinux_alias": {
        "action_id": "show_selinux",
        "patterns": [
            r"(selinux).*(状态|开没开|模式|启用)",
            r"\b(selinux)\s+(status|mode|enabled)\b",
        ],
    },
    "show_cron_alias": {
        "action_id": "show_cron",
        "patterns": [
            r"(定时|计划).*(任务|作业|job).*(有哪些|查看|列表)?",
            r"\b(cron|cronjob|scheduled jobs?)\b",
        ],
    },
    "show_locale_alias": {
        "action_id": "show_locale",
        "patterns": [
            r"(现在|当前|系统).*(语言|编码|locale)",
            r"\b(current|system)\s+(locale|language)\b",
        ],
    },
    "show_kernel_alias": {
        "action_id": "show_kernel_version",
        "patterns": [
            r"(内核|kernel).*(什么版本|版本号|多少)",
            r"\b(kernel|uname)\s+(version|release)\b",
        ],
    },
    "show_cpu_alias": {
        "action_id": "show_cpu_info",
        "patterns": [
            r"(cpu|处理器).*(型号|几核|核心|参数|信息)",
            r"\b(cpu|processor)\s+(model|cores?|info)\b",
        ],
    },
    "show_connections_alias": {
        "action_id": "show_active_connections",
        "patterns": [
            r"(连接|会话|socket).*(有哪些|列表|情况|谁)",
            r"\b(active|network)\s+connections?\b",
        ],
    },
    "test_network_alias": {
        "action_id": "test_network_connectivity",
        "patterns": [
            r"(网络|网).*(通不通|能不能上网|能上网吗|可不可达|延迟)",
            r"能不能上网|能上网吗|网络能用吗|外网通吗",
            r"\b(ping|reachable|connectivity|can it reach|internet works?)\b",
        ],
    },
}

PINYIN_CHAT_HINTS = re.compile(
    r"(?i)\b(?:ni\s*hao|nin\s*hao|chi\s*le\s*ma|chi\s+fan\s+le\s+ma|"
    r"xie\s*xie|duo\s*xie|neng\s+zuo\s+shenme|bang\s+zhu|zen\s+me\s+yong|"
    r"ni\s+shi\s+shui|ni\s+jiao\s+shenme|zai\s*jian|bai\s*bai)\b"
)

SYSTEM_SERVICES = (
    "sshd",
    "httpd",
    "nginx",
    "firewalld",
    "chronyd",
    "auditd",
    "crond",
    "rsyslog",
    "NetworkManager",
    "postfix",
    "mariadb",
    "mysql",
    "redis",
    "docker",
    "podman",
)


class RuleError(RuntimeError):
    pass


def _safe_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _safe_ipv4_network(value: str) -> bool:
    try:
        ipaddress.IPv4Interface(value)
        return True
    except ValueError:
        return False


def _redact_command(command: str) -> str:
    command = re.sub(
        r"(?i)(--?(?:password|passwd|token|secret)[=\s]+)([^\s]+)",
        r"\1[REDACTED]",
        command,
    )
    command = re.sub(r"(?i)(https?://[^:/\s]+:)[^@\s]+@", r"\1[REDACTED]@", command)
    return command


def command_preview(argv: list[str]) -> str:
    return _redact_command(shlex.join([str(item) for item in argv]))


def detect_language(message: str) -> str:
    return (
        "zh"
        if re.search(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]", message or "")
        else "en"
    )


def normalize_message(message: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", message or "").split())


class RuleEngine:
    def __init__(self, rules_dir: Path):
        self.rules_dir = Path(rules_dir)
        self.actions: list[dict[str, Any]] = []
        self.blocked: list[dict[str, Any]] = []
        self._compiled_actions: list[dict[str, Any]] = []
        self._compiled_blocked: list[dict[str, Any]] = []
        self.reload()

    def reload(self) -> None:
        path = self.rules_dir / "commands.json"
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        actions = list(data.get("actions", []))
        for filename in ("extra_commands.json", "extra_commands_more.json"):
            extra_path = self.rules_dir / filename
            if not extra_path.exists():
                continue
            with extra_path.open("r", encoding="utf-8") as handle:
                extra_data = json.load(handle)
            actions.extend(extra_data.get("actions", []))
        blocked = data.get("blocked_patterns", [])
        seen = set()
        for action in actions:
            if action["id"] in seen:
                raise RuleError("Duplicate action id: %s" % action["id"])
            if action.get("risk") not in RISK_ORDER:
                raise RuleError("Invalid risk for action %s" % action["id"])
            seen.add(action["id"])
        self.actions = actions
        self.blocked = blocked
        self._compiled_actions = [
            {
                **action,
                "_patterns": [
                    re.compile(pattern, re.IGNORECASE) for pattern in action.get("patterns", [])
                ],
            }
            for action in actions
        ]
        self._compiled_blocked = [
            {
                **item,
                "_patterns": [
                    re.compile(pattern, re.IGNORECASE) for pattern in item.get("patterns", [])
                ],
            }
            for item in blocked
        ]

    def public_rules(self) -> dict[str, Any]:
        actions = []
        for action in self.actions:
            actions.append(
                {
                    "id": action["id"],
                    "title_zh": action.get("title_zh", action["id"]),
                    "title_en": action.get("title_en", action["id"]),
                    "category": action.get("category", "system"),
                    "risk": action.get("risk", "safe"),
                    "summary_zh": action.get("summary_zh", ""),
                    "summary_en": action.get(
                        "summary_en",
                        self._english_summary(action),
                    ),
                    "impact_zh": action.get("impact_zh", ""),
                    "impact_en": action.get(
                        "impact_en",
                        self._english_impact(action),
                    ),
                    "requires_restart": bool(action.get("requires_restart", False)),
                    "restart_reason_zh": action.get("restart_reason_zh", ""),
                    "restart_reason_en": action.get("restart_reason_en", ""),
                }
            )
        return {
            "count": len(actions),
            "actions": actions,
            "blocked_pattern_count": len(self.blocked),
        }

    def _english_summary(self, action: dict[str, Any]) -> str:
        if action.get("risk") == "safe":
            return "Collects read-only system information using validated command arguments."
        return "Applies a controlled system change after explicit review and confirmation."

    def _english_impact(self, action: dict[str, Any]) -> str:
        if action.get("risk") == "safe":
            return "Does not modify system configuration."
        if action.get("risk") == "destructive":
            return "This high-risk change may interrupt services or remove access."
        return "This operation changes system configuration and should be reviewed first."

    def _extract_entities(self, message: str) -> dict[str, Any]:
        entities: dict[str, Any] = {}
        text = message.replace("\r", "\n")

        timezone_match = re.search(
            r"\b(UTC|(?:Africa|America|Antarctica|Arctic|Asia|Atlantic|Australia|Europe|Indian|Pacific)"
            r"/[A-Za-z0-9_+\-]+)\b",
            text,
            re.IGNORECASE,
        )
        if timezone_match:
            value = timezone_match.group(1)
            entities["timezone"] = "UTC" if value.upper() == "UTC" else value

        datetime_match = re.search(
            r"\b(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2})?)\b", text
        )
        if datetime_match:
            entities["datetime"] = "%s %s" % (
                datetime_match.group(1),
                datetime_match.group(2),
            )

        quoted_path = re.search(r"[\"'`](/[^\"'`\n]{1,200})[\"'`]", text)
        if quoted_path:
            entities["path"] = quoted_path.group(1)
        else:
            path_match = re.search(r"(?<![A-Za-z0-9_])/(?:[A-Za-z0-9_.+@%:-]+/?){1,}", text)
            if path_match:
                entities["path"] = path_match.group(0).rstrip(".,;，。；")

        connection_patterns = [
            r"(?:连接名|连接|connection|网卡|接口|interface|device)\s*(?:是|为|叫|:|：)?\s*([A-Za-z0-9_.@:-]{1,64})",
            r"\b(ens[0-9]+|eth[0-9]+|enp[0-9A-Za-z_.:-]+|eno[0-9A-Za-z_.:-]+|bond[0-9A-Za-z_.:-]+|br[0-9A-Za-z_.:-]+)\b",
        ]
        for pattern in connection_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                candidate = match.group(1)
                if candidate.lower() not in {
                    "ip",
                    "dns",
                    "dhcp",
                    "sshd",
                    "eth",
                    "interface",
                    "connection",
                }:
                    entities["connection"] = candidate
                    break

        all_ips = [
            match.group(0)
            for match in re.finditer(
                r"(?<![0-9])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![0-9])", text
            )
            if _safe_ipv4_network(match.group(0))
        ]

        gateway_match = re.search(
            r"(?:网关|gateway)\s*(?:是|为|:|：)?\s*((?:\d{1,3}\.){3}\d{1,3})",
            text,
            re.IGNORECASE,
        )
        if gateway_match and _safe_ipv4(gateway_match.group(1)):
            entities["gateway"] = gateway_match.group(1)

        dns_match = re.search(
            r"(?:DNS|dns|域名服务器)\s*(?:是|为|:|：)?\s*((?:\d{1,3}\.){3}\d{1,3})",
            text,
        )
        if dns_match and _safe_ipv4(dns_match.group(1)):
            entities["dns"] = dns_match.group(1)

        cidr_ips = [item for item in all_ips if "/" in item]
        if cidr_ips and _safe_ipv4_network(cidr_ips[0]):
            entities["ipv4_cidr"] = cidr_ips[0]

        hostname_match = re.search(
            r"(?:主机名|hostname|host name)\s*(?:改为|改成|设置为|设为|为|是|叫|to|:)?\s*([A-Za-z0-9](?:[A-Za-z0-9.-]{0,61}[A-Za-z0-9])?)",
            text,
            re.IGNORECASE,
        )
        if hostname_match:
            candidate = hostname_match.group(1)
            if candidate.lower() not in {"to", "is", "set", "change"}:
                entities["hostname"] = candidate

        port_match = re.search(
            r"(?:端口|port)\s*(?:是|为|:|：)?\s*([1-9][0-9]{0,4})", text, re.IGNORECASE
        ) or re.search(r"(?:开放|放行|关闭|允许|open|close|allow)\s+([1-9][0-9]{0,4})", text, re.IGNORECASE)
        if port_match and 1 <= int(port_match.group(1)) <= 65535:
            entities["port"] = port_match.group(1)

        protocol_match = re.search(r"\b(tcp|udp)\b", text, re.IGNORECASE)
        if protocol_match:
            entities["protocol"] = protocol_match.group(1).lower()
        elif "port" in entities:
            entities["protocol"] = "tcp"

        known_service_match = re.search(
            r"\b(" + "|".join(re.escape(item) for item in SYSTEM_SERVICES) + r")\b",
            text,
            re.IGNORECASE,
        )
        if known_service_match:
            for service in SYSTEM_SERVICES:
                if service.lower() == known_service_match.group(1).lower():
                    entities["service"] = service
                    break
        else:
            service_match = re.search(
                r"(?:服务|service)\s*(?:名为|名字是|是|为|叫|:|：)?\s*([A-Za-z0-9_.@:-]{2,64})",
                text,
                re.IGNORECASE,
            )
            if service_match:
                candidate = service_match.group(1)
                if candidate.lower() not in {"service", "the", "and", "please"}:
                    entities["service"] = candidate

        username_match = re.search(
            r"(?:用户|账号|账户|user|account)\s*(?:名为|名字是|是|为|叫|:|：)?\s*([a-z_][a-z0-9_-]{0,31})",
            text,
            re.IGNORECASE,
        )
        if username_match:
            candidate = username_match.group(1).lower()
            if candidate not in {"user", "account", "the", "and"}:
                entities["username"] = candidate

        group_match = re.search(
            r"(?:用户组|group)\s*(?:名为|名字是|是|为|叫|:|：)?\s*([a-z_][a-z0-9_-]{0,31})",
            text,
            re.IGNORECASE,
        ) or re.search(
            r"(?:加入|添加到|到|至)\s*(?:用户组|组)?\s*([a-z_][a-z0-9_-]{0,31})",
            text,
            re.IGNORECASE,
        )
        if group_match:
            candidate = group_match.group(1).lower()
            if candidate in {"members", "member", "users", "user"}:
                member_target = re.search(
                    r"(?:组成员|成员|group members?|members?)\s*"
                    r"(?:of|for|in|是|为|:|：)?\s*(?:用户组|group)?\s*"
                    r"([a-z_][a-z0-9_-]{0,31})",
                    text,
                    re.IGNORECASE,
                )
                if member_target:
                    entities["groupname"] = member_target.group(1).lower()
            elif candidate not in {"group", "the", "and"}:
                entities["groupname"] = candidate

        package_match = re.search(
            r"(?:安装|卸载|删除|移除|install|remove|uninstall)\s*(?:软件包|软件|工具|包|package|software|tool)?\s*([A-Za-z0-9_.+-]{2,100})",
            text,
            re.IGNORECASE,
        )
        if package_match:
            candidate = package_match.group(1)
            if candidate.lower() not in {"package", "software", "tool"}:
                entities["package"] = candidate

        pid_match = re.search(r"(?:PID|pid|进程)\s*(?:是|为|:|：)?\s*([1-9][0-9]{0,6})", text)
        if pid_match:
            entities["pid"] = pid_match.group(1)

        return entities

    def _extract_param(
        self, extractor: str, entities: dict[str, Any], message: str
    ) -> Any:
        if extractor in entities:
            return entities[extractor]
        if extractor == "ipv4_cidr":
            address_match = re.search(
                r"(?:IP|ip|地址|address)\s*(?:改为|改成|设置为|设为|为|是|to|:)?\s*((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})",
                message,
                re.IGNORECASE,
            )
            return address_match.group(1) if address_match else None
        if extractor == "gateway":
            return None
        if extractor == "dns":
            return None
        if extractor == "connection":
            return entities.get("connection")
        if extractor == "path":
            return entities.get("path")
        if extractor == "port":
            return entities.get("port")
        if extractor == "protocol":
            return entities.get("protocol", "tcp")
        if extractor == "service":
            return entities.get("service")
        if extractor == "username":
            if entities.get("username"):
                return entities["username"]
            match = re.search(
                r"(?:password status|password state|密码状态)\s*"
                r"(?:for|of|is|是|为|:|：)?\s*([a-z_][a-z0-9_-]{0,31})",
                message,
                re.IGNORECASE,
            )
            return match.group(1) if match else None
        if extractor == "groupname":
            return entities.get("groupname")
        if extractor == "host":
            addresses = re.findall(
                r"(?<![0-9])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])",
                message,
            )
            if addresses:
                return addresses[-1]
            domain = re.search(
                r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                r"[A-Za-z]{2,63}\b",
                message,
            )
            if domain:
                return domain.group(0)
            return entities.get("host") or entities.get("hostname")
        if extractor == "package":
            if entities.get("package"):
                return entities["package"]
            match = re.search(
                r"(?:for|about|名为|名字是|叫)\s*([A-Za-z0-9_.+-]{2,100})",
                message,
                re.IGNORECASE,
            )
            return match.group(1) if match else None
        if extractor == "pid":
            return entities.get("pid")
        if extractor == "timezone":
            return entities.get("timezone")
        if extractor == "datetime":
            return entities.get("datetime")
        if extractor == "hostname":
            return entities.get("hostname")
        return entities.get(extractor)

    def _validate_param(
        self,
        name: str,
        definition: dict[str, Any],
        value: Any,
        language: str = "zh",
    ) -> tuple[bool, str]:
        label = definition.get(
            "label_en" if language == "en" else "label_zh",
            definition.get("label_zh", name),
        )
        if value is None or str(value).strip() == "":
            if definition.get("required", True):
                return (
                    False,
                    "Please provide %s" % label
                    if language == "en"
                    else "请填写 %s" % label,
                )
            return True, ""
        text = str(value).strip()
        if text.startswith("-"):
            return (
                False,
                "%s must not start with '-'" % label
                if language == "en"
                else "%s不能以 - 开头" % label,
            )
        pattern = definition.get("pattern")
        if pattern and not re.fullmatch(pattern, text, re.IGNORECASE):
            return (
                False,
                "Invalid format for %s" % label
                if language == "en"
                else "%s格式不正确" % label,
            )
        return True, ""

    def _validate_semantics(
        self,
        action_id: str,
        params: dict[str, Any],
        language: str = "zh",
    ) -> tuple[bool, str]:
        if action_id == "set_static_ipv4":
            if not _safe_ipv4_network(str(params.get("address", ""))):
                return (
                    False,
                    "Invalid IPv4 address or prefix"
                    if language == "en"
                    else "IPv4 地址或掩码不正确",
                )
            for key in ("gateway", "dns"):
                if not _safe_ipv4(str(params.get(key, ""))):
                    return (
                        False,
                        "%s is not a valid IPv4 address" % key
                        if language == "en"
                        else "%s不是有效的 IPv4 地址" % key,
                    )
        if action_id in {"open_firewall_port", "close_firewall_port"}:
            try:
                port = int(params.get("port", 0))
            except (TypeError, ValueError):
                return (
                    False,
                    "Port is not a valid number"
                    if language == "en"
                    else "端口不是有效数字",
                )
            if not 1 <= port <= 65535:
                return (
                    False,
                    "Port must be between 1 and 65535"
                    if language == "en"
                    else "端口必须在 1-65535 之间",
                )
        if action_id == "delete_path":
            path = str(params.get("path", ""))
            if not path.startswith("/"):
                return (
                    False,
                    "Delete path must be absolute"
                    if language == "en"
                    else "删除路径必须是绝对路径",
                )
            critical = [
                "/",
                "/boot",
                "/dev",
                "/etc",
                "/proc",
                "/sys",
                "/usr",
                "/var/lib",
                "/var/log",
                "/var/run",
                "/var/spool",
                "/root",
            ]
            normalized = posixpath.normpath(path)
            resolved = (
                str(Path(path).resolve(strict=False)) if os.name != "nt" else normalized
            )
            for prefix in critical:
                if prefix == "/":
                    rejected = normalized == "/" or resolved == "/"
                else:
                    rejected = (
                        normalized == prefix
                        or normalized.startswith(prefix + "/")
                        or resolved == prefix
                        or resolved.startswith(prefix + "/")
                    )
                if rejected:
                    return (
                        False,
                        "Refusing to delete protected system path: %s" % normalized
                        if language == "en"
                        else "禁止删除系统关键路径：%s" % normalized,
                    )
        return True, ""

    def _search(self, message: str) -> tuple[list[dict[str, Any]], Optional[dict[str, Any]]]:
        blocked = None
        for item in self._compiled_blocked:
            if any(pattern.search(message) for pattern in item["_patterns"]):
                blocked = {
                    "id": item["id"],
                    "title_zh": item.get("title_zh", "已拦截高风险操作"),
                    "title_en": item.get("title_en", "Blocked high-risk operation"),
                    "severity": item.get("severity", "critical"),
                    "reason_zh": item.get("reason_zh", "该操作不在允许自动执行的范围内。"),
                    "reason_en": item.get("reason_en", "This operation is not allowed."),
                }
                break

        matches: list[dict[str, Any]] = []
        for action in self._compiled_actions:
            action_matches = []
            for pattern in action["_patterns"]:
                found = pattern.search(message)
                if found:
                    action_matches.append(found.group(0))
            if action_matches:
                best = max(action_matches, key=len)
                matches.append(
                    {
                        "action": action,
                        "matched": best,
                        "score": len(best) + int(action.get("priority", 0)) * 100,
                    }
                )
        if not matches:
            matches = self._alias_search(message)
        return matches, blocked

    def _alias_search(self, message: str) -> list[dict[str, Any]]:
        by_id = {action["id"]: action for action in self._compiled_actions}
        matches = []
        seen = set()
        for alias in SEMANTIC_ALIASES.values():
            action = by_id.get(alias["action_id"])
            if not action or action["id"] in seen:
                continue
            found_values = [
                found.group(0)
                for pattern in alias["patterns"]
                if (found := re.search(pattern, message, re.IGNORECASE))
            ]
            if found_values:
                seen.add(action["id"])
                best = max(found_values, key=len)
                matches.append(
                    {
                        "action": action,
                        "matched": best,
                        "score": 250 + len(best) + int(action.get("priority", 0)) * 100,
                    }
                )
        return matches

    def _conversation_reply(
        self, message: str, language: str
    ) -> Optional[dict[str, Any]]:
        for intent, item in SMALL_TALK_REPLIES.items():
            if any(re.search(pattern, message, re.IGNORECASE) for pattern in item["patterns"]):
                return {
                    "status": "chat",
                    "language": language,
                    "intent": intent,
                    "message": item[language],
                    "suggestions": SMALL_TALK_SUGGESTIONS[language],
                    "steps": [],
                }
        return None

    def plan(
        self,
        message: str,
        overrides: Optional[dict[str, dict[str, Any]]] = None,
        context: Optional[dict[str, Any]] = None,
        forced_action_ids: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        message = normalize_message(message)
        language = detect_language(message)
        if PINYIN_CHAT_HINTS.search(message):
            language = "zh"
        messages = PLAN_MESSAGES[language]
        if not message:
            return {
                "status": "empty",
                "language": language,
                "message": messages["empty"],
                "steps": [],
            }
        overrides = overrides or {}
        context = context or {}
        matches, blocked = self._search(message)
        if blocked:
            blocked["language"] = language
            blocked["title"] = blocked["title_en"] if language == "en" else blocked["title_zh"]
            blocked["reason"] = (
                blocked["reason_en"] if language == "en" else blocked["reason_zh"]
            )
            return {
                "status": "blocked",
                "language": language,
                "blocked": blocked,
                "message": messages["blocked"],
                "steps": [],
            }
        if forced_action_ids:
            by_id = {action["id"]: action for action in self._compiled_actions}
            matches = [
                {
                    "action": by_id[action_id],
                    "matched": message[:120],
                    "score": 1000 + index,
                }
                for index, action_id in enumerate(forced_action_ids)
                if action_id in by_id
            ]
        if not matches:
            chat = self._conversation_reply(message, language)
            if chat:
                return chat
            return {
                "status": "unsupported",
                "language": language,
                "message": messages["unsupported"],
                "suggestions": SMALL_TALK_SUGGESTIONS[language],
                "steps": [],
            }

        entities = self._extract_entities(message)
        steps: list[dict[str, Any]] = []
        missing_fields: list[dict[str, Any]] = []
        seen_actions = set()
        seen_groups = set()

        for match in sorted(matches, key=lambda item: item["score"], reverse=True):
            action = match["action"]
            if action["id"] in seen_actions:
                continue
            group = action.get("group")
            if group and group in seen_groups:
                continue
            seen_actions.add(action["id"])
            if group:
                seen_groups.add(group)

            params: dict[str, Any] = {}
            step_missing = []
            definitions = action.get("params", {})
            action_overrides = overrides.get(action["id"], {})
            for name, definition in definitions.items():
                value = action_overrides.get(name)
                if value is None or str(value).strip() == "":
                    value = self._extract_param(
                        definition.get("extractor", name), entities, message
                    )
                if value is None or str(value).strip() == "":
                    value = definition.get("default")
                if value is not None:
                    value = str(value).strip()
                    params[name] = value
                valid, error = self._validate_param(
                    name, definition, value, language=language
                )
                if not valid:
                    label_zh = definition.get("label_zh", name)
                    label_en = definition.get("label_en", name)
                    step_missing.append(
                        {
                            "name": name,
                            "label_zh": label_zh,
                            "label_en": label_en,
                            "label": label_en if language == "en" else label_zh,
                            "placeholder": definition.get("placeholder", ""),
                            "value": "" if value is None else str(value),
                            "error": error,
                        }
                    )
            if step_missing:
                action_title_zh = action.get("title_zh", action["id"])
                action_title_en = action.get("title_en", action["id"])
                missing_fields.extend(
                    [
                        {
                            **field,
                            "action_id": action["id"],
                            "action_title": (
                                action_title_en
                                if language == "en"
                                else action_title_zh
                            ),
                            "action_title_zh": action_title_zh,
                            "action_title_en": action_title_en,
                        }
                        for field in step_missing
                    ]
                )

            semantic_ok, semantic_error = (
                self._validate_semantics(action["id"], params, language=language)
                if not step_missing
                else (True, "")
            )
            if not semantic_ok:
                action_title_zh = action.get("title_zh", action["id"])
                action_title_en = action.get("title_en", action["id"])
                missing_fields.append(
                    {
                        "name": next(iter(definitions), "value"),
                        "label_zh": semantic_error,
                        "label_en": semantic_error,
                        "label": semantic_error,
                        "placeholder": "",
                        "value": "",
                        "error": semantic_error,
                        "action_id": action["id"],
                        "action_title": (
                            action_title_en if language == "en" else action_title_zh
                        ),
                        "action_title_zh": action_title_zh,
                        "action_title_en": action_title_en,
                    }
                )

            title_zh = action.get("title_zh", action["id"])
            title_en = action.get("title_en", action["id"])
            summary_zh = action.get("summary_zh", "")
            summary_en = action.get("summary_en") or self._english_summary(action)
            impact_zh = action.get("impact_zh", "")
            impact_en = action.get("impact_en") or self._english_impact(action)
            restart_reason_zh = action.get("restart_reason_zh", "")
            restart_reason_en = action.get(
                "restart_reason_en",
                "A restart or re-login is required for this change to take effect.",
            )
            confirmation_phrase_en = action.get(
                "confirmation_phrase_en",
                CONFIRMATION_PHRASES_EN.get(action["id"], "Confirm execution"),
            )
            steps.append(
                {
                    "action_id": action["id"],
                    "language": language,
                    "title_zh": title_zh,
                    "title_en": title_en,
                    "title": title_en if language == "en" else title_zh,
                    "category": action.get("category", "system"),
                    "risk": action.get("risk", "safe"),
                    "risk_label": (
                        RISK_LABELS_EN if language == "en" else RISK_LABELS
                    ).get(action.get("risk", "safe"), "Unknown"),
                    "summary_zh": summary_zh,
                    "summary_en": summary_en,
                    "summary": summary_en if language == "en" else summary_zh,
                    "impact_zh": impact_zh,
                    "impact_en": impact_en,
                    "impact": impact_en if language == "en" else impact_zh,
                    "params": params,
                    "param_definitions": definitions,
                    "missing_fields": step_missing,
                    "requires_restart": bool(action.get("requires_restart", False)),
                    "restart_reason_zh": restart_reason_zh,
                    "restart_reason_en": restart_reason_en,
                    "restart_reason": (
                        restart_reason_en if language == "en" else restart_reason_zh
                    ),
                    "confirmation_phrase": (
                        confirmation_phrase_en
                        if language == "en"
                        else action.get("confirmation_phrase", "确认执行")
                    ),
                    "confirmation_phrase_en": confirmation_phrase_en,
                    "commands": self.build_commands(action, params)
                    if not step_missing
                    else [],
                    "matched_text": match["matched"],
                }
            )

        if missing_fields:
            present = [step for step in steps if not step["missing_fields"]]
            return {
                "status": "needs_input",
                "language": language,
                "message": messages["needs_input"],
                "fields": missing_fields,
                "steps": present,
                "draft_actions": [
                    {"action_id": step["action_id"], "params": step["params"]}
                    for step in steps
                ],
            }

        steps = [self._hydrate_step(step, context) for step in steps]
        warnings: list[dict[str, Any]] = []
        for step in steps:
            for warning in step.get("warnings", []):
                if warning not in warnings:
                    warnings.append(warning)
        overall_risk = max(
            (step["risk"] for step in steps), key=lambda item: RISK_ORDER[item]
        )
        non_safe = [step for step in steps if step["risk"] != "safe"]
        if not non_safe:
            confirmation_phrase = ""
        elif len(non_safe) == 1:
            confirmation_phrase = non_safe[0]["confirmation_phrase"]
        elif overall_risk == "destructive":
            confirmation_phrase = messages["confirm_high"]
        else:
            confirmation_phrase = messages["confirm_selected"]
        return {
            "status": "ready",
            "language": language,
            "message": messages["ready"],
            "steps": steps,
            "warnings": warnings,
            "overall_risk": overall_risk,
            "overall_risk_label": (
                RISK_LABELS_EN if language == "en" else RISK_LABELS
            )[overall_risk],
            "requires_confirmation": bool(non_safe),
            "confirmation_phrase": confirmation_phrase,
            "requires_restart": any(step["requires_restart"] for step in steps),
            "restart_reasons": [
                step["restart_reason"]
                for step in steps
                if step["requires_restart"] and step["restart_reason"]
            ],
        }

    def _plan_legacy(
        self,
        message: str,
        overrides: Optional[dict[str, dict[str, Any]]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        message = message.strip()
        if not message:
            return {
                "status": "empty",
                "message": "请输入你想完成的操作，例如：查看磁盘空间。",
                "steps": [],
            }
        overrides = overrides or {}
        context = context or {}
        matches, blocked = self._search(message)
        if blocked:
            return {
                "status": "blocked",
                "blocked": blocked,
                "message": "已识别并拦截高风险操作，没有执行任何命令。",
                "steps": [],
            }
        if not matches:
            return {
                "status": "unsupported",
                "message": "没有找到受支持的操作。可以换一种说法，或在规则库中查看可用指令。",
                "steps": [],
            }

        entities = self._extract_entities(message)
        steps: list[dict[str, Any]] = []
        missing_fields: list[dict[str, Any]] = []
        seen_actions = set()
        seen_groups = set()

        for match in sorted(matches, key=lambda item: item["score"], reverse=True):
            action = match["action"]
            if action["id"] in seen_actions:
                continue
            group = action.get("group")
            if group and group in seen_groups:
                continue
            seen_actions.add(action["id"])
            if group:
                seen_groups.add(group)
            params: dict[str, Any] = {}
            step_missing = []
            definitions = action.get("params", {})
            action_overrides = overrides.get(action["id"], {})
            for name, definition in definitions.items():
                value = action_overrides.get(name)
                if value is None or str(value).strip() == "":
                    value = self._extract_param(
                        definition.get("extractor", name), entities, message
                    )
                if value is None or str(value).strip() == "":
                    value = definition.get("default")
                if value is not None:
                    value = str(value).strip()
                    params[name] = value
                valid, error = self._validate_param(name, definition, value)
                if not valid:
                    step_missing.append(
                        {
                            "name": name,
                            "label_zh": definition.get("label_zh", name),
                            "label_en": definition.get("label_en", name),
                            "placeholder": definition.get("placeholder", ""),
                            "value": "" if value is None else str(value),
                            "error": error,
                        }
                    )
            if step_missing:
                missing_fields.extend(
                    [
                        {
                            **field,
                            "action_id": action["id"],
                            "action_title": action.get("title_zh", action["id"]),
                        }
                        for field in step_missing
                    ]
                )

            semantic_ok, semantic_error = self._validate_semantics(action["id"], params)
            if not semantic_ok:
                missing_fields.append(
                    {
                        "name": next(iter(definitions), "value"),
                        "label_zh": semantic_error,
                        "label_en": semantic_error,
                        "placeholder": "",
                        "value": "",
                        "error": semantic_error,
                        "action_id": action["id"],
                        "action_title": action.get("title_zh", action["id"]),
                    }
                )

            steps.append(
                {
                    "action_id": action["id"],
                    "title_zh": action.get("title_zh", action["id"]),
                    "title_en": action.get("title_en", action["id"]),
                    "category": action.get("category", "system"),
                    "risk": action.get("risk", "safe"),
                    "risk_label": RISK_LABELS.get(action.get("risk", "safe"), "未知"),
                    "summary_zh": action.get("summary_zh", ""),
                    "impact_zh": action.get("impact_zh", ""),
                    "params": params,
                    "param_definitions": definitions,
                    "missing_fields": step_missing,
                    "requires_restart": bool(action.get("requires_restart", False)),
                    "restart_reason_zh": action.get("restart_reason_zh", ""),
                    "confirmation_phrase": action.get("confirmation_phrase", "确认执行"),
                    "commands": self.build_commands(action, params) if not step_missing else [],
                    "matched_text": match["matched"],
                }
            )

        if missing_fields:
            present = [step for step in steps if not step["missing_fields"]]
            return {
                "status": "needs_input",
                "message": "还需要补充一些信息，确认后我会生成完整操作计划。",
                "fields": missing_fields,
                "steps": present,
                "draft_actions": [
                    {"action_id": step["action_id"], "params": step["params"]}
                    for step in steps
                ],
            }

        steps = [self._hydrate_step(step, context) for step in steps]
        warnings: list[dict[str, Any]] = []
        for step in steps:
            for warning in step.get("warnings", []):
                if warning not in warnings:
                    warnings.append(warning)
        overall_risk = max(
            (step["risk"] for step in steps), key=lambda item: RISK_ORDER[item]
        )
        non_safe = [step for step in steps if step["risk"] != "safe"]
        if not non_safe:
            confirmation_phrase = ""
        elif len(non_safe) == 1:
            confirmation_phrase = non_safe[0]["confirmation_phrase"] or "确认执行"
        elif overall_risk == "destructive":
            confirmation_phrase = "确认执行高风险操作"
        else:
            confirmation_phrase = "确认执行以上操作"
        return {
            "status": "ready",
            "message": "已生成操作计划。请先核对每一步，再决定是否执行。",
            "steps": steps,
            "warnings": warnings,
            "overall_risk": overall_risk,
            "overall_risk_label": RISK_LABELS[overall_risk],
            "requires_confirmation": bool(non_safe),
            "confirmation_phrase": confirmation_phrase,
            "requires_restart": any(step["requires_restart"] for step in steps),
            "restart_reasons": [
                step["restart_reason_zh"]
                for step in steps
                if step["requires_restart"] and step["restart_reason_zh"]
            ],
        }

    def _hydrate_step(
        self, step: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        action = next(item for item in self.actions if item["id"] == step["action_id"])
        language = step.get("language", "zh")
        warnings = []
        if action.get("network_disconnect"):
            warnings.append(
                {
                    "type": "ssh_disconnect",
                    "severity": "high",
                    "title_zh": "网络操作可能导致 SSH 断开",
                    "body_zh": "连接重载后 IP 地址可能变化。执行前请确认你可以通过控制台、IPMI 或其他管理网络恢复访问。",
                    "title_en": "Network changes may disconnect SSH",
                    "body_en": "The IP address may change after the connection is reloaded. Make sure console, IPMI, or another management path is available.",
                }
            )
        if action.get("network_disconnect_if"):
            if str(step["params"].get("service", "")).lower() == action["network_disconnect_if"]:
                warnings.append(
                    {
                        "type": "ssh_disconnect",
                        "severity": "high",
                        "title_zh": "SSH 服务操作可能中断当前连接",
                        "body_zh": "现有远程会话可能立即断开，请保留一个控制台会话作为备用。",
                        "title_en": "SSH service change may terminate this session",
                        "body_en": "The current remote session may close immediately. Keep a console session available as a fallback.",
                    }
                )
        if context.get("remote_client") or context.get("ssh_sessions"):
            for warning in warnings:
                if warning["type"] == "ssh_disconnect":
                    warning["context_zh"] = "检测到当前存在远程访问，断连风险已提高。"
                    warning["context_en"] = "A remote client is connected, so the disconnect risk is elevated."
        if step["action_id"] in {"reboot", "poweroff"}:
            warnings.append(
                {
                    "type": "service_outage",
                    "severity": "high",
                    "title_zh": "所有业务和远程会话将中断",
                    "body_zh": "确认没有正在进行的关键任务，并确保你有控制台或电源管理权限。",
                    "title_en": "All workloads and remote sessions will be interrupted",
                    "body_en": "Confirm that no critical task is running and that you have console or power-management access.",
                }
            )
        for warning in warnings:
            warning["title"] = (
                warning["title_en"] if language == "en" else warning["title_zh"]
            )
            warning["body"] = (
                warning["body_en"] if language == "en" else warning["body_zh"]
            )
            warning["context"] = warning.get(
                "context_en" if language == "en" else "context_zh", ""
            )
        step["warnings"] = warnings
        step["command_previews"] = [command_preview(argv) for argv in step["commands"]]
        if action.get("post_check") and not step["missing_fields"]:
            step["post_check_previews"] = [
                command_preview(self._hydrate_argv(argv, step["params"]))
                for argv in action["post_check"]
            ]
        else:
            step["post_check_previews"] = []
        step["accepted_exit_codes"] = action.get("accepted_exit_codes", [0])
        return step

    def _hydrate_argv(self, argv: list[str], params: dict[str, Any]) -> list[str]:
        hydrated = []
        for arg in argv:
            value = arg
            for name, param_value in params.items():
                value = value.replace("{{%s}}" % name, str(param_value))
            hydrated.append(value)
        return hydrated

    def build_commands(
        self, action: dict[str, Any], params: dict[str, Any]
    ) -> list[list[str]]:
        commands = []
        for argv in action.get("commands", []):
            hydrated = self._hydrate_argv(argv, params)
            if any("{{" in arg or "}}" in arg for arg in hydrated):
                raise RuleError("Unresolved command placeholder for action %s" % action["id"])
            commands.append(hydrated)
        return commands

    def actions_for_plan(self, draft_actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_id = {item["id"]: item for item in self.actions}
        result = []
        for item in draft_actions:
            action = by_id.get(item.get("action_id"))
            if action:
                result.append({"action": action, "params": item.get("params", {})})
        return result

    def rebuild(
        self,
        message: str,
        draft_actions: list[dict[str, Any]],
        context: Optional[dict[str, Any]] = None,
        forced_action_ids: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        overrides = {
            item["action_id"]: item.get("params", {})
            for item in draft_actions
            if item.get("action_id")
        }
        return self.plan(
            message,
            overrides=overrides,
            context=context,
            forced_action_ids=forced_action_ids,
        )

    def plan_payload(
        self,
        message: str,
        plan: dict[str, Any],
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        return {
            "message": message,
            "context": context or {},
            "created": time.time(),
            "plan": {
                "status": plan["status"],
                "language": plan.get("language", detect_language(message)),
                "steps": [
                    {
                        "action_id": step["action_id"],
                        "params": step["params"],
                    }
                    for step in plan.get("steps", [])
                    if not step.get("missing_fields")
                ],
                "overall_risk": plan.get("overall_risk", "safe"),
                "confirmation_phrase": plan.get("confirmation_phrase", ""),
                "planner": plan.get("planner", "rules"),
                "llm_model": plan.get("llm_model"),
            },
        }

    def rebuild_from_payload(
        self, payload: dict[str, Any], context: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        action_ids = [
            step["action_id"] for step in payload["plan"].get("steps", [])
        ]
        return self.rebuild(
            payload["message"],
            payload["plan"]["steps"],
            context=context or payload.get("context", {}),
            forced_action_ids=action_ids,
        )

    def select_steps(
        self, plan: dict[str, Any], selected_action_ids: list[str]
    ) -> list[dict[str, Any]]:
        if not selected_action_ids:
            return []
        wanted = set(selected_action_ids)
        return [step for step in plan.get("steps", []) if step["action_id"] in wanted]

    def proposal_risk(self, steps: list[dict[str, Any]]) -> str:
        if not steps:
            return "safe"
        return max((step["risk"] for step in steps), key=lambda item: RISK_ORDER[item])

    def resolution_phrase(self, steps: list[dict[str, Any]]) -> str:
        non_safe = [step for step in steps if step["risk"] != "safe"]
        if not non_safe:
            return ""
        language = non_safe[0].get("language", "zh")
        risk = self.proposal_risk(steps)
        if len(non_safe) == 1:
            return non_safe[0].get("confirmation_phrase") or "确认执行"
        if language == "en":
            return (
                "Confirm high-risk operations"
                if risk == "destructive"
                else "Confirm selected operations"
            )
        return "确认执行高风险操作" if risk == "destructive" else "确认执行以上操作"


def new_trace_id() -> str:
    return uuid.uuid4().hex
