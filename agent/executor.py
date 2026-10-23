from __future__ import annotations

import os
import subprocess
import threading
import time
from typing import Any, Optional

from .db import Database
from .engine import RuleEngine, command_preview, detect_language


MAX_OUTPUT_CHARS = 16_000
EXECUTION_TIMEOUT_SECONDS = 60


class ExecutionError(RuntimeError):
    pass


def _localized(language: str, zh: str, en: str) -> str:
    return en if language == "en" else zh


class ExecutionResult:
    def __init__(self, argv: list[str], returncode: int, output: str, duration: float):
        self.argv = argv
        self.returncode = returncode
        self.output = output
        self.duration = duration

    def as_dict(self) -> dict[str, Any]:
        return {
            "command": command_preview(self.argv),
            "returncode": self.returncode,
            "output": self.output,
            "duration_ms": round(self.duration * 1000),
            "ok": self.returncode == 0,
        }


class Executor:
    def __init__(self, engine: RuleEngine, database: Database, demo: bool = False):
        self.engine = engine
        self.database = database
        self.demo = demo
        self._lock = threading.Lock()
        self.allowed_binaries = {
            "auditctl",
            "chage",
            "chronyc",
            "df",
            "dnf",
            "firewall-cmd",
            "findmnt",
            "free",
            "getent",
            "getenforce",
            "getsebool",
            "groupadd",
            "gpasswd",
            "hostnamectl",
            "id",
            "ip",
            "journalctl",
            "kill",
            "last",
            "lastb",
            "localectl",
            "ls",
            "lsblk",
            "lscpu",
            "mkdir",
            "nmcli",
            "passwd",
            "ping",
            "ps",
            "resolvectl",
            "rm",
            "rpm",
            "sestatus",
            "setenforce",
            "shutdown",
            "ss",
            "sshd",
            "systemctl",
            "subscription-manager",
            "timedatectl",
            "tuned-adm",
            "uname",
            "uptime",
            "useradd",
            "usermod",
            "who",
        }
        self.environment = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": "/root",
            "TERM": "dumb",
        }

    def _validate_argv(self, argv: list[str], language: str = "zh") -> None:
        if not argv:
            raise ExecutionError(_localized(language, "空命令", "Empty command"))
        binary = os.path.basename(argv[0])
        if binary not in self.allowed_binaries:
            raise ExecutionError(
                _localized(
                    language,
                    "命令不在允许列表中：%s" % binary,
                    "Command is not in the allowlist: %s" % binary,
                )
            )
        for arg in argv:
            if "\x00" in arg or "\n" in arg or "\r" in arg:
                raise ExecutionError(
                    _localized(
                        language,
                        "命令参数包含非法字符",
                        "A command argument contains invalid characters",
                    )
                )
        if binary == "rm":
            if argv[1:3] != ["-rf", "--"]:
                raise ExecutionError(
                    _localized(
                        language,
                        "删除命令参数未通过安全校验",
                        "Delete arguments failed safety validation",
                    )
                )
            target = argv[3] if len(argv) > 3 else ""
            if not target.startswith("/"):
                raise ExecutionError(
                    _localized(
                        language,
                        "删除目标必须是绝对路径",
                        "Delete target must be an absolute path",
                    )
                )
        if binary == "kill" and len(argv) != 3:
            raise ExecutionError(
                _localized(language, "进程结束参数不合法", "Invalid process termination arguments")
            )

    def run_argv(
        self,
        argv: list[str],
        accepted_exit_codes: Optional[list[int]] = None,
        language: str = "zh",
    ) -> ExecutionResult:
        self._validate_argv(argv, language)
        accepted = set(accepted_exit_codes or [0])
        started = time.time()
        if self.demo:
            output = _localized(
                language,
                "[演示模式] 命令未在真实主机上执行。\n模拟命令：%s"
                % command_preview(argv),
                "[Demo mode] The command was not executed on the host.\n"
                "Simulated command: %s" % command_preview(argv),
            )
            return ExecutionResult(argv, 0, output, 0.001)
        try:
            completed = subprocess.run(
                argv,
                shell=False,
                cwd="/",
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                timeout=EXECUTION_TIMEOUT_SECONDS,
                check=False,
            )
            output = completed.stdout or ""
            if len(output) > MAX_OUTPUT_CHARS:
                output = output[:MAX_OUTPUT_CHARS] + _localized(
                    language,
                    "\n...[输出已截断]",
                    "\n...[output truncated]",
                )
            result = ExecutionResult(argv, completed.returncode, output, time.time() - started)
        except FileNotFoundError as exc:
            result = ExecutionResult(
                argv,
                127,
                _localized(language, "命令不存在：%s", "Command not found: %s") % exc,
                time.time() - started,
            )
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout or ""
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", errors="replace")
            result = ExecutionResult(
                argv,
                124,
                _localized(
                    language,
                    "命令执行超时（%ss）：\n%s",
                    "Command timed out after %ss:\n%s",
                )
                % (EXECUTION_TIMEOUT_SECONDS, partial),
                time.time() - started,
            )
        except OSError as exc:
            result = ExecutionResult(
                argv,
                126,
                _localized(language, "命令启动失败：%s", "Failed to start command: %s") % exc,
                time.time() - started,
            )
        if result.returncode not in accepted and accepted != {0}:
            return result
        if result.returncode not in {0} and result.returncode not in accepted:
            result.output = result.output.strip() or _localized(
                language,
                "命令返回状态码 %s" % result.returncode,
                "Command returned status code %s" % result.returncode,
            )
        return result

    def execute(
        self,
        proposal_id: str,
        selected_action_ids: list[str],
        confirmation: str,
        actor: str = "web",
    ) -> dict[str, Any]:
        with self._lock:
            payload = self.database.get_proposal(proposal_id)
            language = (
                payload.get("plan", {}).get("language")
                if payload
                else detect_language(payload.get("message", "") if payload else "")
            ) or "zh"
            if payload is None:
                raise ExecutionError(
                    _localized(
                        language,
                        "操作计划不存在",
                        "The operation plan does not exist",
                    )
                )
            if payload["status"] != "pending":
                raise ExecutionError(
                    _localized(
                        language,
                        "操作计划已执行、取消或过期",
                        "The operation plan was already executed, cancelled, or expired",
                    )
                )
            if payload["expires_at"] <= time.time():
                self.database.mark_proposal(proposal_id, "expired")
                raise ExecutionError(
                    _localized(
                        language,
                        "操作计划已过期，请重新生成",
                        "The operation plan expired. Generate a new plan",
                    )
                )

            plan = self.engine.rebuild_from_payload(payload)
            language = plan.get("language", language)
            if plan.get("status") != "ready":
                raise ExecutionError(
                    _localized(
                        language,
                        "操作计划已失效，请重新生成",
                        "The operation plan is no longer valid. Generate a new plan",
                    )
                )
            steps = self.engine.select_steps(plan, selected_action_ids)
            if not steps:
                raise ExecutionError(
                    _localized(
                        language,
                        "没有选择要执行的操作",
                        "No operation was selected for execution",
                    )
                )
            expected_phrase = self.engine.resolution_phrase(steps)
            if expected_phrase and confirmation.strip() != expected_phrase:
                raise ExecutionError(
                    _localized(
                        language,
                        "确认语不正确，请输入：%s" % expected_phrase,
                        "Incorrect confirmation phrase. Enter: %s" % expected_phrase,
                    )
                )
            if not expected_phrase and any(step["risk"] != "safe" for step in steps):
                raise ExecutionError(
                    _localized(
                        language,
                        "变更操作必须完成二次确认",
                        "A second confirmation is required for system changes",
                    )
                )

            self.database.mark_proposal(proposal_id, "executing")
            started = time.time()
            results: list[dict[str, Any]] = []
            overall_ok = True
            requires_restart = False
            restart_reasons = []
            for step in steps:
                if step["risk"] != "safe":
                    self.database.insert_audit_event(
                        {
                            "event_key": "agent-%s-%s-%s"
                            % (proposal_id, step["action_id"], int(started)),
                            "source": "agent",
                            "occurred_at": started,
                            "username": actor,
                            "command": " ; ".join(step.get("command_previews", [])),
                            "rule_id": "agent_high_risk_execution",
                            "title_zh": "Agent 执行高风险操作：%s" % step["title_zh"],
                            "severity": "critical"
                            if step["risk"] == "destructive"
                            else "high",
                        }
                    )
                command_results = []
                step_ok = True
                for argv in step["commands"]:
                    result = self.run_argv(
                        argv,
                        accepted_exit_codes=step.get("accepted_exit_codes", [0]),
                        language=language,
                    )
                    command_results.append(result.as_dict())
                    if result.returncode not in set(step.get("accepted_exit_codes", [0])):
                        step_ok = False
                        overall_ok = False
                        break
                if step_ok:
                    action = next(
                        item for item in self.engine.actions if item["id"] == step["action_id"]
                    )
                    for raw_argv in action.get("post_check", []):
                        argv = self.engine._hydrate_argv(raw_argv, step["params"])
                        result = self.run_argv(
                            argv,
                            accepted_exit_codes=[0, 1, 3],
                            language=language,
                        )
                        command_results.append(result.as_dict())
                results.append(
                    {
                        "action_id": step["action_id"],
                        "language": language,
                        "title_zh": step["title_zh"],
                        "title_en": step["title_en"],
                        "title": step["title_en"]
                        if language == "en"
                        else step["title_zh"],
                        "risk": step["risk"],
                        "ok": step_ok,
                        "commands": command_results,
                    }
                )
                if step.get("requires_restart"):
                    requires_restart = True
                    reason = (
                        step.get("restart_reason_en")
                        if language == "en"
                        else step.get("restart_reason_zh")
                    )
                    if reason:
                        restart_reasons.append(reason)
                if not overall_ok:
                    break

            status = "completed" if overall_ok else "failed"
            response = {
                "status": status,
                "language": language,
                "proposal_id": proposal_id,
                "risk": self.engine.proposal_risk(steps),
                "steps": results,
                "requires_restart": requires_restart,
                "restart_reasons": restart_reasons,
                "executed_at": time.time(),
            }
            self.database.mark_proposal(proposal_id, status)
            execution_id = self.database.record_execution(
                proposal_id=proposal_id,
                status=status,
                risk=self.engine.proposal_risk(steps),
                summary=_localized(
                    language,
                    "执行了 %s 个操作步骤" % len(steps),
                    "Executed %s operation step(s)" % len(steps),
                ),
                output=response,
                started_at=started,
            )
            response["execution_id"] = execution_id
            return response
