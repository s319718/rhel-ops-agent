from __future__ import annotations

import json
import os
import platform
import re
import socket
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from .audit import AuditAnalyzer, AuditCollector
from .auth import AuthManager, LoginRateLimiter
from .config import Settings
from .db import Database
from .engine import RuleEngine
from .executor import ExecutionError, Executor
from .llm import HybridPlanner, LLMConfig
from .scanner import ScanManager, VulnerabilityScanner


COOKIE_NAME = "rhel_agent_session"
MAX_BODY_BYTES = 256 * 1024


def _is_loopback(address: str) -> bool:
    return address in {"127.0.0.1", "::1", "localhost"} or address.startswith("127.")


class AgentApplication:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.database = Database(settings.database_path)
        self.engine = RuleEngine(settings.rules_dir)
        self.auth = AuthManager(
            settings.password_path,
            settings.session_secret_path,
            settings.initial_password_path,
            no_auth=settings.no_auth,
        )
        self.initial_password = self.auth.initialize(demo=settings.demo)
        if settings.no_auth and settings.host not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("RHEL_OPS_NO_AUTH 只允许绑定本机地址")
        if settings.demo:
            self.database.seed_demo()
        self.executor = Executor(
            self.engine, self.database, demo=self.settings.demo
        )
        self.planner = HybridPlanner(
            self.engine,
            LLMConfig.from_settings(settings),
        )
        self.audit_analyzer = AuditAnalyzer(settings.rules_dir)
        self.audit_collector = AuditCollector(
            settings, self.database, analyzer=self.audit_analyzer
        )
        self.scan_manager = ScanManager(
            VulnerabilityScanner(settings, self.database), self.database
        )
        self.login_limiter = LoginRateLimiter()

    def start_background(self) -> None:
        self.audit_collector.start()

    def stop_background(self) -> None:
        self.audit_collector.stop()

    def plan_context(self, client_address: str) -> dict[str, Any]:
        return {
            "remote_client": not _is_loopback(client_address),
            "ssh_sessions": 0,
            "client_address": client_address,
        }

    def overview(self, client_address: str) -> dict[str, Any]:
        latest = self.database.latest_scan(include_findings=True)
        audit_counts = self.database.audit_counts(time.time() - 24 * 60 * 60)
        recent_events = self.database.list_audit_events(limit=6)
        system = self.system_facts()
        findings = latest["findings"] if latest else []
        high_findings = sum(
            1 for item in findings if item["severity"] in {"critical", "high"}
        )
        return {
            "agent": {
                "version": "0.1.0",
                "mode": "demo" if self.settings.demo else "live",
                "status": "active",
                "remote_access": not _is_loopback(client_address),
                "nlu": self.planner.public_status(),
            },
            "system": system,
            "risk": {
                "score": latest["summary"].get("score", 0) if latest else None,
                "findings": len(findings),
                "high_findings": high_findings,
                "pending_updates": next(
                    (
                        item["evidence"]
                        for item in findings
                        if item["rule_id"] == "pending_security_updates"
                    ),
                    "未检测",
                ),
            },
            "audit": audit_counts,
            "scan": {
                "id": latest["id"] if latest else None,
                "status": latest["status"] if latest else "never",
                "started_at": latest["started_at"] if latest else None,
                "finished_at": latest["finished_at"] if latest else None,
                "summary": latest["summary"] if latest else None,
            },
            "recent_events": recent_events,
            "templates": [
                {"text": "查看磁盘空间", "category": "storage"},
                {"text": "检查网络配置", "category": "network"},
                {"text": "把系统语言改成中文", "category": "system"},
                {"text": "查看待安装的安全更新", "category": "patch"},
                {"text": "检查 SSH 安全配置", "category": "ssh"},
            ],
        }

    def system_facts(self) -> dict[str, Any]:
        if self.settings.demo:
            return {
                "hostname": "rhel-lab-01",
                "os": "Red Hat Enterprise Linux 9.4",
                "kernel": "5.14.0-427.el9.x86_64",
                "architecture": "x86_64",
                "uptime": "12 days 04:21",
                "logged_in_as_root": False,
            }
        release = ""
        try:
            release = Path("/etc/redhat-release").read_text(encoding="utf-8").strip()
        except OSError:
            pass
        uptime_seconds = 0.0
        try:
            uptime_seconds = float(Path("/proc/uptime").read_text().split()[0])
        except (OSError, ValueError, IndexError):
            pass
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        return {
            "hostname": socket.gethostname(),
            "os": release or platform.platform(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "uptime": "%d days %02d:%02d" % (days, hours, minutes),
            "logged_in_as_root": is_root,
        }


class AgentHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    # SO_REUSEADDR on Windows can allow two processes to bind the same port.
    allow_reuse_address = os.name != "nt"

    def __init__(self, server_address: tuple[str, int], app: AgentApplication):
        self.app = app
        super().__init__(server_address, AgentRequestHandler)


class AgentRequestHandler(BaseHTTPRequestHandler):
    server: AgentHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Do not log request bodies or credentials.
        print(
            "[http] %s - %s"
            % (self.client_address[0], fmt % args),
            flush=True,
        )

    def handle(self) -> None:
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            pass

    @property
    def app(self) -> AgentApplication:
        return self.server.app

    def _send_headers(
        self,
        status: int,
        content_type: str,
        length: int,
        cookies: Optional[list[str]] = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'",
        )
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _json(self, status: int, payload: dict[str, Any], cookies: Optional[list[str]] = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_headers(status, "application/json; charset=utf-8", len(body), cookies)
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("无效的 Content-Length")
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("请求体为空或过大")
        content_type = self.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            raise ValueError("请求必须使用 application/json")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("JSON 格式错误")
        if not isinstance(data, dict):
            raise ValueError("JSON 顶层必须是对象")
        return data

    def _check_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        host = self.headers.get("Host", "")
        return parsed.netloc == host

    def _session_token(self) -> Optional[str]:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        morsel = cookie.get(COOKIE_NAME)
        return morsel.value if morsel else None

    def _authenticated(self) -> bool:
        return self.app.auth.verify_session(self._session_token())

    def _require_auth(self) -> bool:
        if self._authenticated():
            return True
        self._error(HTTPStatus.UNAUTHORIZED, "请先登录")
        return False

    def _static(self, path: str) -> None:
        mapping = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/index.html": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "application/javascript; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
        }
        entry = mapping.get(path)
        if not entry:
            self._error(HTTPStatus.NOT_FOUND, "页面不存在")
            return
        file_path = self.app.settings.web_dir / entry[0]
        try:
            body = file_path.read_bytes()
        except OSError:
            self._error(HTTPStatus.NOT_FOUND, "静态资源不存在")
            return
        self._send_headers(HTTPStatus.OK, entry[1], len(body))
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            self._static(path)
            return
        try:
            if path == "/api/health":
                self._json(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "service": "rhel-ops-agent",
                        "version": "0.1.0",
                        "time": time.time(),
                    },
                )
                return
            if path == "/api/auth/status":
                self._json(
                    HTTPStatus.OK,
                    {
                        "authenticated": self._authenticated(),
                        "no_auth": self.app.settings.no_auth,
                        "demo": self.app.settings.demo,
                    },
                )
                return
            if not self._require_auth():
                return
            if path == "/api/overview":
                self._json(
                    HTTPStatus.OK,
                    self.app.overview(self.client_address[0]),
                )
                return
            if path == "/api/rules":
                rules = self.app.engine.public_rules()
                rules["vulnerability_checks"] = len(
                    self.app.scan_manager.scanner.rules
                )
                rules["audit_patterns"] = len(self.app.audit_analyzer.patterns)
                rules["planner"] = self.app.planner.public_status()
                self._json(HTTPStatus.OK, rules)
                return
            if path == "/api/llm/status":
                self._json(HTTPStatus.OK, self.app.planner.public_status())
                return
            if path == "/api/findings":
                latest = self.app.database.latest_scan(include_findings=True)
                self._json(
                    HTTPStatus.OK,
                    {
                        "scan": None
                        if not latest
                        else {
                            "id": latest["id"],
                            "status": latest["status"],
                            "started_at": latest["started_at"],
                            "finished_at": latest["finished_at"],
                            "summary": latest["summary"],
                        },
                        "findings": latest["findings"] if latest else [],
                    },
                )
                return
            if path == "/api/scan/latest":
                self._json(
                    HTTPStatus.OK,
                    {"scan": self.app.database.latest_scan(include_findings=True)},
                )
                return
            if path.startswith("/api/scans/"):
                scan_id = path.rsplit("/", 1)[-1]
                scan = self.app.database.get_scan(scan_id, include_findings=True)
                if not scan:
                    self._error(HTTPStatus.NOT_FOUND, "巡检任务不存在")
                    return
                self._json(HTTPStatus.OK, {"scan": scan})
                return
            if path == "/api/audit":
                query = parse_qs(parsed.query)
                limit = int(query.get("limit", ["100"])[0])
                events = self.app.database.list_audit_events(limit=limit)
                self._json(
                    HTTPStatus.OK,
                    {
                        "events": events,
                        "last_run": self.app.audit_collector.last_run,
                    },
                )
                return
            self._error(HTTPStatus.NOT_FOUND, "接口不存在")
        except Exception as exc:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if not self._check_origin():
            self._error(HTTPStatus.FORBIDDEN, "请求来源校验失败")
            return
        try:
            body = self._read_json()
            if path == "/api/auth/login":
                self._login(body)
                return
            if path == "/api/auth/logout":
                self._json(
                    HTTPStatus.OK,
                    {"ok": True},
                    cookies=[
                        "%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
                        % COOKIE_NAME
                    ],
                )
                return
            if not self._require_auth():
                return
            if path == "/api/plan":
                message = str(body.get("message", "")).strip()
                overrides = body.get("overrides") or {}
                if not isinstance(overrides, dict):
                    raise ValueError("overrides 格式错误")
                context = self.app.plan_context(self.client_address[0])
                plan = self.app.planner.plan(
                    message,
                    overrides=overrides,
                    context=context,
                )
                proposal_id = None
                if plan.get("status") == "ready":
                    payload = self.app.engine.plan_payload(message, plan, context)
                    proposal_id = self.app.database.create_proposal(
                        payload, self.app.settings.proposal_ttl_seconds
                    )
                if plan.get("status") == "blocked":
                    blocked = plan["blocked"]
                    self.app.database.insert_audit_event(
                        {
                            "event_key": "blocked-%s-%s"
                            % (blocked["id"], int(time.time() // 5)),
                            "source": "planner",
                            "occurred_at": time.time(),
                            "username": "web",
                            "command": message[:2000],
                            "rule_id": blocked["id"],
                            "title_zh": "Agent 已拦截：%s" % blocked["title_zh"],
                            "severity": blocked.get("severity", "critical"),
                        }
                    )
                self._json(
                    HTTPStatus.OK,
                    {"plan": plan, "proposal_id": proposal_id},
                )
                return
            if path == "/api/execute":
                proposal_id = str(body.get("proposal_id", ""))
                selected = body.get("selected_action_ids") or []
                confirmation = str(body.get("confirmation", ""))
                if not isinstance(selected, list) or not all(
                    isinstance(item, str) for item in selected
                ):
                    raise ValueError("selected_action_ids 格式错误")
                result = self.app.executor.execute(
                    proposal_id,
                    selected,
                    confirmation,
                    actor="web",
                )
                self._json(HTTPStatus.OK, {"result": result})
                return
            if path == "/api/scan":
                result = self.app.scan_manager.start()
                self._json(HTTPStatus.ACCEPTED, result)
                return
            if path == "/api/audit/refresh":
                result = self.app.audit_collector.scan_once()
                self._json(HTTPStatus.OK, result)
                return
            match = re.fullmatch(r"/api/audit/(\d+)/ack", path)
            if match:
                ok = self.app.database.acknowledge_audit_event(int(match.group(1)))
                self._json(HTTPStatus.OK, {"ok": ok})
                return
            if path == "/api/lab/simulate":
                if not _is_loopback(self.client_address[0]):
                    self._error(HTTPStatus.FORBIDDEN, "模拟接口仅允许本机访问")
                    return
                command = str(body.get("command", "")).strip()
                if not command:
                    raise ValueError("command 不能为空")
                inserted = self.app.audit_collector.inject_simulation(command)
                self._json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "detected": inserted,
                        "note": "仅写入模拟审计事件，没有执行命令",
                    },
                )
                return
            self._error(HTTPStatus.NOT_FOUND, "接口不存在")
        except ExecutionError as exc:
            self._error(HTTPStatus.CONFLICT, str(exc))
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def _login(self, body: dict[str, Any]) -> None:
        client = self.client_address[0]
        if not self.app.login_limiter.allowed(client):
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "登录失败次数过多，请稍后再试")
            return
        password = str(body.get("password", ""))
        if not self.app.auth.verify_password(password):
            self.app.login_limiter.fail(client)
            self._error(HTTPStatus.UNAUTHORIZED, "密码不正确")
            return
        self.app.login_limiter.success(client)
        token = self.app.auth.issue_session()
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        cookie = (
            "%s=%s; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict%s"
            % (COOKIE_NAME, token, secure)
        )
        self._json(HTTPStatus.OK, {"authenticated": True}, cookies=[cookie])


def run_server(app: AgentApplication) -> None:
    server = AgentHTTPServer((app.settings.host, app.settings.port), app)
    app.start_background()
    print(
        "RHEL Ops Agent listening on http://%s:%d (mode=%s)"
        % (app.settings.host, app.settings.port, "demo" if app.settings.demo else "live"),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.stop_background()
