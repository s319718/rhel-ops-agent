from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS proposals (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS executions (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL,
    risk TEXT NOT NULL,
    summary TEXT NOT NULL,
    output TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title_zh TEXT NOT NULL,
    title_en TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    detail TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scan_runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_key TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    occurred_at REAL NOT NULL,
    detected_at REAL NOT NULL,
    username TEXT NOT NULL,
    command TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title_zh TEXT NOT NULL,
    severity TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_audit_detected ON audit_events(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_events(severity);

CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._schema_lock = threading.Lock()
        self.initialize()

    def initialize(self) -> None:
        with self._schema_lock:
            with self.connect() as connection:
                connection.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def create_proposal(self, payload: dict[str, Any], ttl_seconds: int) -> str:
        proposal_id = uuid.uuid4().hex
        now = time.time()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO proposals(id, created_at, expires_at, status, payload)
                VALUES (?, ?, ?, 'pending', ?)
                """,
                (proposal_id, now, now + ttl_seconds, json.dumps(payload, ensure_ascii=False)),
            )
        return proposal_id

    def update_proposal(self, proposal_id: str, payload: dict[str, Any]) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE proposals SET payload = ?
                WHERE id = ? AND status = 'pending' AND expires_at > ?
                """,
                (json.dumps(payload, ensure_ascii=False), proposal_id, time.time()),
            )
            return cursor.rowcount == 1

    def get_proposal(self, proposal_id: str) -> Optional[dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM proposals WHERE id = ?", (proposal_id,)
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload"])
        payload["id"] = row["id"]
        payload["created_at"] = row["created_at"]
        payload["expires_at"] = row["expires_at"]
        payload["status"] = row["status"]
        return payload

    def mark_proposal(self, proposal_id: str, status: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE proposals SET status = ? WHERE id = ?", (status, proposal_id)
            )

    def record_execution(
        self,
        proposal_id: str,
        status: str,
        risk: str,
        summary: str,
        output: dict[str, Any],
        started_at: float,
    ) -> str:
        execution_id = uuid.uuid4().hex
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO executions(
                    id, proposal_id, started_at, finished_at, status, risk, summary, output
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    execution_id,
                    proposal_id,
                    started_at,
                    time.time(),
                    status,
                    risk,
                    summary,
                    json.dumps(output, ensure_ascii=False),
                ),
            )
        return execution_id

    def create_scan(self) -> str:
        scan_id = uuid.uuid4().hex
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO scan_runs(id, started_at, status, summary, error)
                VALUES (?, ?, 'running', '{}', '')
                """,
                (scan_id, time.time()),
            )
        return scan_id

    def finish_scan(
        self,
        scan_id: str,
        findings: list[dict[str, Any]],
        summary: dict[str, Any],
        error: str = "",
    ) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            for finding in findings:
                connection.execute(
                    """
                    INSERT INTO findings(
                        scan_id, rule_id, title_zh, title_en, severity, category,
                        detail, evidence, remediation
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        finding["rule_id"],
                        finding["title_zh"],
                        finding["title_en"],
                        finding["severity"],
                        finding["category"],
                        finding["detail"],
                        finding["evidence"],
                        finding["remediation"],
                    ),
                )
            connection.execute(
                """
                UPDATE scan_runs
                SET finished_at = ?, status = ?, summary = ?, error = ?
                WHERE id = ?
                """,
                (
                    time.time(),
                    "failed" if error else "completed",
                    json.dumps(summary, ensure_ascii=False),
                    error,
                    scan_id,
                ),
            )

    def get_scan(self, scan_id: str, include_findings: bool = True) -> Optional[dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM scan_runs WHERE id = ?", (scan_id,)
            ).fetchone()
            if row is None:
                return None
            findings = []
            if include_findings:
                findings = [
                    dict(item)
                    for item in connection.execute(
                        """
                        SELECT * FROM findings WHERE scan_id = ?
                        ORDER BY CASE severity
                            WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                            WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                            id
                        """,
                        (scan_id,),
                    ).fetchall()
                ]
        return {
            **dict(row),
            "summary": json.loads(row["summary"]),
            "findings": findings,
        }

    def latest_scan(self, include_findings: bool = True) -> Optional[dict[str, Any]]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id FROM scan_runs ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
        return self.get_scan(row["id"], include_findings) if row else None

    def insert_audit_event(self, event: dict[str, Any]) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO audit_events(
                    event_key, source, occurred_at, detected_at, username,
                    command, rule_id, title_zh, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_key"],
                    event["source"],
                    event["occurred_at"],
                    event.get("detected_at", time.time()),
                    event.get("username", "unknown"),
                    event["command"],
                    event["rule_id"],
                    event["title_zh"],
                    event["severity"],
                ),
            )
            return cursor.rowcount == 1

    def list_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events ORDER BY detected_at DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def acknowledge_audit_event(self, event_id: int) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE audit_events SET acknowledged = 1 WHERE id = ?", (event_id,)
            )
            return cursor.rowcount == 1

    def audit_counts(self, since: float) -> dict[str, int]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT severity, COUNT(*) AS count
                FROM audit_events WHERE detected_at >= ?
                GROUP BY severity
                """,
                (since,),
            ).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row in rows:
            counts[row["severity"]] = row["count"]
        counts["total"] = sum(counts.values())
        counts["unacknowledged"] = self._unacknowledged_count(since)
        return counts

    def _unacknowledged_count(self, since: float) -> int:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count FROM audit_events
                WHERE detected_at >= ? AND acknowledged = 0
                """,
                (since,),
            ).fetchone()
        return int(row["count"])

    def state_get(self, key: str, default: Any = None) -> Any:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT value FROM app_state WHERE key = ?", (key,)
            ).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default

    def state_set(self, key: str, value: Any) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO app_state(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, json.dumps(value, ensure_ascii=False)),
            )

    def seed_demo(self) -> None:
        now = time.time()
        events = [
            {
                "event_key": "demo-audit-1",
                "source": "demo",
                "occurred_at": now - 420,
                "username": "root",
                "command": "rm -rf /var/tmp/payment-cache",
                "rule_id": "recursive_force_delete",
                "title_zh": "递归强制删除文件",
                "severity": "critical",
            },
            {
                "event_key": "demo-audit-2",
                "source": "demo",
                "occurred_at": now - 2100,
                "username": "admin",
                "command": "systemctl stop firewalld",
                "rule_id": "disable_firewall",
                "title_zh": "停止主机防火墙",
                "severity": "high",
            },
            {
                "event_key": "demo-audit-3",
                "source": "demo",
                "occurred_at": now - 5300,
                "username": "ops",
                "command": "setenforce 0",
                "rule_id": "disable_selinux",
                "title_zh": "临时关闭 SELinux",
                "severity": "high",
            },
        ]
        for event in events:
            self.insert_audit_event(event)

        if self.latest_scan(include_findings=False) is None:
            scan_id = self.create_scan()
            findings = [
                {
                    "rule_id": "sshd_root_login",
                    "title_zh": "SSH 允许 root 直接登录",
                    "title_en": "SSH root login is enabled",
                    "severity": "high",
                    "category": "ssh",
                    "detail": "PermitRootLogin 当前为 yes。",
                    "evidence": "permitrootlogin yes",
                    "remediation": "将 /etc/ssh/sshd_config 中的 PermitRootLogin 改为 no。",
                },
                {
                    "rule_id": "firewalld_inactive",
                    "title_zh": "firewalld 未运行",
                    "title_en": "firewalld is inactive",
                    "severity": "high",
                    "category": "firewall",
                    "detail": "主机防火墙服务未处于 active 状态。",
                    "evidence": "inactive",
                    "remediation": "执行 systemctl enable --now firewalld。",
                },
                {
                    "rule_id": "pending_security_updates",
                    "title_zh": "存在待安装的安全更新",
                    "title_en": "Security updates are pending",
                    "severity": "medium",
                    "category": "patch",
                    "detail": "检测到 11 个安全更新包。",
                    "evidence": "11 security packages",
                    "remediation": "安排维护窗口并执行 dnf update --security。",
                },
                {
                    "rule_id": "auditd_inactive",
                    "title_zh": "auditd 未运行",
                    "title_en": "auditd is inactive",
                    "severity": "medium",
                    "category": "audit",
                    "detail": "系统审计服务未运行，关键操作追溯能力下降。",
                    "evidence": "inactive",
                    "remediation": "执行 systemctl enable --now auditd。",
                },
                {
                    "rule_id": "password_no_expiry",
                    "title_zh": "部分账户密码永不过期",
                    "title_en": "Some passwords never expire",
                    "severity": "low",
                    "category": "account",
                    "detail": "检测到 2 个人类账户未设置密码最长使用期限。",
                    "evidence": "alice, deploy",
                    "remediation": "使用 chage -M 365 <用户名> 设置最长使用期限。",
                },
            ]
            self.finish_scan(
                scan_id,
                findings,
                {
                    "total": 5,
                    "critical": 0,
                    "high": 2,
                    "medium": 2,
                    "low": 1,
                    "score": 64,
                },
            )
