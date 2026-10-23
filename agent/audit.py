from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Optional

from .config import Settings
from .db import Database

try:
    import pwd
except ImportError:  # Windows development/demo environment
    pwd = None


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
AUDIT_KEY = "rhel_ops_agent"
MAX_CHUNK = 512 * 1024


def _event_key(
    source: str, command: str, username: str, occurred_at: float
) -> str:
    raw = "%s|%s|%s|%s" % (
        source,
        command,
        username,
        int(occurred_at // 5),
    )
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _redact_command(command: str) -> str:
    command = re.sub(
        r"(?i)(--?(?:password|passwd|token|secret)[=\s]+)([^\s]+)",
        r"\1[REDACTED]",
        command,
    )
    command = re.sub(r"(?i)(https?://[^:/\s]+:)[^@\s]+@", r"\1[REDACTED]@", command)
    command = re.sub(
        r"(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9._~+/=-]+",
        r"\1[REDACTED]",
        command,
    )
    return command[:2000]


def _decode_audit_arg(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1].replace('\\"', '"')
    if re.fullmatch(r"[0-9A-Fa-f]+", raw) and len(raw) % 2 == 0:
        try:
            return bytes.fromhex(raw).decode("utf-8", errors="replace")
        except ValueError:
            return raw
    return raw


class AuditAnalyzer:
    def __init__(self, rules_dir: Path):
        items = []
        for filename in ("audit_patterns.json", "extra_audit_patterns.json"):
            path = Path(rules_dir) / filename
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            items.extend(data.get("patterns", []))
        seen = set()
        self.patterns = []
        for item in items:
            if item["id"] in seen:
                raise ValueError("Duplicate audit rule id: %s" % item["id"])
            seen.add(item["id"])
            self.patterns.append(
                {
                    **item,
                    "_compiled": [
                        re.compile(pattern, re.IGNORECASE)
                        for pattern in item.get("patterns", [])
                    ],
                }
            )

    def classify(self, command: str) -> Optional[dict[str, Any]]:
        matches = []
        for item in self.patterns:
            for pattern in item["_compiled"]:
                found = pattern.search(command)
                if found:
                    matches.append(
                        (
                            SEVERITY_ORDER.get(item.get("severity", "medium"), 1),
                            len(found.group(0)),
                            item,
                        )
                    )
        if not matches:
            return None
        matches.sort(key=lambda item: (item[0], item[1]), reverse=True)
        selected = matches[0][2]
        return {
            "rule_id": selected["id"],
            "title_zh": selected.get("title_zh", "高风险命令"),
            "severity": selected.get("severity", "medium"),
        }


class AuditCollector:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        analyzer: Optional[AuditAnalyzer] = None,
    ):
        self.settings = settings
        self.database = database
        self.analyzer = analyzer or AuditAnalyzer(settings.rules_dir)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._pending_audit: dict[str, dict[str, Any]] = {}
        self._state = self._load_state()
        self.last_run: Optional[float] = None
        self.last_inserted = 0

    def _load_state(self) -> dict[str, Any]:
        try:
            return json.loads(self.settings.audit_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"files": {}}

    def _save_state(self) -> None:
        temporary = self.settings.audit_state_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(self._state, ensure_ascii=False), encoding="utf-8"
        )
        os.replace(temporary, self.settings.audit_state_path)

    def start(self) -> None:
        if self.settings.demo:
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="rhel-audit-collector", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _loop(self) -> None:
        self.scan_once()
        while not self._stop.wait(self.settings.audit_poll_seconds):
            self.scan_once()

    def _record(self, source: str, command: str, username: str, occurred_at: float) -> bool:
        command = _redact_command(command.strip())
        if not command:
            return False
        match = self.analyzer.classify(command)
        if not match:
            return False
        return self.database.insert_audit_event(
            {
                "event_key": _event_key(source, command, username, occurred_at),
                "source": source,
                "occurred_at": occurred_at,
                "detected_at": time.time(),
                "username": username,
                "command": command,
                "rule_id": match["rule_id"],
                "title_zh": match["title_zh"],
                "severity": match["severity"],
            }
        )

    def scan_once(self) -> dict[str, Any]:
        if self.settings.demo:
            return {"inserted": 0, "sources": {}, "demo": True}
        with self._lock:
            inserted = 0
            sources = {"auditd": 0, "history": 0, "secure": 0}
            audit_path = Path("/var/log/audit/audit.log")
            inserted += self._scan_audit_log(audit_path)
            sources["auditd"] = inserted
            secure_inserted = self._scan_secure_log(Path("/var/log/secure"))
            inserted += secure_inserted
            sources["secure"] = secure_inserted
            history_inserted = self._scan_history_files()
            inserted += history_inserted
            sources["history"] = history_inserted
            self._save_state()
            self.last_run = time.time()
            self.last_inserted = inserted
            return {"inserted": inserted, "sources": sources}

    def _file_state(self, path: Path) -> dict[str, Any]:
        files = self._state.setdefault("files", {})
        return files.setdefault(str(path), {})

    def _read_new_bytes(self, path: Path, initial_tail: int = MAX_CHUNK) -> bytes:
        try:
            stat_result = path.stat()
        except OSError:
            return b""
        state = self._file_state(path)
        inode = int(stat_result.st_ino)
        previous_inode = state.get("inode")
        previous_offset = int(state.get("offset", 0))
        if previous_inode != inode:
            offset = max(0, stat_result.st_size - initial_tail)
        else:
            offset = min(max(previous_offset, 0), stat_result.st_size)
        if stat_result.st_size < offset:
            offset = 0
        try:
            with path.open("rb") as handle:
                handle.seek(offset)
                data = handle.read(MAX_CHUNK)
        except OSError:
            return b""
        state["inode"] = inode
        state["offset"] = offset + len(data)
        return data

    def _scan_history_files(self) -> int:
        inserted = 0
        paths = [Path("/root/.bash_history"), Path("/root/.zsh_history")]
        for home in Path("/home").glob("*"):
            if home.is_dir():
                paths.append(home / ".bash_history")
                paths.append(home / ".zsh_history")
        for path in paths:
            if not path.is_file():
                continue
            state = self._file_state(path)
            first_read = "inode" not in state
            data = self._read_new_bytes(path, initial_tail=128 * 1024)
            if not data:
                continue
            text = data.decode("utf-8", errors="replace")
            lines = text.splitlines()
            if first_read:
                lines = lines[-500:]
            username = path.parent.name if path.parent != Path("/root") else "root"
            occurred = path.stat().st_mtime if path.exists() else time.time()
            for line in lines:
                command = line.strip()
                if command.startswith(": ") and ";" in command:
                    command = command.split(";", 1)[1]
                if self._record("history", command, username, occurred):
                    inserted += 1
        return inserted

    def _scan_secure_log(self, path: Path) -> int:
        if not path.is_file():
            return 0
        data = self._read_new_bytes(path)
        if not data:
            return 0
        inserted = 0
        for line in data.decode("utf-8", errors="replace").splitlines():
            if "COMMAND=" not in line:
                continue
            command = line.split("COMMAND=", 1)[1].strip()
            user_match = re.search(r"\bsudo:\s+(\S+)\s+:", line)
            username = user_match.group(1) if user_match else "sudo"
            if self._record("secure", command, username, time.time()):
                inserted += 1
        return inserted

    def _scan_audit_log(self, path: Path) -> int:
        if not path.is_file():
            return 0
        data = self._read_new_bytes(path)
        if not data:
            return 0
        inserted = 0
        now = time.time()
        for line in data.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            audit_match = re.search(r"msg=audit\(([^)]+)\)", line)
            if not audit_match:
                continue
            event_id = audit_match.group(1)
            pending = self._pending_audit.setdefault(event_id, {})
            if "type=SYSCALL" in line:
                key_match = re.search(r'\bkey="([^"]+)"', line)
                if key_match:
                    pending["key"] = key_match.group(1)
                exe_match = re.search(r'\bexe="([^"]+)"', line)
                if exe_match:
                    pending["exe"] = exe_match.group(1)
                uid_match = re.search(r"\buid=(\d+)", line)
                auid_match = re.search(r"\bauid=(\d+)", line)
                pending["uid"] = (
                    auid_match.group(1)
                    if auid_match and auid_match.group(1) != "4294967295"
                    else uid_match.group(1)
                    if uid_match
                    else "0"
                )
                timestamp_match = re.search(r"msg=audit\((\d+(?:\.\d+)?):", line)
                pending["timestamp"] = (
                    float(timestamp_match.group(1)) if timestamp_match else now
                )
            elif "type=EXECVE" in line:
                args = []
                for match in re.finditer(r"\ba(\d+)=(\"[^\"]*\"|[^\s]+)", line):
                    args.append((int(match.group(1)), _decode_audit_arg(match.group(2))))
                if args:
                    pending["args"] = [value for _, value in sorted(args)]
            elif "type=PROCTITLE" in line and "args" not in pending:
                title_match = re.search(r"\bproctitle=([0-9A-Fa-f]+)", line)
                if title_match:
                    try:
                        decoded = bytes.fromhex(title_match.group(1)).decode(
                            "utf-8", errors="replace"
                        )
                        pending["args"] = decoded.split("\x00")
                    except ValueError:
                        pass
            if pending.get("key") == AUDIT_KEY and pending.get("args"):
                command = " ".join(pending["args"]).strip()
                uid = pending.get("uid", "0")
                try:
                    username = (
                        pwd.getpwuid(int(uid)).pw_name
                        if pwd is not None
                        else "uid=%s" % uid
                    )
                except (KeyError, ValueError, OverflowError):
                    username = "uid=%s" % uid
                occurred = float(pending.get("timestamp", now))
                if self._record("auditd", command, username, occurred):
                    inserted += 1
                pending["args"] = []
                pending["completed"] = True
        if len(self._pending_audit) > 1000:
            ordered = sorted(
                self._pending_audit.items(),
                key=lambda item: float(item[1].get("timestamp", 0)),
                reverse=True,
            )
            self._pending_audit = dict(ordered[:500])
        return inserted

    def inject_simulation(self, command: str, username: str = "simulation") -> bool:
        return self._record("simulation", command, username, time.time())

