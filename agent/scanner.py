from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from .config import Settings
from .db import Database


SEVERITY_WEIGHTS = {"critical": 22, "high": 12, "medium": 6, "low": 2}


@dataclass
class CommandResult:
    returncode: int
    output: str


@dataclass
class CheckResult:
    status: str
    detail: str = ""
    evidence: str = ""


def _read_text(path: str) -> Optional[str]:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def _run(argv: list[str], timeout: int) -> CommandResult:
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/root",
    }
    try:
        completed = subprocess.run(
            argv,
            shell=False,
            cwd="/",
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        output = (completed.stdout or "").strip()
        return CommandResult(completed.returncode, output[:12_000])
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return CommandResult(127, str(exc))
    except subprocess.TimeoutExpired:
        return CommandResult(124, "command timed out")


def _service_active(name: str, timeout: int) -> Optional[bool]:
    if not shutil.which("systemctl"):
        return None
    result = _run(["systemctl", "is-active", name], timeout)
    if result.returncode == 0:
        return True
    if result.returncode in {3, 4} or result.output in {"inactive", "failed", "unknown"}:
        return False
    return None


def _sshd_effective(timeout: int) -> dict[str, str]:
    if not shutil.which("sshd"):
        return {}
    result = _run(["sshd", "-T"], timeout)
    values = {}
    if result.returncode == 0:
        for line in result.output.splitlines():
            if " " in line:
                key, value = line.split(None, 1)
                values[key.lower()] = value.strip()
    return values


def _parse_shadow() -> tuple[dict[int, str], Optional[dict[str, list[str]]]]:
    passwd_text = _read_text("/etc/passwd")
    shadow_text = _read_text("/etc/shadow")
    users = {}
    if passwd_text:
        for line in passwd_text.splitlines():
            fields = line.split(":")
            if len(fields) >= 4:
                try:
                    users[int(fields[2])] = fields[0]
                except ValueError:
                    continue
    shadow = {}
    if shadow_text:
        for line in shadow_text.splitlines():
            fields = line.split(":")
            if len(fields) >= 8:
                shadow[fields[0]] = fields
    return users, shadow if shadow_text is not None else None


class VulnerabilityScanner:
    def __init__(self, settings: Settings, database: Database):
        self.settings = settings
        self.database = database
        rules_path = settings.rules_dir / "vulnerabilities.json"
        with rules_path.open("r", encoding="utf-8") as handle:
            self.rules = json.load(handle)["checks"]
        self.rule_map = {rule["id"]: rule for rule in self.rules}
        self.checkers: dict[str, Callable[[], CheckResult]] = {
            "selinux_not_enforcing": self._selinux_not_enforcing,
            "firewalld_inactive": self._firewalld_inactive,
            "sshd_root_login": self._sshd_root_login,
            "sshd_password_auth": self._sshd_password_auth,
            "sshd_empty_password": self._sshd_empty_password,
            "sshd_max_auth_tries": self._sshd_max_auth_tries,
            "sshd_weak_crypto": self._sshd_weak_crypto,
            "firewalld_trusted_zone": self._firewalld_trusted_zone,
            "pending_security_updates": self._pending_security_updates,
            "dnf_gpgcheck_disabled": self._dnf_gpgcheck_disabled,
            "chronyd_inactive": self._chronyd_inactive,
            "auditd_inactive": self._auditd_inactive,
            "rsyslog_inactive": self._rsyslog_inactive,
            "password_no_expiry": self._password_no_expiry,
            "uid_zero_duplicate": self._uid_zero_duplicate,
            "empty_password_accounts": self._empty_password_accounts,
            "sudo_nopasswd": self._sudo_nopasswd,
            "sensitive_world_writable": self._sensitive_world_writable,
            "tmp_missing_isolation": self._tmp_missing_isolation,
            "crypto_policy_legacy": self._crypto_policy_legacy,
            "aslr_disabled": self._aslr_disabled,
            "ip_forwarding_enabled": self._ip_forwarding_enabled,
            "core_dump_suid_enabled": self._core_dump_suid_enabled,
            "nfs_exports_wildcard": self._nfs_exports_wildcard,
            "telnet_server_installed": self._telnet_server_installed,
            "ftp_server_installed": self._ftp_server_installed,
            "dnf_automatic_disabled": self._dnf_automatic_disabled,
            "usbguard_absent": self._usbguard_absent,
            "aide_absent": self._aide_absent,
            "journald_volatile": self._journald_volatile,
        }

    def _timeout(self) -> int:
        return self.settings.scan_timeout_seconds

    def _selinux_not_enforcing(self) -> CheckResult:
        if not shutil.which("getenforce"):
            return CheckResult("skipped", "getenforce not found")
        result = _run(["getenforce"], self._timeout())
        if result.returncode != 0:
            return CheckResult("skipped", result.output)
        if result.output.strip() != "Enforcing":
            return CheckResult("vulnerable", "SELinux 当前模式不是 Enforcing。", result.output)
        return CheckResult("ok", evidence=result.output)

    def _firewalld_inactive(self) -> CheckResult:
        active = _service_active("firewalld", self._timeout())
        if active is None:
            return CheckResult("skipped", "systemctl unavailable")
        return (
            CheckResult("vulnerable", "firewalld 未运行。", "inactive")
            if not active
            else CheckResult("ok")
        )

    def _sshd_root_login(self) -> CheckResult:
        config = _sshd_effective(self._timeout())
        value = config.get("permitrootlogin")
        if value is None:
            return CheckResult("skipped", "sshd effective config unavailable")
        if value.lower() in {"yes", "without-password", "prohibit-password"}:
            return CheckResult("vulnerable", "PermitRootLogin 允许 root 登录。", value)
        return CheckResult("ok", evidence=value)

    def _sshd_password_auth(self) -> CheckResult:
        config = _sshd_effective(self._timeout())
        value = config.get("passwordauthentication")
        if value is None:
            return CheckResult("skipped", "sshd effective config unavailable")
        if value.lower() == "yes":
            return CheckResult("vulnerable", "SSH 密码认证已启用。", value)
        return CheckResult("ok", evidence=value)

    def _sshd_empty_password(self) -> CheckResult:
        config = _sshd_effective(self._timeout())
        value = config.get("permitemptypasswords")
        if value is None:
            return CheckResult("skipped", "sshd effective config unavailable")
        if value.lower() == "yes":
            return CheckResult("vulnerable", "SSH 允许空密码。", value)
        return CheckResult("ok", evidence=value)

    def _sshd_max_auth_tries(self) -> CheckResult:
        config = _sshd_effective(self._timeout())
        value = config.get("maxauthtries")
        if value is None:
            return CheckResult("skipped", "sshd effective config unavailable")
        try:
            attempts = int(value)
        except ValueError:
            return CheckResult("skipped", value)
        if attempts > 4:
            return CheckResult("vulnerable", "MaxAuthTries 大于 4。", value)
        return CheckResult("ok", evidence=value)

    def _sshd_weak_crypto(self) -> CheckResult:
        config = _sshd_effective(self._timeout())
        if not config:
            return CheckResult("skipped", "sshd effective config unavailable")
        weak = re.compile(r"(3des|arcfour|rc4|hmac-md5|diffie-hellman-group1)", re.IGNORECASE)
        evidence = []
        for key in ("ciphers", "macs", "kexalgorithms"):
            value = config.get(key, "")
            if weak.search(value):
                evidence.append("%s=%s" % (key, value))
        if evidence:
            return CheckResult("vulnerable", "SSH 配置包含弱算法。", " | ".join(evidence))
        return CheckResult("ok")

    def _firewalld_trusted_zone(self) -> CheckResult:
        if not shutil.which("firewall-cmd"):
            return CheckResult("skipped", "firewall-cmd not found")
        result = _run(["firewall-cmd", "--get-default-zone"], self._timeout())
        if result.returncode != 0:
            return CheckResult("skipped", result.output)
        if result.output.strip() == "trusted":
            return CheckResult("vulnerable", "默认区域为 trusted。", result.output)
        return CheckResult("ok", evidence=result.output)

    def _pending_security_updates(self) -> CheckResult:
        if not shutil.which("dnf"):
            return CheckResult("skipped", "dnf not found")
        result = _run(["dnf", "-q", "check-update", "--security"], self._timeout())
        if result.returncode in {0, 1} and not result.output.strip():
            return CheckResult("ok", evidence="no security updates")
        if result.returncode == 100 or re.search(r"^\S+\.\S+\s+\S+", result.output, re.MULTILINE):
            package_lines = [
                line
                for line in result.output.splitlines()
                if re.match(r"^\S+\.\S+\s+\S+", line)
            ]
            count = len(package_lines)
            evidence = "%s security packages" % count if count else result.output[:1000]
            return CheckResult("vulnerable", "存在待安装的安全更新。", evidence)
        return CheckResult("skipped", result.output or "dnf metadata unavailable")

    def _dnf_gpgcheck_disabled(self) -> CheckResult:
        paths = ["/etc/dnf/dnf.conf", "/etc/yum.conf"]
        evidence = []
        for path in paths:
            text = _read_text(path)
            if not text:
                continue
            for line in text.splitlines():
                if re.match(r"^\s*(repo_)?gpgcheck\s*=\s*0\b", line, re.IGNORECASE):
                    evidence.append("%s: %s" % (path, line.strip()))
        if evidence:
            return CheckResult("vulnerable", "软件包签名校验被关闭。", " | ".join(evidence))
        return CheckResult("ok")

    def _chronyd_inactive(self) -> CheckResult:
        return self._inactive_service("chronyd")

    def _auditd_inactive(self) -> CheckResult:
        return self._inactive_service("auditd")

    def _rsyslog_inactive(self) -> CheckResult:
        return self._inactive_service("rsyslog")

    def _inactive_service(self, service: str) -> CheckResult:
        active = _service_active(service, self._timeout())
        if active is None:
            return CheckResult("skipped", "systemctl unavailable")
        if not active:
            return CheckResult("vulnerable", "%s 未运行。" % service, "inactive")
        return CheckResult("ok")

    def _password_no_expiry(self) -> CheckResult:
        users, shadow = _parse_shadow()
        if shadow is None:
            return CheckResult("skipped", "/etc/shadow is not readable")
        affected = []
        for username, fields in shadow.items():
            uid = next((key for key, value in users.items() if value == username), None)
            if uid is None or uid < 1000 or uid == 65534:
                continue
            max_days = fields[4]
            if not max_days or max_days == "99999":
                affected.append(username)
        if affected:
            return CheckResult("vulnerable", "部分人类账户未设置密码最长使用期限。", ", ".join(affected[:30]))
        return CheckResult("ok")

    def _uid_zero_duplicate(self) -> CheckResult:
        text = _read_text("/etc/passwd")
        if text is None:
            return CheckResult("skipped", "/etc/passwd is not readable")
        users = []
        for line in text.splitlines():
            fields = line.split(":")
            if len(fields) >= 3 and fields[2] == "0":
                users.append(fields[0])
        if len(users) > 1:
            return CheckResult("vulnerable", "存在多个 UID 0 账户。", ", ".join(users))
        return CheckResult("ok")

    def _empty_password_accounts(self) -> CheckResult:
        _, shadow = _parse_shadow()
        if shadow is None:
            return CheckResult("skipped", "/etc/shadow is not readable")
        accounts = [name for name, fields in shadow.items() if fields[1] == ""]
        if accounts:
            return CheckResult("vulnerable", "存在空密码账户。", ", ".join(accounts))
        return CheckResult("ok")

    def _sudo_nopasswd(self) -> CheckResult:
        paths = [Path("/etc/sudoers"), Path("/etc/sudoers.d")]
        files = []
        for path in paths:
            if path.is_file():
                files.append(path)
            elif path.is_dir():
                files.extend(item for item in path.iterdir() if item.is_file())
        matches = []
        for path in files:
            text = _read_text(str(path))
            if text and re.search(r"NOPASSWD\s*:", text, re.IGNORECASE):
                matches.append(path.name)
        if matches:
            return CheckResult("vulnerable", "sudoers 中存在免密规则。", ", ".join(matches))
        return CheckResult("ok")

    def _sensitive_world_writable(self) -> CheckResult:
        paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
        ]
        evidence = []
        for path in paths:
            try:
                mode = os.stat(path).st_mode
            except OSError:
                continue
            if mode & stat.S_IWOTH:
                evidence.append("%s mode=%04o" % (path, stat.S_IMODE(mode)))
        if evidence:
            return CheckResult("vulnerable", "敏感文件可被其他用户写入。", " | ".join(evidence))
        return CheckResult("ok")

    def _tmp_missing_isolation(self) -> CheckResult:
        if not shutil.which("findmnt"):
            return CheckResult("skipped", "findmnt not found")
        result = _run(["findmnt", "-no", "OPTIONS", "/tmp"], self._timeout())
        if result.returncode != 0:
            return CheckResult("skipped", result.output)
        options = set(result.output.strip().split(","))
        missing = [option for option in ("nodev", "nosuid") if option not in options]
        if missing:
            return CheckResult("vulnerable", "/tmp 缺少隔离挂载选项。", "missing=" + ",".join(missing))
        return CheckResult("ok", evidence=result.output)

    def _crypto_policy_legacy(self) -> CheckResult:
        if not shutil.which("update-crypto-policies"):
            return CheckResult("skipped", "update-crypto-policies not found")
        result = _run(["update-crypto-policies", "--show"], self._timeout())
        if result.returncode != 0:
            return CheckResult("skipped", result.output)
        if result.output.strip().upper() == "LEGACY":
            return CheckResult("vulnerable", "系统加密策略为 LEGACY。", result.output)
        return CheckResult("ok", evidence=result.output)

    def _sysctl_value(self, key: str) -> Optional[str]:
        if not shutil.which("sysctl"):
            return None
        result = _run(["sysctl", "-n", key], self._timeout())
        return result.output.strip() if result.returncode == 0 else None

    def _aslr_disabled(self) -> CheckResult:
        value = self._sysctl_value("kernel.randomize_va_space")
        if value is None:
            return CheckResult("skipped", "sysctl unavailable")
        try:
            if int(value) < 2:
                return CheckResult("vulnerable", "ASLR 未完全启用。", value)
        except ValueError:
            return CheckResult("skipped", value)
        return CheckResult("ok", evidence=value)

    def _ip_forwarding_enabled(self) -> CheckResult:
        value = self._sysctl_value("net.ipv4.ip_forward")
        if value is None:
            return CheckResult("skipped", "sysctl unavailable")
        if value == "1":
            return CheckResult("vulnerable", "IPv4 转发已启用。", value)
        return CheckResult("ok", evidence=value)

    def _core_dump_suid_enabled(self) -> CheckResult:
        value = self._sysctl_value("fs.suid_dumpable")
        if value is None:
            return CheckResult("skipped", "sysctl unavailable")
        if value not in {"0", ""}:
            return CheckResult("vulnerable", "SUID 程序可生成核心转储。", value)
        return CheckResult("ok", evidence=value)

    def _nfs_exports_wildcard(self) -> CheckResult:
        text = _read_text("/etc/exports")
        if not text:
            return CheckResult("ok", evidence="no /etc/exports")
        evidence = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if re.search(r"(^|\s)\*(?:\(|\s|$)", stripped) or "no_root_squash" in stripped:
                evidence.append(stripped)
        if evidence:
            return CheckResult("vulnerable", "NFS 导出范围过宽。", " | ".join(evidence[:10]))
        return CheckResult("ok")

    def _rpm_installed(self, package: str) -> Optional[bool]:
        if not shutil.which("rpm"):
            return None
        result = _run(["rpm", "-q", package], self._timeout())
        if result.returncode == 0:
            return True
        if "not installed" in result.output.lower() or result.returncode == 1:
            return False
        return None

    def _telnet_server_installed(self) -> CheckResult:
        installed = self._rpm_installed("telnet-server")
        if installed is None:
            return CheckResult("skipped", "rpm unavailable")
        if installed:
            return CheckResult("vulnerable", "安装了 telnet-server。", "telnet-server")
        return CheckResult("ok")

    def _ftp_server_installed(self) -> CheckResult:
        installed = self._rpm_installed("vsftpd")
        if installed is None:
            return CheckResult("skipped", "rpm unavailable")
        if installed:
            return CheckResult("vulnerable", "安装了 vsftpd。", "vsftpd")
        return CheckResult("ok")

    def _dnf_automatic_disabled(self) -> CheckResult:
        if not shutil.which("systemctl"):
            return CheckResult("skipped", "systemctl unavailable")
        result = _run(["systemctl", "is-enabled", "dnf-automatic.timer"], self._timeout())
        if result.returncode == 0 or result.output.strip() == "enabled":
            return CheckResult("ok", evidence=result.output)
        if result.output.strip() in {"disabled", "static", "masked"}:
            return CheckResult("vulnerable", "dnf-automatic.timer 未启用。", result.output)
        return CheckResult("skipped", result.output)

    def _usbguard_absent(self) -> CheckResult:
        active = _service_active("usbguard", self._timeout())
        if active is None:
            return CheckResult("skipped", "systemctl unavailable")
        if not active:
            return CheckResult("vulnerable", "USBGuard 未运行。", "inactive")
        return CheckResult("ok")

    def _aide_absent(self) -> CheckResult:
        installed = self._rpm_installed("aide")
        if installed is None:
            return CheckResult("skipped", "rpm unavailable")
        if not installed:
            return CheckResult("vulnerable", "未安装 AIDE。", "aide not installed")
        return CheckResult("ok")

    def _journald_volatile(self) -> CheckResult:
        text = _read_text("/etc/systemd/journald.conf")
        if text is None:
            return CheckResult("skipped", "/etc/systemd/journald.conf is not readable")
        storage = ""
        for line in text.splitlines():
            match = re.match(r"^\s*Storage\s*=\s*(\S+)", line, re.IGNORECASE)
            if match:
                storage = match.group(1).lower()
        persistent_dir = Path("/var/log/journal").is_dir()
        if storage in {"volatile", "none"} or (storage == "auto" and not persistent_dir):
            return CheckResult("vulnerable", "journald 未配置持久化日志。", "Storage=%s" % storage)
        return CheckResult("ok", evidence="Storage=%s" % (storage or "auto"))

    def _check_one(self, rule: dict[str, Any]) -> tuple[str, CheckResult]:
        checker = self.checkers.get(rule["id"])
        if checker is None:
            return rule["id"], CheckResult("skipped", "checker not implemented")
        try:
            return rule["id"], checker()
        except Exception as exc:
            return rule["id"], CheckResult("skipped", "checker error: %s" % exc)

    def scan(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if self.settings.demo:
            return self._demo_scan()
        results: dict[str, CheckResult] = {}
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="rhel-scan") as pool:
            futures = [pool.submit(self._check_one, rule) for rule in self.rules]
            for future in as_completed(futures):
                rule_id, result = future.result()
                results[rule_id] = result

        findings = []
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        checked = 0
        skipped = 0
        for rule in self.rules:
            result = results.get(rule["id"], CheckResult("skipped", "not run"))
            if result.status == "skipped":
                skipped += 1
                continue
            checked += 1
            if result.status == "vulnerable":
                severity = rule.get("severity", "medium")
                counts[severity] = counts.get(severity, 0) + 1
                findings.append(
                    {
                        "rule_id": rule["id"],
                        "title_zh": rule["title_zh"],
                        "title_en": rule["title_en"],
                        "severity": severity,
                        "category": rule.get("category", "system"),
                        "detail": result.detail or rule.get("detail_zh", ""),
                        "evidence": result.evidence,
                        "remediation": rule.get("remediation_zh", ""),
                    }
                )
        penalty = sum(SEVERITY_WEIGHTS.get(level, 0) * count for level, count in counts.items())
        summary = {
            "total": len(findings),
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "checked": checked,
            "skipped": skipped,
            "score": max(0, min(100, 100 - penalty)),
        }
        return findings, summary

    def _demo_scan(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        fixtures = {
            "sshd_root_login": "permitrootlogin yes",
            "firewalld_inactive": "inactive",
            "pending_security_updates": "11 security packages",
            "auditd_inactive": "inactive",
            "password_no_expiry": "alice, deploy",
        }
        findings = []
        for rule_id, evidence in fixtures.items():
            rule = self.rule_map[rule_id]
            findings.append(
                {
                    "rule_id": rule_id,
                    "title_zh": rule["title_zh"],
                    "title_en": rule["title_en"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "detail": rule["detail_zh"],
                    "evidence": evidence,
                    "remediation": rule["remediation_zh"],
                }
            )
        return findings, {
            "total": len(findings),
            "critical": 0,
            "high": 2,
            "medium": 2,
            "low": 1,
            "checked": len(self.rules),
            "skipped": 0,
            "score": 64,
        }


class ScanManager:
    def __init__(self, scanner: VulnerabilityScanner, database: Database):
        self.scanner = scanner
        self.database = database
        self._lock = threading.Lock()
        self._current_id: Optional[str] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def current_id(self) -> Optional[str]:
        with self._lock:
            return self._current_id

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._thread and self._thread.is_alive() and self._current_id:
                return {"scan_id": self._current_id, "status": "running", "reused": True}
            scan_id = self.database.create_scan()
            self._current_id = scan_id
            self._thread = threading.Thread(
                target=self._run, args=(scan_id,), name="rhel-scan", daemon=True
            )
            self._thread.start()
            return {"scan_id": scan_id, "status": "running", "reused": False}

    def _run(self, scan_id: str) -> None:
        error = ""
        try:
            findings, summary = self.scanner.scan()
            self.database.finish_scan(scan_id, findings, summary)
        except Exception as exc:
            error = str(exc)
            self.database.finish_scan(
                scan_id,
                [],
                {
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "score": 0,
                },
                error=error,
            )
        finally:
            with self._lock:
                if self._current_id == scan_id:
                    self._current_id = None
