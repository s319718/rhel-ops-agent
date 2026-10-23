from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Optional


PBKDF2_ITERATIONS = 310_000
SESSION_TTL_SECONDS = 12 * 60 * 60


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


class AuthManager:
    def __init__(
        self,
        password_path: Path,
        secret_path: Path,
        initial_password_path: Path,
        no_auth: bool = False,
    ):
        self.password_path = Path(password_path)
        self.secret_path = Path(secret_path)
        self.initial_password_path = Path(initial_password_path)
        self.no_auth = no_auth
        self.secret = self._load_secret()

    def _load_secret(self) -> bytes:
        if self.secret_path.exists():
            return self.secret_path.read_bytes()
        secret = secrets.token_bytes(32)
        self.secret_path.write_bytes(secret)
        try:
            os.chmod(self.secret_path, 0o600)
        except OSError:
            pass
        return secret

    def initialize(self, password: Optional[str] = None, demo: bool = False) -> str:
        if self.password_path.exists():
            return ""
        supplied = password or os.environ.get("RHEL_OPS_ADMIN_PASSWORD")
        generated = supplied is None
        if generated:
            supplied = "rhel-demo" if demo else secrets.token_urlsafe(15)
        self.set_password(supplied)
        if generated and not demo:
            self.initial_password_path.write_text(supplied + "\n", encoding="utf-8")
            try:
                os.chmod(self.initial_password_path, 0o600)
            except OSError:
                pass
        return supplied if generated else ""

    def set_password(self, password: str) -> None:
        if len(password) < 8:
            raise ValueError("管理员密码至少需要 8 个字符")
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        payload = {
            "algorithm": "pbkdf2_sha256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": _b64encode(salt),
            "digest": _b64encode(digest),
        }
        self.password_path.write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
        try:
            os.chmod(self.password_path, 0o600)
        except OSError:
            pass

    def verify_password(self, password: str) -> bool:
        if self.no_auth:
            return True
        try:
            payload = json.loads(self.password_path.read_text(encoding="utf-8"))
            salt = _b64decode(payload["salt"])
            expected = _b64decode(payload["digest"])
            iterations = int(payload.get("iterations", PBKDF2_ITERATIONS))
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return hmac.compare_digest(digest, expected)

    def issue_session(self) -> str:
        payload = {
            "sub": "admin",
            "iat": int(time.time()),
            "exp": int(time.time()) + SESSION_TTL_SECONDS,
            "nonce": secrets.token_hex(8),
        }
        encoded = _b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        signature = hmac.new(
            self.secret, encoded.encode("ascii"), hashlib.sha256
        ).digest()
        return encoded + "." + _b64encode(signature)

    def verify_session(self, token: Optional[str]) -> bool:
        if self.no_auth:
            return True
        if not token or "." not in token:
            return False
        encoded, supplied_signature = token.split(".", 1)
        expected = hmac.new(
            self.secret, encoded.encode("ascii"), hashlib.sha256
        ).digest()
        try:
            actual = _b64decode(supplied_signature)
        except ValueError:
            return False
        if not hmac.compare_digest(actual, expected):
            return False
        try:
            payload = json.loads(_b64decode(encoded).decode("utf-8"))
            return int(payload.get("exp", 0)) > int(time.time())
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return False


class LoginRateLimiter:
    def __init__(self, attempts: int = 5, window_seconds: int = 300):
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._records: dict[str, list[float]] = {}

    def allowed(self, key: str) -> bool:
        self._prune(key)
        return len(self._records.get(key, [])) < self.attempts

    def fail(self, key: str) -> None:
        self._prune(key)
        self._records.setdefault(key, []).append(time.time())

    def success(self, key: str) -> None:
        self._records.pop(key, None)

    def _prune(self, key: str) -> None:
        cutoff = time.time() - self.window_seconds
        values = [value for value in self._records.get(key, []) if value >= cutoff]
        if values:
            self._records[key] = values
        else:
            self._records.pop(key, None)
