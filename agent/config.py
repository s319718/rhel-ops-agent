from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _load_managed_env() -> None:
    path = Path(os.environ.get("RHEL_OPS_ENV_FILE", "/etc/rhel-ops-agent/agent.env"))
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


_load_managed_env()


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


@dataclass
class Settings:
    root_dir: Path
    data_dir: Path
    rules_dir: Path
    web_dir: Path
    host: str = "127.0.0.1"
    port: int = 8765
    demo: bool = False
    no_auth: bool = False
    audit_poll_seconds: int = 20
    scan_timeout_seconds: int = 20
    proposal_ttl_seconds: int = 900
    max_history_lines: int = 3000
    allowed_origins: list[str] = field(default_factory=list)
    llm_enabled: bool = False
    llm_mode: str = "hybrid"
    llm_provider: str = "ollama"
    llm_base_url: str = ""
    llm_model: str = ""
    llm_api_key: str = ""
    llm_timeout_seconds: int = 20
    llm_confidence_threshold: float = 0.55
    llm_structured_output: bool = True
    llm_max_actions: int = 6

    @classmethod
    def from_env(
        cls,
        root_dir: Optional[Path] = None,
        data_dir: Optional[Path] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        demo: Optional[bool] = None,
        no_auth: Optional[bool] = None,
    ) -> "Settings":
        root = (root_dir or Path(__file__).resolve().parent.parent).resolve()
        configured_data = data_dir or os.environ.get("RHEL_OPS_DATA_DIR")
        if configured_data is None:
            packaged_data = Path("/var/lib/rhel-ops-agent")
            if root == Path("/opt/rhel-ops-agent") and packaged_data.is_dir():
                configured_data = packaged_data
            else:
                configured_data = root / "data"
        configured_host = host or os.environ.get("RHEL_OPS_HOST", "127.0.0.1")
        configured_port = port or int(os.environ.get("RHEL_OPS_PORT", "8765"))
        is_demo = _env_bool("RHEL_OPS_DEMO") if demo is None else demo
        is_no_auth = (
            _env_bool("RHEL_OPS_NO_AUTH") if no_auth is None else no_auth
        )
        llm_provider = os.environ.get("RHEL_OPS_LLM_PROVIDER", "ollama").strip().lower()
        if llm_provider == "ollama":
            default_llm_url = "http://127.0.0.1:11434"
            default_llm_model = "qwen2.5:7b-instruct"
        elif llm_provider == "qwen":
            default_llm_url = "https://dashscope.aliyuncs.com/compatible-mode/v1"
            default_llm_model = "qwen-plus"
        else:
            default_llm_url = "https://api.openai.com/v1"
            default_llm_model = ""
        settings = cls(
            root_dir=root,
            data_dir=Path(configured_data).resolve(),
            rules_dir=root / "rules",
            web_dir=root / "web",
            host=configured_host,
            port=configured_port,
            demo=is_demo,
            no_auth=is_no_auth,
            audit_poll_seconds=int(os.environ.get("RHEL_OPS_AUDIT_POLL", "20")),
            scan_timeout_seconds=int(os.environ.get("RHEL_OPS_SCAN_TIMEOUT", "20")),
            proposal_ttl_seconds=int(os.environ.get("RHEL_OPS_PROPOSAL_TTL", "900")),
            max_history_lines=int(os.environ.get("RHEL_OPS_HISTORY_LINES", "3000")),
            llm_enabled=_env_bool("RHEL_OPS_LLM_ENABLED"),
            llm_mode=os.environ.get("RHEL_OPS_LLM_MODE", "llm_first").strip().lower(),
            llm_provider=llm_provider,
            llm_base_url=os.environ.get("RHEL_OPS_LLM_BASE_URL", default_llm_url).strip(),
            llm_model=os.environ.get("RHEL_OPS_LLM_MODEL", default_llm_model).strip(),
            llm_api_key=(
                os.environ.get("RHEL_OPS_LLM_API_KEY", "").strip()
                or os.environ.get("DASHSCOPE_API_KEY", "").strip()
            ),
            llm_timeout_seconds=int(os.environ.get("RHEL_OPS_LLM_TIMEOUT", "20")),
            llm_confidence_threshold=_env_float(
                "RHEL_OPS_LLM_CONFIDENCE", 0.55
            ),
            llm_structured_output=_env_bool(
                "RHEL_OPS_LLM_STRUCTURED_OUTPUT", True
            ),
            llm_max_actions=int(os.environ.get("RHEL_OPS_LLM_MAX_ACTIONS", "6")),
        )
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        return settings

    @property
    def database_path(self) -> Path:
        return self.data_dir / "agent.db"

    @property
    def password_path(self) -> Path:
        return self.data_dir / "admin.passwd"

    @property
    def session_secret_path(self) -> Path:
        return self.data_dir / "session.secret"

    @property
    def initial_password_path(self) -> Path:
        return self.data_dir / "initial-password.txt"

    @property
    def audit_state_path(self) -> Path:
        return self.data_dir / "audit-state.json"
