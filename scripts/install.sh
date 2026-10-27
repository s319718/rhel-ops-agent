#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash install.sh" >&2
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/rhel-ops-agent"
DATA_DIR="/var/lib/rhel-ops-agent"
CONFIG_DIR="/etc/rhel-ops-agent"
SERVICE_NAME="rhel-ops-agent"

if [[ ! -f /etc/redhat-release ]]; then
  echo "提示：未检测到 /etc/redhat-release，继续尝试安装。"
fi

find_python() {
  local candidate
  for candidate in python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      if "${candidate}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
        command -v "${candidate}"
        return 0
      fi
    fi
  done
  return 1
}

PYTHON_BIN="$(find_python || true)"
if [[ -z "${PYTHON_BIN}" ]]; then
  echo "未找到 Python 3.9+。RHEL 8 可先执行：sudo dnf install -y python39" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1 && ! systemctl is-system-running >/dev/null 2>&1; then
  if [[ "$(systemctl is-system-running 2>/dev/null || true)" == "offline" ]]; then
    echo "提示：systemd 当前不在运行状态，安装后需要手动启动服务。" >&2
  fi
fi

echo "==> 安装文件到 ${INSTALL_DIR}"
install -d -m 0755 "${INSTALL_DIR}"
rm -rf "${INSTALL_DIR}/agent" "${INSTALL_DIR}/rules" "${INSTALL_DIR}/web"
cp -a "${SOURCE_DIR}/agent" "${INSTALL_DIR}/agent"
cp -a "${SOURCE_DIR}/rules" "${INSTALL_DIR}/rules"
cp -a "${SOURCE_DIR}/web" "${INSTALL_DIR}/web"
install -m 0755 "${SOURCE_DIR}/app.py" "${INSTALL_DIR}/app.py"
install -m 0755 "${SOURCE_DIR}/rhel-agent" "${INSTALL_DIR}/rhel-agent"
install -m 0644 "${SOURCE_DIR}/README.md" "${INSTALL_DIR}/README.md"
install -m 0644 "${SOURCE_DIR}/FEATURES.md" "${INSTALL_DIR}/FEATURES.md"
install -m 0644 "${SOURCE_DIR}/LLM.md" "${INSTALL_DIR}/LLM.md"
install -d -m 0755 "${INSTALL_DIR}/scripts"
install -m 0755 "${SOURCE_DIR}/scripts/live-audit-test.sh" "${INSTALL_DIR}/scripts/live-audit-test.sh"
install -m 0755 "${SOURCE_DIR}/scripts/install-audit-rules.sh" "${INSTALL_DIR}/scripts/install-audit-rules.sh"
install -m 0755 "${SOURCE_DIR}/scripts/setup-ollama.sh" "${INSTALL_DIR}/scripts/setup-ollama.sh"
install -m 0755 "${SOURCE_DIR}/scripts/setup-qwen-api.sh" "${INSTALL_DIR}/scripts/setup-qwen-api.sh"
install -m 0755 "${SOURCE_DIR}/scripts/setup-glm-api.sh" "${INSTALL_DIR}/scripts/setup-glm-api.sh"
install -m 0644 "${SOURCE_DIR}/scripts/api_smoke_test.py" "${INSTALL_DIR}/scripts/api_smoke_test.py"

WRAPPER_TMP="$(mktemp)"
cat > "${WRAPPER_TMP}" <<EOF
#!/usr/bin/env bash
if [[ -r "${CONFIG_DIR}/agent.env" ]]; then
  set -a
  . "${CONFIG_DIR}/agent.env"
  set +a
fi
exec "${PYTHON_BIN}" "${INSTALL_DIR}/rhel-agent" "\$@"
EOF
install -m 0755 "${WRAPPER_TMP}" /usr/local/bin/rhel-agent
rm -f "${WRAPPER_TMP}"

install -d -m 0700 "${DATA_DIR}"
install -d -m 0750 "${CONFIG_DIR}"
if [[ ! -f "${CONFIG_DIR}/agent.env" ]]; then
  install -m 0640 "${SOURCE_DIR}/deploy/agent.env.example" "${CONFIG_DIR}/agent.env"
fi
SERVICE_TMP="$(mktemp)"
sed "s|^ExecStart=.*|ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/app.py web|" \
  "${SOURCE_DIR}/deploy/rhel-ops-agent.service" > "${SERVICE_TMP}"
install -m 0644 "${SERVICE_TMP}" "/etc/systemd/system/${SERVICE_NAME}.service"
rm -f "${SERVICE_TMP}"

export RHEL_OPS_DATA_DIR="${DATA_DIR}"
if [[ ! -f "${DATA_DIR}/admin.passwd" ]]; then
  echo "==> 初始化管理员密码"
  "${PYTHON_BIN}" "${INSTALL_DIR}/app.py" init
fi

echo "==> 安装定向 auditd 规则"
bash "${INSTALL_DIR}/scripts/install-audit-rules.sh" || {
  echo "警告：auditd 规则安装失败。历史日志采集仍可使用，但实时性会降低。" >&2
}

echo "==> 启用系统服务"
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}.service"
  sleep 1
  systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
else
  echo "未找到 systemctl，可手动运行：${PYTHON_BIN} ${INSTALL_DIR}/app.py web" >&2
fi

echo
echo "安装完成。"
echo "本机控制台：http://127.0.0.1:8765"
echo "命令行用法：rhel-agent \"查看磁盘空间\""
echo "命令行交互：rhel-agent"
if [[ -f "${DATA_DIR}/initial-password.txt" ]]; then
  echo "初始管理员密码：$(cat "${DATA_DIR}/initial-password.txt")"
  echo "密码文件：${DATA_DIR}/initial-password.txt"
fi
if command -v ss >/dev/null 2>&1; then
  ss -lntp | grep ':8765' || true
fi
