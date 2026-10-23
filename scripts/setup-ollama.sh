#!/usr/bin/env bash
set -euo pipefail

MODEL="${RHEL_OPS_LLM_MODEL:-qwen2.5:7b-instruct}"
OLLAMA_URL="${RHEL_OPS_LLM_BASE_URL:-http://127.0.0.1:11434}"
ENV_FILE="/etc/rhel-ops-agent/agent.env"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash scripts/setup-ollama.sh" >&2
  exit 1
fi

if ! command -v ollama >/dev/null 2>&1; then
  if [[ "${RHEL_OPS_INSTALL_OLLAMA:-0}" != "1" ]]; then
    cat >&2 <<'EOF'
未检测到 Ollama。

如确认要从 Ollama 官方地址安装，请执行：
  sudo RHEL_OPS_INSTALL_OLLAMA=1 bash scripts/setup-ollama.sh

安装完成后，模型会保存在 /usr/share/ollama/.ollama/models，不会进入 Git 仓库。
EOF
    exit 2
  fi
  echo "==> 下载并安装 Ollama"
  installer="$(mktemp)"
  trap 'rm -f "${installer}"' EXIT
  curl -fsSL https://ollama.com/install.sh -o "${installer}"
  sh "${installer}"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now ollama >/dev/null 2>&1 || true
fi

echo "==> 拉取模型 ${MODEL}"
ollama pull "${MODEL}"

echo "==> 验证模型"
ollama show "${MODEL}" >/dev/null

if [[ -f "${ENV_FILE}" ]]; then
  set_env() {
    local key="$1"
    local value="$2"
    if grep -q "^${key}=" "${ENV_FILE}"; then
      sed -i "s|^${key}=.*|${key}=${value}|" "${ENV_FILE}"
    else
      printf '\n%s=%s\n' "${key}" "${value}" >> "${ENV_FILE}"
    fi
  }
  set_env "RHEL_OPS_LLM_ENABLED" "1"
  set_env "RHEL_OPS_LLM_MODE" "hybrid"
  set_env "RHEL_OPS_LLM_PROVIDER" "ollama"
  set_env "RHEL_OPS_LLM_BASE_URL" "${OLLAMA_URL}"
  set_env "RHEL_OPS_LLM_MODEL" "${MODEL}"
  chmod 0640 "${ENV_FILE}"
  echo "==> 已更新 ${ENV_FILE}"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart rhel-ops-agent.service >/dev/null 2>&1 || true
fi

echo
echo "LLM 配置完成。"
echo "模型：${MODEL}"
echo "接口：${OLLAMA_URL}"
echo "检查：sudo rhel-agent rules"
