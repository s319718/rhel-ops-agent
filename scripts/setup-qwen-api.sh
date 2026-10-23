#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/rhel-ops-agent/agent.env"
MODEL="${RHEL_OPS_LLM_MODEL:-qwen-plus}"
BASE_URL="${RHEL_OPS_LLM_BASE_URL:-https://dashscope.aliyuncs.com/compatible-mode/v1}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash scripts/setup-qwen-api.sh" >&2
  exit 1
fi
if [[ ! -x /usr/local/bin/rhel-agent ]]; then
  echo "RHEL Ops Agent 尚未安装。请先在项目目录执行：sudo bash install.sh" >&2
  exit 3
fi

API_KEY="${RHEL_OPS_LLM_API_KEY:-${DASHSCOPE_API_KEY:-}}"
if [[ -z "${API_KEY}" ]]; then
  if [[ ! -t 0 ]]; then
    echo "请在交互终端中运行，或设置 DASHSCOPE_API_KEY。" >&2
    exit 2
  fi
  read -r -s -p "请输入 DashScope API Key（输入不会显示）： " API_KEY
  echo
fi
if [[ -z "${API_KEY}" ]]; then
  echo "API Key 不能为空。" >&2
  exit 2
fi

install -d -m 0750 "$(dirname "${ENV_FILE}")"
temporary="$(mktemp)"
if [[ -f "${ENV_FILE}" ]]; then
  grep -Ev '^RHEL_OPS_LLM_(ENABLED|MODE|PROVIDER|BASE_URL|MODEL|API_KEY)=' \
    "${ENV_FILE}" > "${temporary}" || true
fi

{
  printf 'RHEL_OPS_LLM_ENABLED=1\n'
  printf 'RHEL_OPS_LLM_MODE=hybrid\n'
  printf 'RHEL_OPS_LLM_PROVIDER=qwen\n'
  printf 'RHEL_OPS_LLM_BASE_URL=%s\n' "${BASE_URL}"
  printf 'RHEL_OPS_LLM_MODEL=%s\n' "${MODEL}"
  printf 'RHEL_OPS_LLM_API_KEY=%s\n' "${API_KEY}"
} >> "${temporary}"

install -m 0600 "${temporary}" "${ENV_FILE}"
rm -f "${temporary}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart rhel-ops-agent.service >/dev/null 2>&1 || true
fi

echo "Qwen API 配置已保存到 ${ENV_FILE}"
echo "模型：${MODEL}"
echo "地址：${BASE_URL}"
echo
echo "验证：sudo rhel-agent llm-test"
