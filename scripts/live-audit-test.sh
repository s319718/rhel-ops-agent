#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash scripts/live-audit-test.sh" >&2
  exit 1
fi

if ! command -v rhel-agent >/dev/null 2>&1; then
  echo "未找到 rhel-agent，请先运行安装脚本。" >&2
  exit 1
fi

TEST_DIR="$(mktemp -d /tmp/rhel-agent-audit-test.XXXXXX)"
cleanup() {
  rm -rf -- "${TEST_DIR}"
}
trap cleanup EXIT

mkdir -p "${TEST_DIR}/victim"
printf 'safe audit test\n' > "${TEST_DIR}/victim/sample.txt"

echo "即将从当前终端执行一条真实但安全的高危形态命令："
echo "  rm -rf -- ${TEST_DIR}"
echo "该目录由本脚本创建，不包含系统文件。"

# This intentionally triggers the audit rule. The target is only the temporary
# directory created above.
rm -rf -- "${TEST_DIR}"

echo
echo "等待 Agent 读取 auditd 事件..."
sleep 2
rhel-agent audit

echo
echo "如果日志中出现 recursive_force_delete，说明另一个终端的命令采集正常。"
