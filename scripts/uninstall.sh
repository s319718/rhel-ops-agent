#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash scripts/uninstall.sh" >&2
  exit 1
fi

if [[ "${1:-}" == "--purge" ]]; then
  echo "将删除程序、配置、数据库和登录密码。"
  read -r -p "输入 DELETE 确认清空所有数据：" confirm
  if [[ "${confirm}" != "DELETE" ]]; then
    echo "已取消。"
    exit 1
  fi
  systemctl disable --now rhel-ops-agent.service 2>/dev/null || true
  rm -f /etc/systemd/system/rhel-ops-agent.service
  rm -f /etc/audit/rules.d/rhel-ops-agent.rules
  rm -rf /opt/rhel-ops-agent /etc/rhel-ops-agent /var/lib/rhel-ops-agent
  rm -f /usr/local/bin/rhel-agent
  systemctl daemon-reload 2>/dev/null || true
  augenrules --load 2>/dev/null || true
  echo "已完全卸载。"
  exit 0
fi

systemctl disable --now rhel-ops-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/rhel-ops-agent.service
rm -f /etc/audit/rules.d/rhel-ops-agent.rules
rm -rf /opt/rhel-ops-agent /etc/rhel-ops-agent
rm -f /usr/local/bin/rhel-agent
systemctl daemon-reload 2>/dev/null || true
augenrules --load 2>/dev/null || true
echo "程序已卸载，数据保留在 /var/lib/rhel-ops-agent。"
echo "如需彻底清除，运行：sudo bash scripts/uninstall.sh --purge"
