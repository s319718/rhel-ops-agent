#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash scripts/install-audit-rules.sh" >&2
  exit 1
fi

if ! command -v auditctl >/dev/null 2>&1; then
  echo "未找到 auditctl。请先安装并启用 auditd，本脚本跳过。"
  exit 0
fi

RULES_FILE="/etc/audit/rules.d/rhel-ops-agent.rules"
RULES_DIR="$(dirname "${RULES_FILE}")"
install -d -m 0750 "${RULES_DIR}"

TMP_FILE="$(mktemp)"
trap 'rm -f "${TMP_FILE}"' EXIT

cat > "${TMP_FILE}" <<'EOF'
## Managed by RHEL Ops Agent. Only selected high-risk binaries are recorded.
## This does not change shell prompts or require a login shell wrapper.
EOF

BINARIES=(
  /usr/bin/rm
  /usr/bin/dd
  /usr/bin/chmod
  /usr/bin/chown
  /usr/bin/systemctl
  /usr/bin/crontab
  /usr/bin/userdel
  /usr/bin/visudo
  /usr/bin/nmcli
  /usr/bin/ip
  /usr/bin/kill
  /usr/bin/pkill
  /usr/bin/killall
  /usr/bin/firewall-cmd
  /usr/sbin/firewall-cmd
  /usr/sbin/iptables
  /usr/sbin/nft
  /usr/sbin/setenforce
  /usr/sbin/auditctl
  /usr/sbin/shutdown
  /usr/sbin/reboot
  /usr/sbin/poweroff
  /usr/sbin/mkfs.xfs
  /usr/sbin/mkfs.ext4
  /usr/sbin/wipefs
  /usr/sbin/rmmod
  /usr/sbin/modprobe
  /usr/sbin/sysctl
  /usr/bin/dnf
  /usr/bin/yum
)

for binary in "${BINARIES[@]}"; do
  if [[ -x "${binary}" ]]; then
    printf '%s\n' "-a always,exit -F arch=b64 -S execve -F exe=${binary} -k rhel_ops_agent" >> "${TMP_FILE}"
  fi
done

install -m 0640 "${TMP_FILE}" "${RULES_FILE}"

if command -v augenrules >/dev/null 2>&1; then
  augenrules --load
elif command -v auditctl >/dev/null 2>&1; then
  auditctl -R "${RULES_FILE}"
else
  echo "已写入 ${RULES_FILE}，但未找到 audit 规则加载工具。" >&2
  exit 1
fi

echo "已安装定向 auditd 规则：${RULES_FILE}"
echo "核对命令：auditctl -l | grep rhel_ops_agent"
