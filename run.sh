#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash run.sh" >&2
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x /usr/local/bin/rhel-agent ]]; then
  bash "${SOURCE_DIR}/install.sh"
fi

exec /usr/local/bin/rhel-agent "$@"
