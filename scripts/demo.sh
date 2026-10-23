#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${SOURCE_DIR}"

export RHEL_OPS_DEMO=1
export RHEL_OPS_DATA_DIR="${RHEL_OPS_DATA_DIR:-${SOURCE_DIR}/data-demo}"
export PYTHONUNBUFFERED=1

python3 app.py web
