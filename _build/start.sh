#!/usr/bin/env bash
# 前台启动（调试用）。生产环境请用 systemd（见 remotemgr.service）。
set -euo pipefail
cd /opt/remotemgrserver
export REMOTEMGR_DATA=/opt/remotemgrserver/dat
export REMOTEMGR_ENV=/opt/remotemgrserver/.env
exec ./remotemgr-server
