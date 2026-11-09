#!/usr/bin/env bash
# Install / reinstall the RemoteMgr server on a Linux host.
# Existing .env and data/*.key are never overwritten.
set -euo pipefail

BASE="${REMOTEMGR_HOME:-$HOME/remotemgr}"
USER_NAME="$(id -un)"
GROUP_NAME="$(id -gn)"
PORT="$(grep -E '^BIND_PORT=' "$BASE/.env" 2>/dev/null | cut -d= -f2 | tr -d ' \"' || true)"
PORT="${PORT:-8800}"

run_sudo() {
  if [ "$(id -u)" -eq 0 ]; then "$@";
  elif [ -n "${SUDO_PASSWORD:-}" ]; then echo "$SUDO_PASSWORD" | sudo -S "$@";
  else sudo "$@"; fi
}

echo "==> 安装目录: $BASE"
echo "==> 服务端口: $PORT"

command -v python3 >/dev/null || { echo "缺少 python3"; exit 1; }
mkdir -p "$BASE/data"

# Ubuntu 24.04 often ships python3 without ensurepip, so `python3 -m venv`
# fails. Install the matching venv package when that is the case.
if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
  echo "==> 系统缺少 ensurepip，安装 python3-venv"
  PY_VER="$(python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])')"
  run_sudo apt-get update -qq
  run_sudo apt-get install -y -qq "python${PY_VER}-venv" || run_sudo apt-get install -y -qq python3-venv
fi

if [ ! -x "$BASE/venv/bin/pip" ]; then
  echo "==> 创建虚拟环境"
  rm -rf "$BASE/venv"
  python3 -m venv "$BASE/venv"
fi

echo "==> 安装依赖"
PIP="$BASE/venv/bin/pip"
install_deps() {
  if [ -n "${1:-}" ]; then
    "$PIP" install --disable-pip-version-check -q -i "$1" -r "$BASE/server/requirements.txt"
  else
    "$PIP" install --disable-pip-version-check -q -r "$BASE/server/requirements.txt"
  fi
}
"$PIP" install --disable-pip-version-check -q --upgrade pip || true
if [ -n "${PIP_INDEX_URL:-}" ]; then
  install_deps "$PIP_INDEX_URL"
elif ! install_deps ""; then
  echo "==> 默认源不可用，改用阿里云镜像重试"
  install_deps "https://mirrors.aliyun.com/pypi/simple" || {
    echo "==> 改用清华镜像重试"
    install_deps "https://pypi.tuna.tsinghua.edu.cn/simple"
  }
fi

if [ ! -f "$BASE/.env" ]; then
  echo "==> 生成 .env 与初始管理员密码"
  INITIAL_PASS="$("$BASE/venv/bin/python" -c 'import secrets;print(secrets.token_urlsafe(14))')"
  cp "$BASE/server/.env.example" "$BASE/.env"
  "$BASE/venv/bin/python" - "$BASE/.env" "$INITIAL_PASS" <<'PY'
import sys, pathlib
path, password = pathlib.Path(sys.argv[1]), sys.argv[2]
text = path.read_text(encoding="utf-8").replace("BOOTSTRAP_PASSWORD=", "BOOTSTRAP_PASSWORD=" + password)
path.write_text(text, encoding="utf-8")
PY
  chmod 600 "$BASE/.env"
  echo "    初始管理员: admin"
  echo "    初始密码  : $INITIAL_PASS  (同时保存在 $BASE/.env，请登录后立刻修改)"
else
  echo "==> 保留已有 .env（含云端数据库配置）"
fi

echo "==> 初始化数据库并自检"
"$BASE/venv/bin/python" "$BASE/server/manage.py" selftest
"$BASE/venv/bin/python" "$BASE/server/manage.py" check-db

if command -v systemctl >/dev/null 2>&1; then
  echo "==> 安装 systemd 服务"
  TMP_UNIT="$(mktemp)"
  sed -e "s|/home/acaiplus/remotemgr|$BASE|g" \
      -e "s|^User=.*|User=$USER_NAME|" \
      -e "s|^Group=.*|Group=$GROUP_NAME|" \
      -e "s|--listen=0.0.0.0:8800|--listen=0.0.0.0:$PORT|" \
      "$BASE/deploy/remotemgr.service" > "$TMP_UNIT"
  run_sudo cp "$TMP_UNIT" /etc/systemd/system/remotemgr.service
  rm -f "$TMP_UNIT"
  run_sudo systemctl daemon-reload
  run_sudo systemctl enable --now remotemgr.service
  sleep 2
  run_sudo systemctl --no-pager status remotemgr.service || true
  echo "==> 日志: journalctl -u remotemgr -f"
else
  echo "==> 无 systemd，请手动运行:"
  echo "    $BASE/venv/bin/waitress-serve --listen=0.0.0.0:$PORT --threads=8 app:app"
fi

echo "==> 完成：浏览器打开 http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1):$PORT"
