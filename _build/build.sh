#!/usr/bin/env bash
set -xeuo pipefail
export PIP_DISABLE_PIP_VERSION_CHECK=1
cd /tmp/rmtbuild

echo "=== extract source ==="
rm -rf server
mkdir -p server
tar -xzf server.tar.gz -C server

echo "=== create build venv ==="
python3 -m venv venv
./venv/bin/python -m pip install --upgrade pip -q

echo "=== install deps + pyinstaller ==="
if ! ./venv/bin/pip install -q -i https://mirrors.aliyun.com/pypi/simple/ -r server/requirements.txt pyinstaller; then
  echo "aliyun mirror failed, retrying default index"
  ./venv/bin/pip install -q -r server/requirements.txt pyinstaller
fi

echo "=== pyinstaller build ==="
rm -rf build dist remotemgr-server.spec
./venv/bin/pyinstaller --onefile --name remotemgr-server \
  --paths server \
  --hidden-import waitress \
  --hidden-import pymysql \
  --hidden-import psycopg2 \
  server/app.py

echo "=== result ==="
ls -la dist/remotemgr-server
file dist/remotemgr-server
echo "BUILD_DONE_OK"
