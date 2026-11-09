# RemoteMgr · 独立二进制部署说明

本目录下的 `remotemgr-server` 是把 `server/` 下的 Flask 后端用 PyInstaller
（`--onefile`）打包出来的**独立可执行文件**，运行时不依赖系统 Python / venv / pip。

## 目录结构（/opt/remotemgrserver）

```
/opt/remotemgrserver/
├─ remotemgr-server      # 独立二进制（server/app.py 打包，内置 waitress）
├─ static/               # WebUI：index.html / app.js / style.css（与二进制同级）
├─ dat/                  # 运行时数据：remotemgr.db + master.key + secret.key
├─ .env                  # 运行配置（数据库位置 / 端口 / 密钥目录 …）
├─ remotemgr.service     # systemd 单元（需手动安装，见下）
└─ start.sh              # 前台启动脚本（调试用）
```

## 启动

生产（systemd，开机自启）：

```bash
sudo cp /opt/remotemgrserver/remotemgr.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now remotemgr.service
sudo journalctl -u remotemgr -f
```

调试（前台）：`bash /opt/remotemgrserver/start.sh`

## 关键路径

- 二进制通过 `sys.executable` 定位自身目录，因此 `static/`、`dat/`、`.env`
  都以二进制所在目录为基准，移动到任何路径都能用。
- `dat/` 里的 `master.key` / `secret.key` 是解密凭据的唯一主密钥，**务必单独备份**；
  丢了就无法解开库里的密码与 SSH 私钥。
- 首次启动若 `.env` 的 `BOOTSTRAP_PASSWORD` 为空，会随机生成管理员密码并写入
  `dat/initial_admin.txt`（权限 0600）。

## 健康检查

```bash
curl http://127.0.0.1:8800/api/health
```

## 重建二进制（如需更新）

```bash
python3 -m venv build-venv && build-venv/bin/pip install -r server/requirements.txt pyinstaller
cd build && pyinstaller --onefile --name remotemgr-server --paths ../server ../server/app.py
# 产物在 build/dist/remotemgr-server，连同 ../server/static 一起拷到部署目录即可
```
