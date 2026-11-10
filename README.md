# RemoteMgr · C/S 版

把 [dwj0/Remote-management](https://github.com/dwj0/Remote-management)（VC2017 / MFC + 本地 SQLite 的单机远程连接管理器）改造成 **C/S 架构 + 云端数据库 + WebUI 管理** 的 Linux 后端程序。

服务端部署在 `192.168.10.121`（Ubuntu 24.04.5 / Python 3.12），浏览器和本地 Agent 都是客户端。

---

## 一、架构

```
浏览器 WebUI ─┐
本地 Agent  ──┼── HTTPS/REST + 登录令牌 ──> Linux 服务端 (8800) ──> 云端 MySQL / PostgreSQL
旧库迁移工具 ─┘                              │
                                            └─ master.key 只存服务端本地
```

- **服务端**：Flask + SQLAlchemy + waitress，提供 REST API、静态 WebUI、WOL 广播、审计、密钥托管。**不做在线探测**——TCP 可达性只由本地 Agent 从操作员电脑发包判定。
- **WebUI**：零构建单页，多级分组树、主机 CRUD、搜索、拖拽移动、在线检测、用户/设置/审计/导入导出。
- **本地 Agent**：浏览器沙箱启动不了 `mstsc`，所以用一个零依赖 Python 小程序在你自己的电脑上拉起 RDP / PuTTY / VNC / Radmin / FlashFXP 客户端或系统浏览器，复刻原版「双击直连」。
- **数据库**：`DATABASE_URL` 决定，SQLite / MySQL / PostgreSQL 同一套代码，改一行配置就能把数据放到云上。
- **凭据安全**：主机密码和 SSH 私钥内容都经 AES-256-GCM 加密后才入库，主密钥只在服务端 `data/master.key`（0600）。**云数据库被拖库也拿不到明文密码或私钥**。SSH 还支持「只存本机路径」模式，私钥正文完全不上传。

### 原功能对照

| 原 MFC 功能 | C/S 版实现 |
|---|---|
| ConfigTab / GroupTab / HostTab | `rm_settings` / `rm_groups` / `rm_hosts`（+ `rm_users` / `rm_audit`） |
| 多级分组、拖拽移动、改名 | WebUI 分组树 + 拖拽，级联删除需确认 |
| RDP / Radmin / SSH / RealVNC / TightVNC | `protocol` 字段，默认端口 3389/4899/22/5900/5900；另新增 **FTP（FlashFXP）** 21、**Web（HTTP/HTTPS）** 443 与 **WinSCP（SFTP/FTP）** 22 三类记录 |
| 双击调用客户端并自动填密码 | WebUI「连接」→ 一次性票据 → 本地 Agent 直接拉起客户端（RDP 走 DPAPI，Radmin 自动填登录窗，SSH 支持密码 / 密钥对、私钥可加密入库，VNC 命令行传密码，FTP 用 FlashFXP URL，Web 直接打开浏览器）；**所有协议统一一键直连，不再提供「下载 .rdp 文件」入口** |
| 在线扫描（TCP connect） | `POST /probe` 由**本地 Agent 从操作员机器**并发探测，是唯一判定来源；服务端不发包、没有 `/api/hosts/probe` 接口；Agent 不在线时状态显示「—」并提示启动，不会误报「离线」 |
| Ping / WOL 唤醒 | WOL 由服务端发 UDP 广播；Ping 用「命令」按钮复制 |
| 主机搜索 | 名称 / 地址 / 账号 / 备注模糊搜索，`*` 显示全部 |
| 鼠标悬浮查看连接参数 | 主机行悬浮卡片：连接目标 / 账号 / 密码状态 / 分组 + 记录级选项（含 FTP / Web 的 URL 协议、路径与参数格式）+ 本机 Agent 实际命令行与 `.rdp` 关键行（密码隐藏） |
| 分组导入导出 | JSON 备份（WebUI 导入导出，含密码与 SSH 私钥密文，需同一 `master.key` 才能恢复） |
| 软件打开密码 | 多用户登录（admin / editor / viewer）+ PBKDF2 密码哈希 + 令牌 |
| 本地 User.db | `manage.py import-legacy` 迁移，含旧 AES 密码解密 |

> 没有去改 MFC 源码：老工程是 GBK 编码的 VC2017 项目，改造它连数据库/加登录的成本高于重写，而且会丢掉 WebUI 这个诉求。功能按上表等价迁移，旧数据可一键导入。

---

## 二、目录

```
remotemgr/
├─ server/
│  ├─ app.py               # REST API + WebUI 入口（waitress-serve app:app）
│  ├─ models.py            # SQLAlchemy 模型，跨 SQLite/MySQL/PostgreSQL
│  ├─ crypto.py            # AES-GCM、口令哈希、旧库 AES-128-ECB 解密
│  ├─ config.py            # 全部配置来自环境变量 / .env
│  ├─ manage.py            # 运维 CLI：init-db / 用户 / 旧库迁移 / copy-db / selftest
│  ├─ static/               # WebUI（index.html / app.js / style.css）
│  ├─ requirements.txt
│  └─ .env.example
├─ agent/remotemgr_agent.py    # 本地连接 Agent（零第三方依赖）
├─ deploy/install.sh           # 一键安装 + systemd
├─ deploy/remotemgr.service
├─ scripts/cloud_db_setup.sql  # 云端建库脚本
└─ README.md
```

---

## 三、部署（192.168.10.121）

```bash
cd ~/remotemgr
bash deploy/install.sh          # 非 root 时会提示 sudo；也可 SUDO_PASSWORD=xxx bash deploy/install.sh
journalctl -u remotemgr -f       # 看日志
```

`install.sh` 不覆盖已有 `.env` 和 `data/*.key`。首次运行会：

1. 建 venv 并装依赖；
2. 从 `.env.example` 生成 `.env`，随机生成初始管理员密码写进去（权限 0600）；
3. 自动建表 + 生成 `data/master.key`、`data/secret.key`；
4. 装 systemd 服务 `remotemgr.service` 并开机自启。

浏览器打开 `http://192.168.10.121:8800`。健康检查：`curl http://127.0.0.1:8800/api/health`。

本机开发调试（不装 systemd）：

```bash
python -m venv venv && venv/bin/pip install -r server/requirements.txt
venv/bin/python server/manage.py selftest
venv/bin/python server/app.py
```

---

## 四、迁移旧版 User.db

```bash
cd ~/remotemgr
venv/bin/python server/manage.py import-legacy /path/to/User.db --dry-run
venv/bin/python server/manage.py import-legacy /path/to/User.db
# 只想挂到某个分组下：加 --group-id 3
```

- 自动识别旧库 UTF-8 / GBK 文本；`CtrlMode` 0..4 映射为 rdp / radmin / ssh / realvnc / tightvnc。旧库没有 FTP / Web / WinSCP 类型，这三类只能在 WebUI 里新增。
- 旧密码是 AES-128-ECB（密钥为 GBK「远程连接管理软件」）加 PKCS#7 填充的 hex，`crypto.py` 已复刻；解不开的主机会保留但密码留空，并在输出里列出来，请在 WebUI 里重填。
- 迁移后会重新加密成 AES-GCM。建议先跑 `--dry-run`，再抽查几台主机的密码。

---

## 五、本地连接 Agent（一键直连）

```bash
# 在你自己电脑上（Windows / Linux 都行，Python 3.9+，零依赖）
python remotemgr_agent.py --server http://192.168.10.121:8800 login --user admin --password '你的密码'
python remotemgr_agent.py list
python remotemgr_agent.py connect 12
python remotemgr_agent.py serve       # 保持运行，WebUI 点「连接」即可一键拉起
```

`serve` 只监听 `127.0.0.1:17860`。WebUI 点连接时向服务端申请一个 **60 秒、一次性** 票据，Agent 拿票据换取明文密码后立刻启动本地客户端；登录令牌不会出现在 URL 里。

各协议行为：

| 协议 | Windows | Linux |
|---|---|---|
| RDP | 点「连接」直接拉起 `mstsc.exe`：Agent 在**本机**生成临时 `.rdp`（`CryptProtectData` 写入 `password 51:b` 自动登录，并按记录写入分辨率/色深/背景/磁盘/音频），8 秒后删掉；浏览器不下载任何文件 | `xfreerdp /v:host:port /u:user /p:pass` |
| SSH | **密码**：PuTTY `-ssh -l user -pw pass -P port host`；**密钥对**：`-ssh -l user -P port -i <私钥> host`（不传 `-pw`；私钥存数据库时 `<私钥>` 是 Agent 落地、用完即删的 0600 临时文件）；模板留空时自动拼接，找不到 PuTTY 则给出命令 | 密码走 `sshpass -p pass ssh ...`；密钥对走 `ssh -p port -i <私钥> user@host`；没装 sshpass 则给出可复制命令 |
| Radmin | `radmin.exe /connect:host[:port] [模式] /8bpp｜/16bpp｜/24bpp [/fullscreen]`，色深按记录配置，并自动往「Radmin 安全性」窗口填账号密码 | 不支持（Radmin 只有 Windows 客户端） |
| VNC | `vncviewer host:port`（TightVNC 额外传 `-password=`） | `vncviewer host:port` |
| FTP（FlashFXP） | 按记录拼 `ftp://` / `ftps://` / `ftpes://` / `sftp://` URL 交给 `flashfxp.exe`，可带 `-max/-min/-tray` 与 `-localpath=`；匿名登录不传账号密码 | 不支持（FlashFXP 是 Windows 客户端）；Agent 会回显脱敏 URL 供手工打开 |
| Web（HTTP/HTTPS） | 地址栏**可直接粘贴完整 URL**（含端口、路径、`?参数`、`#锚点`）原样打开；只填主机名时才按「页面协议 + 端口 + URL 路径」拼接。用系统默认浏览器或指定浏览器打开，可加自定义参数（如 `--incognito`）。默认**不传密码**，选「URL 内嵌 Basic 认证」才把账号密码写进 URL | 同左，`webbrowser.open()` 交给桌面默认浏览器 |
| WinSCP（SFTP/FTP） | 按记录拼 `sftp://` / `scp://` / `ftp://` / `ftps://` / `webdav(s)://` 会话 URL 交给 `WinSCP.exe`，可带 `/minimized` / `/newinstance`；匿名登录自动合成 `anonymous:anonymous`（保存的密码不下发） | 不支持（WinSCP 是 Windows 客户端）；Agent 会回显脱敏 URL 供手工打开 |

FTP 的 URL 前缀与端口来自 FlashFXP 官方「快速连接 / 站点管理器」：`ftp://`（21）、`ftps://`（隐式 SSL，990）、`ftpes://`（显式 TLS，21）、`sftp://`（SFTP over SSH，22）。切换连接协议时 WebUI 会自动把端口改成该协议默认值（前提是你没手填自定义端口）。Web 记录的 `https`（443）/ `http`（80）同理。WinSCP 的会话前缀：`sftp://` / `scp://`（22）、`ftp://`（21）、`ftps://`（990）、`webdav://`（80）、`webdavs://`（443），切换时同样自动跟端口。

**Web 记录的地址字段有两种写法**（Agent 与悬浮卡片用同一套解析规则）：

| 地址栏填的内容 | 结果 |
|---|---|
| 完整 URL：`http://49.234.138.90:6443/static/#/proxies/tcp` | **原样打开**，协议 / 端口 / 路径 / `?query` / `#hash` 全部保留；「页面协议」「端口」「URL 路径」三项自动失效，服务端地址长度放宽到 512 字符 |
| 纯主机名：`portal.lan` | 按 `web_scheme` + `port` + `web_path` 拼接，例如 `https://portal.lan/admin/login?tab=1#/node/2` |

`#` 不再被百分号编码（SPA 的 hash 路由必须保留），`?` 查询串同理；只有路径主体做 URL 编码。完整 URL 里若已自带 `user:pass@`，Basic 模式也不会覆盖它；否则 Basic 会把记录的账号密码插到主机名之前。在线检测与自定义模板的 `%1`/`%2` 取的是 URL 里的**主机名与端口**，不是 URL 字符串。服务端只接受 Web 记录的 `http://` / `https://` 完整地址，其它协议填 `://` 会报错。

### 系统设置（分组与冗余精简）

「系统设置」按原版 MFC `IDD_DIALOG1` 的 `GROUPBOX` 分成两块：

| 分区 | 内容 |
|---|---|
| 常规 | 在线检测超时、WOL 广播地址、本地 Agent 端口、Radmin 自动填登录窗 |
| 客户端程序路径 | Radmin / SSH / VNC / FlashFXP / WinSCP / 浏览器 六个路径（见下） |

所有**连接参数都归每条记录**：RDP 宽/高/色深/全屏、Radmin 全屏/控制模式收进折叠区「旧记录兼容默认值」（只给没单独配过的旧记录兜底）；Radmin 控制颜色、SSH / FTP / Web 命令行参数格式已下沉到「编辑主机」；`rdp_console`（`mstsc /admin`，原版「使用Console连接」）判定为冗余，已连同 `show_parent_hosts` 一起从默认设置和数据库里清除。

### 客户端路径配置（仿原版「RADMIN路径」按钮 + 编辑框）

原版「设置」对话框里，每个客户端是左侧一个 `PUSHBUTTON`（点它弹文件选择框）、右侧一个 `ES_AUTOHSCROLL` 编辑框。WebUI 保持这个骨架并加宽了弹窗：

| 控件 | 行为 |
|---|---|
| 左侧名称按钮（RADMIN / SSH / VNC / FLASHFXP / 浏览器路径） | 自动探测本机常见安装位置并回填绝对路径 |
| 中间路径输入框 | 可直接粘贴绝对路径，右侧徽标显示「已配置 / 留空·自动查找」 |
| 「浏览…」 | 在**运行 Agent 的那台机器**上弹置顶的原生文件选择框，选完自动回填；点击后按钮变「选择中…」并提示切到桌面/看任务栏 |
| 「全部自动探测」 | 一次探测全部客户端；浏览器路径**留空**时 Web 记录用系统默认浏览器，自动探测会填入找到的浏览器 |

路径探测与在线检测**都由本地 Agent 独占**，WebUI 通过 `127.0.0.1:<agent_port>` 回访：

| 接口 | 返回 |
|---|---|
| `GET /clients` | 本机探测到的六个客户端绝对路径（含 `flashfxp_path` / `winscp_path` / `browser_path`）、平台、本地覆盖值（探测含有限深度的常用目录扫描，约 0.2 秒） |
| `GET /browse?kind=radmin_path` | `{path, error}`；客户端路径（含 `flashfxp_path` / `winscp_path` / `browser_path`）用 `*.exe` 过滤器；取消返回空 `path`，无图形会话时返回 `error` 提示手填 |
| `GET /browse?kind=ssh_key_path` | 同上，但过滤器是 `*.ppk;*.pem;*.key`，用于「编辑主机 → SSH 设置 → 或：私钥文件（本机路径）」；只返回路径，私钥内容**不上传服务端**。若要把私钥内容加密存进数据库，用表单里的文件选择 / 粘贴框（浏览器直接读取文件内容，不走这个接口） |
| `POST /probe` | `{ok, data: {"<主机ID>": true/false}, source:"agent"}`，**在线状态的唯一来源**；body 是 WebUI 已有的 `{targets:[{id,address,port}], timeout_ms}`，从**运行 Agent 的机器**发 TCP connect |

这几个接口都校验 `Origin`（只允许服务端来源与 loopback），并带 Private Network Access 响应头，避免任意网页探测本机路径或弹窗。`/probe` 另有限制：目标最多 300 个，地址只接受主机名 / IP 字面量、端口 1–65535，超时限幅 0.05–5 秒。

**路径选择框**：Windows 走 PowerShell `OpenFileDialog`，并挂一个隐藏的 `TopMost` 宿主窗体——否则无 owner 的模态框会被浏览器窗口压在后面，看起来像「按钮没反应」；Linux 走 zenity / kdialog。弹窗期间 `/browse` 会一直占用该 HTTP 连接（最多 90 秒），选完或取消才返回，所以前端给了明确的「选择中…」状态。没有图形会话时直接粘贴路径即可。

**为什么在线检测只走 Agent**：真正打开远程客户端的是操作员电脑，不是服务端。若服务端在 `192.168.10.0/24`、被管主机在 `192.168.249.0/24` 且两个网段不通，从服务端发包必然全部超时，界面就会一直显示「离线」——这正是之前的现象。现在服务端已删除 `/api/hosts/probe` 与 `_tcp_probe()`，**没有任何服务端兜底**：WebUI 只请求 Agent 的 `POST /probe`，成功时状态栏显示「在线检测完成（本机 Agent）· n/N 在线」；Agent 未启动、版本过旧或超时，则清空结果、所有行回到「—」并明确提示「请启动/更新 start-agent.bat 后重试」，绝不把「没测到」当成「离线」。系统设置里的「在线检测超时（毫秒）」只作为 `timeout_ms` 由 WebUI 传给 Agent，服务端不读取它来发包。

排查「仍然全离线」时按顺序看：① 状态栏是不是「在线检测未完成：本地 Agent 不可用」——是就先启动 `start-agent.bat`；② 状态栏写的是「在线检测完成（本机 Agent）」但结果 0/N，说明**你这台电脑**连不上这些端口，在本机用 `telnet <地址> <端口>` 或 PowerShell `Test-NetConnection` 复核；③ 网络略慢可在系统设置把超时从 500 调到 2000 毫秒再测。注意 TCP 端口能连上才算「在线」，主机禁 ping 不影响判定，但防火墙只放行 ICMP 不放行远程端口时会显示离线。

| 设置项 | 留空时的查找顺序 |
|---|---|
| `radmin_path` | PATH → Agent 同目录 → 常见安装目录 / 常用下载目录 |
| `ssh_path` | PATH → Agent 同目录 → PuTTY 默认安装目录 |
| `vnc_path` | PATH → Agent 同目录 → TightVNC / RealVNC 默认目录 |
| `flashfxp_path` | PATH → Agent 同目录 → FlashFXP 默认安装目录 |
| `winscp_path` | PATH → Agent 同目录 → WinSCP 默认安装目录（Program Files / x86） |
| `browser_path` | 留空 = 系统默认浏览器（`webbrowser.open()`）；填写 / 自动探测后按指定浏览器启动 |

其余全局项只有 `radmin_autologin`（自动填 Radmin 安全性窗口，尽力而为）。Radmin 颜色、SSH 认证方式 / 私钥文件 / 命令行参数格式、FTP 与 Web 的协议 / 路径 / 参数格式都已在每台主机的「编辑」里配置，不再有全局入口。

⚠️ SSH 私钥有**两种互不冲突的来源**，优先级从高到低：① 表单上传 / 粘贴的私钥内容（加密存服务端数据库，换任何一台电脑都能用）；② 「或：私钥文件」里的**本机路径字符串**（私钥正文始终留在运行 Agent 的那台机器上，换电脑要保证路径一致）；③ 两者都空时交给 Pageant / ssh-agent 已加载的密钥或客户端交互输入。路径模式使用 `/browse` 让 Agent 弹本机文件框，**只返回路径、不读取正文**。

⚠️ 这些路径填的是**运行 Agent 的那台机器**上的路径。设置存在云端、会下发给所有 Agent；如果多台机器路径不同，可在本地配置文件加 `client_paths` 覆盖：

```json
{"client_paths": {"radmin_path": "D:\\tools\\radmin.exe"}}
```

### 每条记录单独配置连接参数

在「新增 / 编辑主机」里，选好连接类型后会出现对应的设置区。这些设置**跟着主机记录存**（`rm_hosts.options`），不是全局设置：

| 协议 | 设置项 | 实际生效方式 |
|---|---|---|
| RDP | 分辨率（全屏 / 800×600 … 2560×1440） | 选具体尺寸自动切窗口模式并写 `desktopwidth` / `desktopheight`；全屏用本机屏幕分辨率 |
| RDP | 色深 16 / 24 / 32 位 | `session bpp` |
| RDP | 显示桌面背景 | `disable wallpaper` / `disable themes` |
| RDP | 挂载本地磁盘 | `drivestoredirect:s:*` + `redirectdrives:i:1` |
| RDP | 连接远程音频 | `audiomode:i:0`（远程声音在本地播放），关闭为 `i:2` |
| Radmin | 连接方式：全屏 / 窗口 | 全屏追加 `/fullscreen` |
| Radmin | 控制方式：完全控制 / 仅限查看 / 文件传送 / 命令行连接 / 远程关机 | 分别对应 无参数 / `/noinput` / `/file` / `/telnet` / `/shutdown` |
| Radmin | 控制颜色：8 / 16 / 24 位 | `/8bpp` / `/16bpp` / `/24bpp`，默认 24 位 |
| SSH | 认证方式：密码 / 密钥对（私钥） | 密钥对登录**不传密码**：不生成 `-pw`，服务端连接票据也不再下发这条记录已保存的密码 |
| SSH | 私钥内容：选择文件 / 粘贴（**加密存入服务端数据库**） | 保存时 AES-256-GCM 加密写入 `rm_hosts.ssh_key_enc`；列表只回显文件名 + SHA-256 指纹，不下发明文。连接时由一次性票据下发到本机 Agent，落地成权限收紧的临时文件再传给 `-i` / `%5`，45 秒后删除 |
| SSH | 或：私钥文件（本机路径） | 追加 PuTTY `-i <路径>` / ssh `-i <路径>`；路径不存在会明确报错。优先级低于数据库私钥；两者都留空则由 Pageant / ssh-agent 已加载的密钥或客户端交互提供 |
| SSH | 软件命令行参数格式 | `%1` 地址 / `%2` 端口 / `%3` 账号 / `%4` 密码 / `%5` 私钥路径；**必须包含 `%1`**；密钥登录时自动去掉 `-pw %4`，模板没写 `%5` 会自动补 `-i`；留空则由 Agent 自动拼接 PuTTY / ssh 参数 |
| FTP | 连接协议：FTP / FTPS 隐式 SSL / FTPES 显式 TLS / SFTP over SSH | 决定 URL 前缀与默认端口（21 / 990 / 21 / 22），切换时表单自动改端口 |
| FTP | 登录方式：账号密码 / 匿名 | 匿名登录 URL 不带任何 userinfo，服务端票据也**不下发密码** |
| FTP | 远程初始路径 / 本地初始路径 | 远程路径写进 URL 并做 URL 编码（支持中文、空格）；本地路径追加 `-localpath=<本机目录>` |
| FTP | 启动方式：默认 / 最大化 / 最小化 / 托盘 | 追加 FlashFXP 官方 `-max` / `-min` / `-tray` |
| FTP | 命令行参数格式（可选） | `%0` FlashFXP 路径 / `%1` 地址 / `%2` 端口 / `%3` 账号 / `%4` 密码 / `%5` 完整 URL / `%6` 远程路径；**必须包含 `%5`**；留空则由 Agent 自动拼 URL、启动开关与 `-localpath` |
| Web | 主机地址（可填完整 URL） | 填 `http(s)://…` 时原样打开，下面三项不再参与拼接；只填主机名时才拼接 |
| Web | 页面协议：HTTPS / HTTP | 默认端口 443 / 80；切协议时表单自动改端口（**仅纯主机名模式**生效） |
| Web | 认证方式：不传密码（默认）/ URL 内嵌 Basic 认证 | 默认模式服务端票据**不下发密码**，由网站登录页自行输入；Basic 模式把账号密码插在 URL 主机名之前（会进浏览器历史，谨慎使用） |
| Web | URL 路径（可选） | 拼到 `http(s)://host:port/` 后面；路径主体做 URL 编码，`?query` 与 `#fragment` 原样保留（**仅纯主机名模式**生效） |
| Web | 浏览器命令行参数格式（可选） | `%0` 浏览器路径 / `%1` 主机名 / `%2` 端口 / `%3` 账号 / `%4` 密码 / `%5` 完整 URL；**必须包含 `%5`**；使用前需在「系统设置 → 客户端程序路径」指定浏览器路径，留空则用系统默认浏览器 |
| WinSCP | 连接协议：SFTP / SCP / FTP / FTPS / WebDAV / WebDAVS | 决定会话 URL 前缀与默认端口（22 / 22 / 21 / 990 / 80 / 443），切换时表单自动改端口 |
| WinSCP | 登录方式：账号密码 / 匿名 | 匿名登录自动合成 `anonymous:anonymous`（账号栏留空时用 `anonymous`，填了账号则用它作用户名），保存的密码**不下发**；密码登录 URL 为 `user:pass@host` |
| WinSCP | 远程初始目录 | 写进 URL 并做 URL 编码（支持中文、空格），登录后直接进入该目录 |
| WinSCP | 启动方式：默认 / 最小化 / 新实例 | 追加 WinSCP 官方 `/minimized` / `/newinstance`（默认会复用已开的 WinSCP 窗口） |
| WinSCP | 命令行参数格式（可选） | `%0` WinSCP 路径 / `%1` 地址 / `%2` 端口 / `%3` 账号 / `%4` 密码 / `%5` 完整会话 URL / `%6` 远程目录；**必须包含 `%5`**；密钥登录可在模板里自行加 `/privatekey="…ppk"`；留空则由 Agent 自动拼 URL 与启动开关 |

> 原版 MFC 菜单的第 4 项是「远程关机」(`/shutdown`)；这里按需求把「命令行连接」做成 `/telnet`，并把「远程关机」保留为第 5 个选项。

记录级选项是连接的**唯一来源**：服务端 `host_dict` 与票据兑换都会带上 `options`，Agent 用它覆盖旧的兼容默认值。服务端与 Agent 各做一层白名单校验：色深、控制方式、SSH 认证方式，以及 FTP / Web 的协议、认证与启动方式都只接受枚举值；SSH 参数格式与私钥路径会剥离控制字符、截断到 512 字符，且不含 `%1` 的模板一律丢弃；FTP / Web 模板要求含 `%5`（完整 URL），URL 路径会去掉引号与反斜杠、截断后由 Agent 做百分号编码，避免记录被篡改后变成任意命令。跨协议的键（例如在 FTP 记录里塞 `web_scheme`）会被直接丢弃。没配过选项的老记录由内置的协议默认值兜底（SSH 默认密码登录），不会破坏已有数据。SSH 模板会**先按参数切分、再逐项替换占位符**，所以密码为空或含空格时不会把后面的地址吞掉；值为空的 `-pw %4` / `-i %5` 开关会被整对删掉，不会留下 `-pw ""` 这种让 PuTTY 卡在密码阶段的残参。**私钥正文不在这个明文 `options` JSON 里**，而是单独加密存 `ssh_key_enc`，服务端白名单也会拒绝任何伪造的 `ssh_key` 值（必须是含 `PRIVATE KEY` / `PuTTY-User-Key-File` / `BEGIN SSH2` 标记、且 ≤64 KB 的文本）。

**SSH 密钥对登录 · 私钥存服务端数据库**：在「编辑主机 → SSH 设置 → 认证方式 = 密钥对登录」里，直接选 `.ppk` / `.pem` / `.key` 文件或粘贴 PEM 内容，保存后：

1. 浏览器读取文件文本，随主机表单一起提交；服务端校验格式标记与 64 KB 上限，用 `master.key` 做 AES-256-GCM 加密后写入 `rm_hosts.ssh_key_enc`。**主密钥只在服务端本机，云端库里只有密文**。
2. `/api/hosts` 列表和编辑框只显示「已保存：文件名 · SHA-256 指纹」，**不回显、不下发私钥正文**；想替换就重新选文件，想删除点「清除已保存私钥」。
3. 点「连接」时，一次性票据（60 秒、用完即焚）的兑换响应才把私钥正文连同 `ssh_key` 一起下发给本机 Agent；密码登录 / 非 SSH 记录拿到的永远是空对象。
4. Agent 把正文写进 `tempfile.mkdtemp()`（0700）里的临时文件，POSIX 上 `chmod 0600`（OpenSSH 强制要求），再用这个路径替换 `%5` 或追加 `-i`。客户端启动 45 秒后删除文件与目录，Agent 退出时 `atexit` 再兜底清理一次。
5. 若记录没保存私钥内容，则退回「或：私钥文件」里的本机路径；两者都空则交给 Pageant / ssh-agent。数据库私钥优先，所以换一台电脑打开 WebUI 也能连。

私钥明文只短暂存在于浏览器内存、服务端进程内存、票据响应体和本机临时文件里。**票据响应走的是 HTTP 时私钥和已保存的密码一样可能被内网抓包，务必按第七节套 HTTPS / VPN**。带口令的私钥仍需客户端弹窗输入口令（Agent 不会把口令写进命令行）。PuTTY 只认 `.ppk`，Linux `ssh` 只认 OpenSSH 格式，两者不通用，需要时用 PuTTYgen 转换；备份 / 恢复时私钥以密文形式进 JSON，恢复必须在同一份 `master.key` 下进行。

RDP 与 Radmin 一样是**一键直连**：WebUI 点「连接」只向本地 Agent 发一次性票据，不再弹确认框、不再下载 `.rdp` 文件。Linux 服务端生成不了 Windows DPAPI 加密块，而且 `mstsc` 命令行只能传地址/宽高/全屏，传不了色深、桌面背景、磁盘映射、远程音频和已保存的密码——所以 Windows Agent 在本机生成一份临时 `.rdp` 交给 `mstsc.exe`，用完即删。这个文件**不是浏览器下载物**，用户无需保存或双击。
把密码放在命令行参数里（PuTTY / sshpass / xfreerdp / FlashFXP URL）会被同机其他进程看到，只建议在可信的个人电脑上使用。密钥对登录的命令行里只有私钥**路径**（本机路径，或数据库私钥落地后的临时路径）、没有任何口令或密码，在这一点上更安全。FTP 密码与 Web Basic 密码都会出现在 URL 里：Agent 回显到 `/connect` 页面和日志时会替换成 `******`，但客户端进程参数仍是明文，**Web 记录请优先用网站自带登录页而不是 Basic 认证**。匿名 FTP 和普通 Web 记录压根不会从服务端拿到密码。

**悬浮卡片（不用点开编辑就能看参数）**：鼠标移到任意主机行上，会跟随指针弹出一张卡片，分三块显示 —— ① 连接目标、账号、是否已保存密码、所属分组、MAC；② 该记录的 RDP / Radmin / SSH / FTP / Web 配置值（SSH 会显示认证方式、**私钥来源**：服务端数据库加密 / Agent 本机路径 / Pageant，以及模板里的 `-pw` 在密钥登录时会被忽略的提示；FTP / Web 会显示 URL 协议、路径、认证方式与参数格式）；③ 本机 Agent 实际会用的命令行（RDP 还额外列出临时 `.rdp` 的 `screen mode id` / `desktopwidth` / `session bpp` / `drivestoredirect` / `audiomode` 等关键行）。密码一律显示为 `******`，卡片命令行的取值逻辑与 Agent 的模板处理完全一致。

卡片完全由浏览器里的 `host` 对象即时渲染，不新增接口、不请求 Agent，也不把 HTML 塞进 `data-` 属性（名称、备注、SSH 模板都会转义）。没配过选项的老记录标注「Agent 兼容默认值」，只配了一部分的记录标注「记录 + 默认值」：取值逻辑与 Agent 的 `_effective_settings()` 一致（全局兼容值打底、记录里实际存在的键才覆盖），不会编造不存在的值。行数据刷新、点击、拖拽或滚动时卡片自动收起。

---

## 六、主要 API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | 登录，返回令牌 |
| GET/POST/PUT/DELETE | `/api/groups`, `/api/groups/<id>` | 分组 |
| GET/POST | `/api/hosts`, `/api/hosts/move` | 主机列表 / 移动；**在线检测不在此处**，只由本地 Agent `POST /probe` 提供 |
| GET/PUT/DELETE | `/api/hosts/<id>` | 主机 |
| POST | `/api/hosts/<id>/credential` | 取明文密码；SSH 密钥登录时附带解密后的私钥 `ssh_key`（写审计）；匿名 FTP / 匿名 WinSCP 与非 Basic 的 Web 记录返回空密码 |
| GET/PUT | `/api/hosts/<id>/ssh-key` | admin 读取私钥正文（恢复用，写审计）／ editor 上传、替换或删除私钥；也可随主机表单的 `ssh_key` 字段一次提交 |
| POST | `/api/hosts/<id>/wol` | 网络唤醒 |
| POST | `/api/connect-ticket`, `/api/connect-ticket/redeem` | 一次性连接票据；兑现在密钥登录时把私钥正文交给本机 Agent |
| GET/PUT | `/api/settings` | 系统设置 |
| GET/POST/PUT/DELETE | `/api/users` | 用户管理（admin） |
| GET | `/api/audit` | 审计日志（admin） |
| GET/POST | `/api/export`, `/api/import` | JSON 备份 / 恢复 |
| GET | `/api/health` | 健康检查（含数据库类型） |

角色：`admin` 全部；`editor` 可改主机/分组、可取凭据与连接所需的私钥；`viewer` 只读且取不到任何密码或私钥正文。`/api/hosts` 列表只回显 `has_ssh_key` / 文件名 / 指纹，密文列 `ssh_key_enc` 从不出现在主机响应里。

---

## 七、安全建议

1. **上 HTTPS**：现在内网是 HTTP。对外访问请套 Nginx/Caddy 反代 + TLS，或只在 VPN / 内网用。
2. **改初始密码**：登录后立刻在「修改密码」里改掉；`.env` 里的 `BOOTSTRAP_PASSWORD` 只是首次建号用。
3. **备份密钥**：`data/master.key`、`data/secret.key` 单独离线备份；换机器要一起带过去。
4. **限制来源**：`CORS_ORIGINS` 生产环境别用 `*`，填实际 WebUI 来源。
5. **云数据库最小权限**：只给 `remotemgr` 库，别给 root；开启 TLS 与 IP 白名单。
6. **审计**：登录、取密码、导出、所有写操作都记在 `rm_audit`。
7. 在线探测只在本地 Agent 上进行：WebUI 传入的目标最多 300 个，地址只接受主机名 / IP 字面量（Web 完整 URL 会先解析出主机名与端口，不会把 URL 字符串当地址）、端口限 1–65535、超时限幅 0.05–5 秒，并校验 `Origin`；服务端不再提供任何探测接口，避免被当成内网端口扫描器。
8. **私钥入库后 HTTPS 更重要**：一次性票据的兑换响应会包含私钥正文（和密码一样）。私钥在库里是 AES-GCM 密文、主密钥不入库，但传输层若仍是明文 HTTP，内网抓包就能拿到；对外访问务必先上 TLS/VPN。给私钥本身设口令，并定期在审计日志里看 `ssh_key_read` / `ssh_key_export` / `connect_redeem +ssh_key`。
9. **FTP / WinSCP / Web 的 URL 凭据**：FTP 与 WinSCP 的会话 URL、Web Basic 认证 URL 都内含密码，会出现在客户端命令行 / 浏览器历史里。优先让网站自己弹登录页，匿名 FTP 就不要存密码；Agent 回显的命令行已脱敏，但不要把它贴到公开工单里。

---

## 八（附）、当前部署实例（2026-11-09）

| 项 | 值 |
|---|---|
| 主机 | `192.168.10.121`（Ubuntu 24.04.5，Python 3.12） |
| 访问地址 | `http://192.168.10.121:8800` |
| 初始账号 | `admin`，初始密码见目标机 `~/remotemgr/.env` 的 `BOOTSTRAP_PASSWORD`（登录后请立刻改） |
| 服务 | `remotemgr.service`，active + 开机自启；日志 `journalctl -u remotemgr -f` |
| 代码目录 | `~/remotemgr`（本机对应 `D:\rmd\remotemgr`） |
| 密钥 | `~/remotemgr/data/master.key`、`secret.key`（0600），需单独备份 |
| 数据库 | 当前为本地 SQLite `~/remotemgr/data/remotemgr.db` |
| 安装附加项 | 补装 `python3.12-venv`；pip 走阿里云镜像；systemd unit 设了 `TZ=Asia/Shanghai` |
| 验证 | `scripts/smoke_test.py` 13 项全通过（登录/CRUD/加密/票据/**私钥加密入库与下发**/**FTP 与 Web 记录**/**Web 完整 URL 地址**/**WinSCP 记录**/导出/审计/WebUI 静态资源） |

> 目标机家目录里原有的 `remotemgr-build-20261109/`（Go 写的 TCP 8896/8897 兼容服务）属于**另一个项目**，本次一行未动；新服务用 8800 端口，互不冲突。

---

## 九、已知边界

- 没有重写 MFC 客户端；老客户端不再直连数据库，改由 WebUI + Agent 承担。
- Radmin 自动填登录窗已按原版 `FindWindow` / `GetDlgItem` / `WM_SETTEXT` 移植，但依赖 Radmin Viewer 的窗口标题与控件 ID（2.2 / 3.x 中文版）；版本或语言不匹配时会退回手填。
- RDP 自动登录只在 Windows Agent 上可用：DPAPI 加密的密码块写进本机临时 `.rdp`，8 秒后删除；Linux Agent 走 `xfreerdp`，密码出现在命令行参数里。
- FTP 记录依赖 Windows 上的 FlashFXP（`ftps://` / `ftpes://` / `sftp://` 需要较新版本）；WinSCP 记录依赖 Windows 上的 WinSCP 5.x+（`/minimized` / `/newinstance` 开关与 `webdav(s)://` 前缀需 5.9+）；Linux Agent 会给出脱敏 URL 供手工打开。Web 记录走桌面默认浏览器，无图形会话（纯服务器）时需在系统设置里指定可用的浏览器路径，否则会明确报错。
- 服务端默认 HTTP；TLS 由反向代理负责。
- 一次性票据存在进程内存里，多实例部署需要换成共享存储（当前单机足够）。
