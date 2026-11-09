"""RemoteMgr C/S server: REST API + embedded WebUI.

Run directly for development::

    python app.py

or in production::

    waitress-serve --listen=0.0.0.0:8800 --threads=8 app:app
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from datetime import datetime
from functools import wraps

from flask import Flask, Response, g, jsonify, request, send_from_directory
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func, or_

import config
from crypto import decrypt_secret, encrypt_secret, hash_password, verify_password
from models import AuditLog, Group, Host, Setting, User, init_db, make_engine

# When frozen into a standalone binary, serve the WebUI from a real directory
# next to the executable (keeps the project layout editable / inspectable).
if getattr(sys, "frozen", False):
    _STATIC_FOLDER = str(Path(sys.executable).resolve().parent / "static")
else:
    _STATIC_FOLDER = "static"
app = Flask(__name__, static_folder=_STATIC_FOLDER, static_url_path="/static")
app.config["JSON_AS_ASCII"] = False
app.json.ensure_ascii = False

ENGINE = make_engine(config.DATABASE_URL, config.SQL_ECHO)
SESSION = init_db(ENGINE)

_TOKEN_SIGNER = URLSafeTimedSerializer(
    base64.urlsafe_b64encode(config.SECRET_KEY).decode("ascii"), salt="remotemgr-login"
)
_TICKET_SIGNER = URLSafeTimedSerializer(
    base64.urlsafe_b64encode(config.SECRET_KEY).decode("ascii"), salt="remotemgr-ticket"
)

PROTOCOLS = ("rdp", "radmin", "ssh", "realvnc", "tightvnc", "ftp", "web", "winscp")
PROTOCOL_DEFAULT_PORT = {"rdp": 3389, "radmin": 4899, "ssh": 22,
                         "realvnc": 5900, "tightvnc": 5900,
                         "ftp": 21, "web": 443, "winscp": 22}
# FlashFXP's Quick Connect / Site Manager URL prefixes (FTP, implicit SSL,
# explicit SSL, SFTP over SSH) and the two browser schemes. The default port
# for each scheme is used by the WebUI to auto-adjust the port field.
FTP_SCHEMES = ("ftp", "ftps", "ftpes", "sftp")
FTP_AUTHS = ("password", "anonymous")
FTP_WINDOWS = ("normal", "max", "min", "tray")
WEB_SCHEMES = ("https", "http")
WEB_AUTHS = ("none", "basic")
# WinSCP session URL prefixes; anonymous mode synthesizes anonymous:anonymous
# so one-click connect does not pop WinSCP's Login dialog.
WINSCP_SCHEMES = ("sftp", "scp", "ftp", "ftps", "webdav", "webdavs")
WINSCP_AUTHS = ("password", "anonymous")
WINSCP_WINDOWS = ("normal", "min", "new")
URL_PATH_FIELDS = ("ftp_path", "web_path", "winscp_dir")
URL_TEMPLATE_FIELDS = ("ftp_param_format", "web_param_format", "winscp_param_format")
ROLE_LEVEL = {"viewer": 1, "editor": 2, "admin": 3}
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

# --------------------------------------------------------------------------- #
# Per-host connection options (stored as JSON in rm_hosts.options)
# --------------------------------------------------------------------------- #
RDP_RESOLUTIONS = ("fullscreen", "800x600", "1024x768", "1280x720", "1366x768",
                   "1600x900", "1920x1080", "1920x1200", "2560x1440")
RDP_COLORS = ("16", "24", "32")
RADMIN_DISPLAYS = ("fullscreen", "window")
# "telnet" is the command-line mode asked for by the operator; "shutdown" keeps
# the original MFC menu's fourth entry (远程关机, /shutdown) available.
RADMIN_CONTROLS = ("full", "view", "file", "telnet", "shutdown")
RADMIN_COLORS = ("8", "16", "24")
# SSH can authenticate with a password or with a private key. ssh_key_path is
# a path on the machine running the Agent (key never leaves that PC); the key
# BODY can alternatively be uploaded and is stored AES-GCM encrypted in the
# separate ssh_key_enc column, never in this plaintext JSON options blob.
SSH_AUTHS = ("password", "key")
HOST_OPTION_DEFAULTS = {
    "rdp": {"rdp_resolution": "fullscreen", "rdp_color": "32",
            "rdp_wallpaper": False, "rdp_drives": False, "rdp_audio": False},
    "radmin": {"radmin_display": "fullscreen", "radmin_ctrl": "full",
               "radmin_color": "24"},
    "ssh": {"ssh_auth": "password", "ssh_key_path": "", "ssh_param_format": ""},
    "ftp": {"ftp_scheme": "ftp", "ftp_auth": "password", "ftp_path": "",
            "ftp_local_path": "", "ftp_window": "normal", "ftp_param_format": ""},
    "web": {"web_scheme": "https", "web_auth": "none", "web_path": "",
            "web_param_format": ""},
    "winscp": {"winscp_scheme": "sftp", "winscp_auth": "password",
               "winscp_dir": "", "winscp_window": "normal",
               "winscp_param_format": ""},
}


def _clean_option_text(value, max_len=512, keep_backslash=False) -> str:
    """Strip control characters / quotes from a record-supplied path or template.

    A Windows local path (ftp_local_path) legitimately contains backslashes and
    spaces, so it keeps them; URL paths are normalised to forward slashes.
    """
    text = "".join(ch for ch in str(value) if " " <= ch != "\x7f")
    if not keep_backslash:
        text = text.replace("\\", "/").replace('"', "").replace("'", "")
    return text.strip().strip('"').strip("'").strip()[:max_len]


def _parse_options(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _normalize_options(raw, protocol: str) -> dict:
    """Whitelist keys and values so a record can only contain known options."""
    if isinstance(raw, str):
        raw = _parse_options(raw)
    if not isinstance(raw, dict):
        raw = {}
    result = dict(HOST_OPTION_DEFAULTS.get(protocol, {}))
    for key, default in result.items():
        if key not in raw:
            continue
        value = raw[key]
        if isinstance(default, bool):
            result[key] = (value if isinstance(value, bool) else
                           str(value).strip().lower() in ("1", "true", "yes", "on"))
        elif key == "rdp_resolution" and value in RDP_RESOLUTIONS:
            result[key] = value
        elif key == "rdp_color" and str(value) in RDP_COLORS:
            result[key] = str(value)
        elif key == "radmin_display" and value in RADMIN_DISPLAYS:
            result[key] = value
        elif key == "radmin_ctrl" and value in RADMIN_CONTROLS:
            result[key] = value
        elif key == "radmin_color" and str(value) in RADMIN_COLORS:
            result[key] = str(value)
        elif key == "ssh_auth" and value in SSH_AUTHS:
            result[key] = value
        elif key == "ssh_key_path" and isinstance(value, str):
            # A local filesystem path on the Agent's machine. Strip control
            # characters and surrounding quotes, but keep spaces / backslashes
            # (Windows paths) and UNC prefixes intact.
            path = "".join(ch for ch in value if " " <= ch != "\x7f").strip()
            path = path.strip('"').strip("'").strip()[:512]
            result[key] = path
        elif key == "ssh_param_format" and isinstance(value, str):
            fmt = "".join(ch for ch in value if ch >= " ").strip()[:512]
            # Without the address placeholder a "format" could be an arbitrary
            # program; reject it and let the Agent build its default command.
            if "%1" in fmt:
                result[key] = fmt
        elif key == "ftp_scheme" and value in FTP_SCHEMES:
            result[key] = value
        elif key == "ftp_auth" and value in FTP_AUTHS:
            result[key] = value
        elif key == "ftp_window" and value in FTP_WINDOWS:
            result[key] = value
        elif key == "web_scheme" and value in WEB_SCHEMES:
            result[key] = value
        elif key == "web_auth" and value in WEB_AUTHS:
            result[key] = value
        elif key == "winscp_scheme" and value in WINSCP_SCHEMES:
            result[key] = value
        elif key == "winscp_auth" and value in WINSCP_AUTHS:
            result[key] = value
        elif key == "winscp_window" and value in WINSCP_WINDOWS:
            result[key] = value
        elif key in URL_PATH_FIELDS and isinstance(value, str):
            # URL path components are percent-encoded by the Agent; here we
            # only remove characters that could break out of a URL argument.
            result[key] = _clean_option_text(value, 256).lstrip("/")
        elif key == "ftp_local_path" and isinstance(value, str):
            result[key] = _clean_option_text(value, 512, keep_backslash=True)
        elif key in URL_TEMPLATE_FIELDS and isinstance(value, str):
            fmt = _clean_option_text(value, 512)
            # A custom command line must at least consume the generated URL,
            # otherwise it is just an arbitrary program with no target.
            if "%5" in fmt:
                result[key] = fmt
    return result


# --------------------------------------------------------------------------- #
# SSH private keys stored (encrypted) in the server database
# --------------------------------------------------------------------------- #
MAX_SSH_KEY_CHARS = 65536
# Deliberately loose: OpenSSH PEM, encrypted PEM, PuTTY .ppk and SSH.com keys
# all carry one of these markers. Anything else is most likely a public key or
# a wrong file and should be rejected before it is written to the database.
SSH_KEY_MARKERS = ("PRIVATE KEY", "PuTTY-User-Key-File", "BEGIN SSH2")
_SSH_KEY_KEEP = object()   # "field absent" is different from "delete the key"


def _parse_ssh_key_field(data: dict):
    """Validate an uploaded key. Return a dict, None (=remove) or _SSH_KEY_KEEP."""
    if "ssh_key" not in data:
        return _SSH_KEY_KEEP
    value = data.get("ssh_key")
    if value is None or (isinstance(value, dict) and value.get("remove")):
        return None
    if not isinstance(value, dict):
        raise ValueError("私钥内容格式不正确")
    content = str(value.get("content") or "")
    if not content:
        return None
    if len(content) > MAX_SSH_KEY_CHARS:
        raise ValueError("私钥内容过大（上限 64 KB）")
    if not any(marker in content for marker in SSH_KEY_MARKERS):
        raise ValueError("文件看起来不是 SSH 私钥（支持 OpenSSH/PEM、PuTTY .ppk、SSH2 格式）")
    raw_name = str(value.get("filename") or "private_key")
    filename = "".join(ch for ch in raw_name
                       if ch >= " " and ch not in '/\\:"*?<>|').strip()[:128]
    return {"filename": filename or "private_key", "content": content}


def _encode_ssh_key(value) -> str:
    return (encrypt_secret(json.dumps(value, ensure_ascii=False), config.MASTER_KEY)
            if value else "")


def _decode_ssh_key(host: Host) -> dict:
    """Decrypt the stored key body. Only used when building a connection."""
    if not host.ssh_key_enc:
        return {}
    try:
        raw = json.loads(decrypt_secret(host.ssh_key_enc, config.MASTER_KEY))
        content = str(raw.get("content") or "") if isinstance(raw, dict) else ""
        if not content:
            return {}
        return {"filename": str(raw.get("filename") or "private_key")[:128],
                "content": content}
    except Exception:
        return {}


def _ssh_key_meta(host: Host) -> dict:
    """Non-secret metadata for the WebUI; the key body is never in a list."""
    result = {"has_ssh_key": False, "ssh_key_filename": "", "ssh_key_fingerprint": ""}
    if not host.ssh_key_enc:
        return result
    key = _decode_ssh_key(host)
    result["has_ssh_key"] = True
    if not key:
        result["ssh_key_error"] = "私钥无法解密（服务端 master.key 不匹配？）"
        return result
    result["ssh_key_filename"] = key["filename"]
    result["ssh_key_fingerprint"] = hashlib.sha256(
        key["content"].encode("utf-8")).hexdigest()[:16]
    return result


_TICKETS: dict[str, tuple[int, float]] = {}
_TICKET_LOCK = threading.Lock()
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_LOGIN_LOCK = threading.Lock()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def db():
    if "db" not in g:
        g.db = SESSION()
    return g.db


@app.teardown_appcontext
def _close_db(_exc=None):
    session = g.pop("db", None)
    if session is not None:
        session.close()


def ok(data=None, **extra):
    payload = {"ok": True, "data": data}
    payload.update(extra)
    return jsonify(payload)


def fail(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def body() -> dict:
    value = request.get_json(silent=True)
    return value if isinstance(value, dict) else {}


def log_action(action: str, target: str = "", detail: str = "", username: str | None = None):
    user = getattr(g, "user", None) or {}
    try:
        db().add(AuditLog(
            username=username if username is not None else user.get("username", ""),
            action=action,
            target=str(target)[:128],
            detail=str(detail)[:512],
            ip=(request.remote_addr or "")[:64],
        ))
        db().commit()
    except Exception:  # auditing must never break the actual operation
        db().rollback()


def require(min_role: str = "viewer"):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = ""
            header = request.headers.get("Authorization", "")
            if header.lower().startswith("bearer "):
                token = header[7:].strip()
            token = token or request.args.get("token", "")
            if not token:
                return fail("未登录", 401)
            try:
                payload = _TOKEN_SIGNER.loads(token, max_age=config.TOKEN_TTL)
            except SignatureExpired:
                return fail("登录已过期，请重新登录", 401)
            except BadSignature:
                return fail("无效的登录令牌", 401)
            session = db()
            user = session.get(User, payload.get("uid"))
            if not user or not user.enabled or user.username != payload.get("u"):
                return fail("账号状态已变化，请重新登录", 401)
            g.user = {"id": user.id, "username": user.username, "role": user.role}
            if ROLE_LEVEL.get(user.role, 0) < ROLE_LEVEL[min_role]:
                return fail("权限不足", 403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def user_dict(user: User) -> dict:
    return {"id": user.id, "username": user.username, "role": user.role,
            "enabled": bool(user.enabled), "created_at": _ts(user.created_at)}


def group_dict(group: Group) -> dict:
    return {"id": group.id, "name": group.name, "parent_id": group.parent_id,
            "sort_order": group.sort_order}


def host_dict(host: Host, include_secret: bool = False) -> dict:
    result = {
        "id": host.id, "name": host.name, "group_id": host.group_id,
        "protocol": host.protocol, "address": host.address, "port": host.port,
        "mac": host.mac, "account": host.account, "note": host.note,
        "options": _parse_options(host.options), "sort_order": host.sort_order,
        "has_password": bool(host.password_enc),
        "created_at": _ts(host.created_at), "updated_at": _ts(host.updated_at),
    }
    # Only metadata: the key body is NEVER part of a normal host response.
    result.update(_ssh_key_meta(host))
    if include_secret:
        try:
            result["password"] = decrypt_secret(host.password_enc, config.MASTER_KEY)
        except Exception:
            result["password"] = ""
            result["password_error"] = "凭据无法解密（主密钥不匹配？）"
    return result


def _connection_password(host: Host) -> str:
    """A key-auth SSH record must not receive its stored password at all.

    Otherwise a stale password could still be handed to the Agent and end up
    on a command line even though the record says "log in with a private key".
    """
    opts = _parse_options(host.options)
    if host.protocol == "ssh" and opts.get("ssh_auth") == "key":
        return ""
    if host.protocol == "ftp" and opts.get("ftp_auth") == "anonymous":
        return ""
    if host.protocol == "winscp" and opts.get("winscp_auth") == "anonymous":
        return ""
    if host.protocol == "web" and opts.get("web_auth") != "basic":
        # A normal browser bookmark needs no credential at all; handing the
        # stored password to the Agent would only put it on a command line.
        return ""
    return decrypt_secret(host.password_enc, config.MASTER_KEY)


def _connection_ssh_key(host: Host) -> dict:
    """Decrypt the database-held key only for an actual SSH key connection."""
    opts = _parse_options(host.options)
    if host.protocol != "ssh" or opts.get("ssh_auth") != "key":
        return {}
    return _decode_ssh_key(host)


def _ts(value) -> str:
    if isinstance(value, datetime):
        return value.isoformat(sep=" ", timespec="seconds")
    return ""


def _clean(value, default="", max_len=128) -> str:
    text = "" if value is None else str(value).strip()
    text = "".join(ch for ch in text if ch >= " " or ch in "\t")
    return text[:max_len] or default


def _validate_host(data: dict, existing: Host | None = None) -> dict:
    """Validate and normalize host fields. Raises ValueError with a message."""
    protocol = _clean(data.get("protocol"), "rdp", 16).lower()
    if protocol not in PROTOCOLS:
        raise ValueError("不支持的连接类型")
    name = _clean(data.get("name"), "", 64)
    # A Web record's address field may hold a complete URL (path, query and
    # hash route included), which is longer than a plain hostname.
    address = _clean(data.get("address"), "", 512 if protocol == "web" else 128)
    if not name:
        raise ValueError("主机名称不能为空")
    if not address:
        raise ValueError("主机地址不能为空")
    if "://" in address:
        # Only Web records accept a full URL; other protocols need a bare host
        # or IP because their clients build the target themselves.
        if protocol != "web" or not re.match(r"^https?://[^/?#\s]+", address, re.I):
            raise ValueError("只有 Web 记录可填完整 URL，且必须以 http:// 或 https:// 开头并含主机名")
    try:
        port = int(data.get("port", PROTOCOL_DEFAULT_PORT[protocol]))
    except (TypeError, ValueError) as exc:
        raise ValueError("端口必须是数字") from exc
    if not 1 <= port <= 65535:
        raise ValueError("端口超出范围")
    mac = _clean(data.get("mac"), "", 24).upper()
    if mac and not MAC_RE.match(mac):
        raise ValueError("MAC 地址格式应为 AA:BB:CC:DD:EE:FF")
    try:
        group_id = int(data.get("group_id", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("分组 ID 无效") from exc
    account = _clean(data.get("account"), "", 64)
    note = _clean(data.get("note"), "", 512)
    password = data.get("password")
    result = {
        "name": name, "address": address, "port": port, "protocol": protocol,
        "mac": mac, "group_id": group_id, "account": account, "note": note,
        "options": json.dumps(_normalize_options(data.get("options"), protocol),
                              ensure_ascii=False, separators=(",", ":")),
    }
    # An omitted password means "keep the current one"; an explicit "" clears it.
    if password is not None:
        result["_password"] = str(password)[:256]
    ssh_key = _parse_ssh_key_field(data)
    if ssh_key is not _SSH_KEY_KEEP:
        result["_ssh_key"] = ssh_key
    return result


def _apply_host(host: Host, fields: dict):
    for key in ("name", "address", "port", "protocol", "mac", "group_id",
                "account", "note", "options"):
        setattr(host, key, fields[key])
    if "_password" in fields:
        host.password_enc = encrypt_secret(fields["_password"], config.MASTER_KEY)
    if "_ssh_key" in fields:
        host.ssh_key_enc = _encode_ssh_key(fields["_ssh_key"])


def _descendant_group_ids(session, group_id: int) -> set[int]:
    result = {group_id}
    frontier = [group_id]
    while frontier:
        parents = frontier
        frontier = [row.id for row in session.query(Group).filter(Group.parent_id.in_(parents)).all()]
        for item in frontier:
            if item not in result:
                result.add(item)
    return result


def _wol(mac: str, broadcast: str) -> None:
    raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(raw) != 6:
        raise ValueError("MAC 地址无效")
    packet = b"\xff" * 6 + raw * 16
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, (broadcast, 9))
    finally:
        sock.close()


def _login_throttled(ip: str) -> bool:
    now = time.time()
    with _LOGIN_LOCK:
        hits = [t for t in _LOGIN_ATTEMPTS.get(ip, []) if now - t < 60]
        hits.append(now)
        _LOGIN_ATTEMPTS[ip] = hits
        return len(hits) > 15


@app.after_request
def _cors(response):
    origins = config.CORS_ORIGINS
    origin = request.headers.get("Origin", "")
    if "*" in origins:
        response.headers["Access-Control-Allow-Origin"] = "*"
    elif origin in origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


@app.route("/api/<path:_path>", methods=["OPTIONS"])
def _options(_path):
    return Response(status=204)


# --------------------------------------------------------------------------- #
# bootstrap / auth
# --------------------------------------------------------------------------- #
def bootstrap():
    """Create default settings and, on a fresh database, the first admin."""
    session = SESSION()
    try:
        for key, value in config.DEFAULT_SETTINGS.items():
            if session.get(Setting, key) is None:
                session.add(Setting(key=key, value=value))
        for key in config.DEPRECATED_SETTINGS:
            stale = session.get(Setting, key)
            if stale is not None:
                session.delete(stale)
        session.commit()
        if session.query(User).count() == 0:
            password = config.BOOTSTRAP_PASSWORD or secrets.token_urlsafe(14)
            session.add(User(username=config.BOOTSTRAP_ADMIN,
                              password_hash=hash_password(password), role="admin"))
            session.commit()
            if config.BOOTSTRAP_PASSWORD:
                print(f"[RemoteMgr] initial admin '{config.BOOTSTRAP_ADMIN}' created "
                      f"with the configured BOOTSTRAP_PASSWORD")
            else:
                config.DATA_DIR.mkdir(parents=True, exist_ok=True)
                path = config.DATA_DIR / "initial_admin.txt"
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(f"{config.BOOTSTRAP_ADMIN}\t{password}\n")
                print(f"[RemoteMgr] initial admin '{config.BOOTSTRAP_ADMIN}' created; "
                      f"the random password is in {path} (mode 0600)")
    finally:
        session.close()


@app.get("/api/health")
def health():
    return ok({"status": "up", "database": config.DATABASE_URL.split("://")[0],
               "time": datetime.now().isoformat(timespec="seconds")})


@app.post("/api/login")
def login():
    if _login_throttled(request.remote_addr or ""):
        return fail("尝试过于频繁，请一分钟后再试", 429)
    data = body()
    username = _clean(data.get("username"), "", 64)
    password = str(data.get("password", ""))
    session = db()
    user = session.query(User).filter(func.lower(User.username) == username.lower()).first()
    if not user or not user.enabled or not verify_password(password, user.password_hash):
        log_action("login_failed", username, "账号或密码错误", username=username)
        return fail("账号或密码错误", 401)
    token = _TOKEN_SIGNER.dumps({"uid": user.id, "u": user.username, "role": user.role})
    log_action("login", user.username, "登录成功", username=user.username)
    return ok({"token": token, "user": user_dict(user), "expires_in": config.TOKEN_TTL})


@app.get("/api/me")
@require()
def me():
    return ok(g.user)


@app.post("/api/change-password")
@require()
def change_password():
    data = body()
    old = str(data.get("old_password", ""))
    new = str(data.get("new_password", ""))
    if len(new) < 8:
        return fail("新密码至少 8 位")
    session = db()
    user = session.get(User, g.user["id"])
    if not user or not verify_password(old, user.password_hash):
        return fail("原密码不正确", 403)
    user.password_hash = hash_password(new)
    session.commit()
    log_action("change_password", user.username)
    return ok({"changed": True})


# --------------------------------------------------------------------------- #
# groups
# --------------------------------------------------------------------------- #
@app.get("/api/groups")
@require()
def list_groups():
    rows = db().query(Group).order_by(Group.sort_order, Group.id).all()
    return ok([group_dict(row) for row in rows])


@app.post("/api/groups")
@require("editor")
def create_group():
    data = body()
    name = _clean(data.get("name"), "", 64)
    if not name:
        return fail("分组名不能为空")
    try:
        parent_id = int(data.get("parent_id", 0))
    except (TypeError, ValueError):
        return fail("父分组 ID 无效")
    session = db()
    if parent_id and session.get(Group, parent_id) is None:
        return fail("父分组不存在")
    if session.query(Group).filter(Group.name == name, Group.parent_id == parent_id).count():
        return fail("同级下已存在同名分组")
    group = Group(name=name, parent_id=parent_id,
                  sort_order=int(data.get("sort_order", 0) or 0))
    session.add(group)
    session.commit()
    log_action("group_create", name, f"id={group.id}")
    return ok(group_dict(group))


@app.put("/api/groups/<int:group_id>")
@require("editor")
def update_group(group_id: int):
    session = db()
    group = session.get(Group, group_id)
    if not group:
        return fail("分组不存在", 404)
    data = body()
    if "name" in data:
        name = _clean(data.get("name"), "", 64)
        if not name:
            return fail("分组名不能为空")
        group.name = name
    if "parent_id" in data:
        try:
            parent_id = int(data["parent_id"])
        except (TypeError, ValueError):
            return fail("父分组 ID 无效")
        if parent_id == group_id or parent_id in _descendant_group_ids(session, group_id):
            return fail("不能把分组移动到自己的子分组下")
        if parent_id and session.get(Group, parent_id) is None:
            return fail("父分组不存在")
        group.parent_id = parent_id
    if "sort_order" in data:
        group.sort_order = int(data["sort_order"] or 0)
    session.commit()
    log_action("group_update", group.name, f"id={group_id}")
    return ok(group_dict(group))


@app.delete("/api/groups/<int:group_id>")
@require("editor")
def delete_group(group_id: int):
    session = db()
    group = session.get(Group, group_id)
    if not group:
        return fail("分组不存在", 404)
    ids = _descendant_group_ids(session, group_id)
    child_count = len(ids) - 1
    host_count = session.query(Host).filter(Host.group_id.in_(ids)).count()
    force = request.args.get("force") == "1"
    if (child_count or host_count) and not force:
        return fail(f"该分组包含 {child_count} 个子分组、{host_count} 台主机，"
                   f"如确认级联删除请加 force=1", 409)
    if force:
        session.query(Host).filter(Host.group_id.in_(ids)).delete(synchronize_session=False)
        for item in ids:
            target = session.get(Group, item)
            if target:
                session.delete(target)
    else:
        session.delete(group)
    session.commit()
    log_action("group_delete", group.name, f"id={group_id} force={force}")
    return ok({"deleted": True, "hosts_deleted": host_count if force else 0})


# --------------------------------------------------------------------------- #
# hosts
# --------------------------------------------------------------------------- #
@app.get("/api/hosts")
@require()
def list_hosts():
    session = db()
    query = session.query(Host)
    group_id = request.args.get("group_id")
    if group_id not in (None, "", "0"):
        try:
            gid = int(group_id)
        except ValueError:
            return fail("分组 ID 无效")
        ids = _descendant_group_ids(session, gid) if request.args.get("include_desc") == "1" else {gid}
        query = query.filter(Host.group_id.in_(ids))
    keyword = _clean(request.args.get("q"), "", 64)
    if keyword and keyword != "*":
        pattern = f"%{keyword}%"
        query = query.filter(or_(Host.name.like(pattern), Host.address.like(pattern),
                                 Host.account.like(pattern), Host.note.like(pattern)))
    rows = query.order_by(Host.sort_order, Host.id).limit(2000).all()
    return ok([host_dict(row) for row in rows], total=len(rows))


@app.get("/api/hosts/<int:host_id>")
@require()
def get_host(host_id: int):
    host = db().get(Host, host_id)
    if not host:
        return fail("主机不存在", 404)
    return ok(host_dict(host))


@app.post("/api/hosts")
@require("editor")
def create_host():
    try:
        fields = _validate_host(body())
    except ValueError as exc:
        return fail(str(exc))
    session = db()
    if fields["group_id"] and session.get(Group, fields["group_id"]) is None:
        return fail("分组不存在")
    if session.query(Host).filter(Host.group_id == fields["group_id"],
                                   Host.name == fields["name"],
                                   Host.protocol == fields["protocol"]).count():
        return fail("同分组下已存在同名、同类型的主机")
    host = Host()
    _apply_host(host, fields)
    session.add(host)
    session.commit()
    log_action("host_create", host.name, f"id={host.id} {host.protocol}")
    return ok(host_dict(host))


@app.put("/api/hosts/<int:host_id>")
@require("editor")
def update_host(host_id: int):
    session = db()
    host = session.get(Host, host_id)
    if not host:
        return fail("主机不存在", 404)
    data = body()
    merged = host_dict(host)
    merged.update(data)
    try:
        fields = _validate_host(merged)
    except ValueError as exc:
        return fail(str(exc))
    if fields["group_id"] and session.get(Group, fields["group_id"]) is None:
        return fail("分组不存在")
    _apply_host(host, fields)
    session.commit()
    log_action("host_update", host.name, f"id={host_id}")
    return ok(host_dict(host))


@app.delete("/api/hosts/<int:host_id>")
@require("editor")
def delete_host(host_id: int):
    session = db()
    host = session.get(Host, host_id)
    if not host:
        return fail("主机不存在", 404)
    session.delete(host)
    session.commit()
    log_action("host_delete", host.name, f"id={host_id}")
    return ok({"deleted": True})


@app.post("/api/hosts/bulk-delete")
@require("editor")
def bulk_delete_hosts():
    ids = body().get("ids", [])
    ids = [int(i) for i in ids if str(i).isdigit()][:500]
    if not ids:
        return fail("没有选中主机")
    session = db()
    session.query(Host).filter(Host.id.in_(ids)).delete(synchronize_session=False)
    session.commit()
    log_action("host_bulk_delete", "", f"ids={ids}")
    return ok({"deleted": len(ids)})


@app.post("/api/hosts/move")
@require("editor")
def move_hosts():
    data = body()
    try:
        group_id = int(data.get("group_id", 0))
    except (TypeError, ValueError):
        return fail("分组 ID 无效")
    ids = [int(i) for i in data.get("ids", []) if str(i).isdigit()][:500]
    if not ids:
        return fail("没有选中主机")
    session = db()
    if group_id and session.get(Group, group_id) is None:
        return fail("分组不存在")
    session.query(Host).filter(Host.id.in_(ids)).update(
        {Host.group_id: group_id}, synchronize_session=False)
    session.commit()
    log_action("host_move", f"group={group_id}", f"ids={ids}")
    return ok({"moved": len(ids)})


@app.post("/api/hosts/<int:host_id>/credential")
@require("editor")
def get_credential(host_id: int):
    host = db().get(Host, host_id)
    if not host:
        return fail("主机不存在", 404)
    log_action("credential_read", host.name, f"id={host_id}")
    try:
        password = _connection_password(host)
    except Exception:
        return fail("凭据无法解密，请检查服务端 master.key", 500)
    ssh_key = _connection_ssh_key(host)
    if ssh_key:
        log_action("ssh_key_read", host.name, f"id={host_id} filename={ssh_key['filename']}")
    return ok({"host": host_dict(host), "password": password, "ssh_key": ssh_key})


@app.get("/api/hosts/<int:host_id>/ssh-key")
@require("admin")
def get_ssh_key(host_id: int):
    """Admin-only recovery of a key body; the WebUI never calls this."""
    host = db().get(Host, host_id)
    if not host:
        return fail("主机不存在", 404)
    key = _decode_ssh_key(host)
    if not key:
        return fail("该主机没有已保存的私钥，或私钥无法解密", 404)
    log_action("ssh_key_export", host.name, f"id={host_id} filename={key['filename']}")
    return ok(key)


@app.put("/api/hosts/<int:host_id>/ssh-key")
@require("editor")
def put_ssh_key(host_id: int):
    """Upload/replace/delete the encrypted private key of one host record."""
    host = db().get(Host, host_id)
    if not host:
        return fail("主机不存在", 404)
    data = body()
    # Accept both {"ssh_key": {...}} (host form) and a bare {"content": ...}.
    if "ssh_key" not in data and ("content" in data or "remove" in data):
        data = {"ssh_key": data}
    try:
        parsed = _parse_ssh_key_field(data)
    except ValueError as exc:
        return fail(str(exc))
    if parsed is _SSH_KEY_KEEP:
        return fail("缺少 ssh_key 内容；如需删除请传 {\"remove\": true}")
    host.ssh_key_enc = _encode_ssh_key(parsed)
    db().commit()
    log_action("ssh_key_delete" if parsed is None else "ssh_key_upload",
               host.name, f"id={host_id} filename={(parsed or {}).get('filename', '')}")
    return ok(host_dict(host))


# NOTE: there is intentionally no /api/hosts/probe endpoint. Online detection
# belongs to the local Agent (POST /probe, 127.0.0.1:<agent_port>): it runs on
# the operator's machine, the same machine that opens mstsc / Radmin / PuTTY.
# Probing from the server produced false "离线" for hosts on a different LAN
# segment, so the server never sends a TCP probe. "probe_timeout_ms" is merely
# stored here and forwarded to the Agent by the WebUI.


@app.post("/api/hosts/<int:host_id>/wol")
@require("editor")
def wake_host(host_id: int):
    host = db().get(Host, host_id)
    if not host:
        return fail("主机不存在", 404)
    if not MAC_RE.match(host.mac or ""):
        return fail("未配置合法的 MAC 地址")
    try:
        _wol(host.mac, get_settings_map().get("wol_broadcast", config.WOL_BROADCAST))
    except (ValueError, OSError) as exc:
        return fail(f"唤醒包发送失败：{exc}")
    log_action("wol", host.name, f"mac={host.mac}")
    return ok({"sent": True, "mac": host.mac})


# --------------------------------------------------------------------------- #
# one-shot connect tickets (WebUI -> local Agent)
# --------------------------------------------------------------------------- #
@app.post("/api/connect-ticket")
@require("editor")
def create_connect_ticket():
    host_id = body().get("host_id")
    host = db().get(Host, int(host_id)) if str(host_id).isdigit() else None
    if not host:
        return fail("主机不存在", 404)
    ticket = _TICKET_SIGNER.dumps({"uid": g.user["id"], "h": host.id, "n": time.time()})
    with _TICKET_LOCK:
        _TICKETS[ticket] = (host.id, time.time() + config.TICKET_TTL)
    log_action("connect_ticket", host.name, f"id={host.id}")
    return ok({"ticket": ticket, "host_id": host.id, "expires_in": config.TICKET_TTL})


@app.post("/api/connect-ticket/redeem")
def redeem_connect_ticket():
    """Public but one-shot and short lived; called by the local Agent."""
    ticket = str(body().get("ticket", ""))
    try:
        payload = _TICKET_SIGNER.loads(ticket, max_age=config.TICKET_TTL)
    except (BadSignature, SignatureExpired):
        return fail("连接票据无效或已过期", 403)
    with _TICKET_LOCK:
        entry = _TICKETS.pop(ticket, None)
        for key, (_, expiry) in list(_TICKETS.items()):
            if expiry < time.time():
                _TICKETS.pop(key, None)
    if not entry or entry[0] != payload.get("h") or entry[1] < time.time():
        return fail("连接票据已被使用或已过期", 403)
    host = db().get(Host, entry[0])
    if not host:
        return fail("主机不存在", 404)
    try:
        password = _connection_password(host)
    except Exception:
        return fail("凭据无法解密", 500)
    ssh_key = _connection_ssh_key(host)
    log_action("connect_redeem", host.name,
               f"id={host.id}" + (" +ssh_key" if ssh_key else ""),
               username=f"ticket:{payload.get('uid')}")
    return ok({"host": host_dict(host), "password": password,
               "ssh_key": ssh_key, "settings": get_settings_map()})


# --------------------------------------------------------------------------- #
# settings / users / audit / backup
# --------------------------------------------------------------------------- #
def get_settings_map() -> dict:
    """Stored values merged over defaults, so newly added settings reach the
    Agent even before the next startup seeds the missing rows."""
    values = dict(config.DEFAULT_SETTINGS)
    # Ignore rows left behind by older builds: only known keys may reach the Agent.
    values.update({row.key: row.value for row in db().query(Setting).all()
                   if row.key in config.DEFAULT_SETTINGS})
    return values


@app.get("/api/settings")
@require()
def get_settings():
    values = dict(config.DEFAULT_SETTINGS)
    values.update(get_settings_map())
    return ok(values)


@app.put("/api/settings")
@require("admin")
def put_settings():
    session = db()
    for key, value in body().items():
        if key not in config.DEFAULT_SETTINGS:
            continue
        row = session.get(Setting, key)
        if row:
            row.value = str(value)
        else:
            session.add(Setting(key=key, value=str(value)))
    session.commit()
    log_action("settings_update", "", "更新系统设置")
    return ok(get_settings_map())


@app.get("/api/users")
@require("admin")
def list_users():
    rows = db().query(User).order_by(User.id).all()
    return ok([user_dict(row) for row in rows])


@app.post("/api/users")
@require("admin")
def create_user():
    data = body()
    username = _clean(data.get("username"), "", 64)
    password = str(data.get("password", ""))
    role = _clean(data.get("role"), "viewer", 16)
    if not username or len(password) < 8:
        return fail("用户名不能为空，密码至少 8 位")
    if role not in ROLE_LEVEL:
        return fail("角色只能是 admin / editor / viewer")
    session = db()
    if session.query(User).filter(func.lower(User.username) == username.lower()).count():
        return fail("用户名已存在")
    user = User(username=username, password_hash=hash_password(password), role=role)
    session.add(user)
    session.commit()
    log_action("user_create", username, f"role={role}")
    return ok(user_dict(user))


@app.put("/api/users/<int:user_id>")
@require("admin")
def update_user(user_id: int):
    session = db()
    user = session.get(User, user_id)
    if not user:
        return fail("用户不存在", 404)
    data = body()
    if "role" in data:
        if data["role"] not in ROLE_LEVEL:
            return fail("角色无效")
        user.role = data["role"]
    if "enabled" in data:
        user.enabled = bool(data["enabled"])
        if user.id == g.user["id"] and not user.enabled:
            return fail("不能禁用当前登录账号")
    if data.get("password"):
        if len(str(data["password"])) < 8:
            return fail("密码至少 8 位")
        user.password_hash = hash_password(str(data["password"]))
    session.commit()
    log_action("user_update", user.username, f"id={user_id}")
    return ok(user_dict(user))


@app.delete("/api/users/<int:user_id>")
@require("admin")
def delete_user(user_id: int):
    if user_id == g.user["id"]:
        return fail("不能删除当前登录账号")
    session = db()
    user = session.get(User, user_id)
    if not user:
        return fail("用户不存在", 404)
    session.delete(user)
    session.commit()
    log_action("user_delete", user.username, f"id={user_id}")
    return ok({"deleted": True})


@app.get("/api/audit")
@require("admin")
def list_audit():
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
    except ValueError:
        limit = 200
    rows = db().query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    return ok([{
        "id": r.id, "created_at": _ts(r.created_at), "username": r.username,
        "action": r.action, "target": r.target, "detail": r.detail, "ip": r.ip,
    } for r in rows])


@app.get("/api/export")
@require("admin")
def export_backup():
    session = db()
    include_secrets = request.args.get("secrets", "1") == "1"
    hosts = []
    for host in session.query(Host).order_by(Host.id).all():
        item = host_dict(host)
        if include_secrets:
            # Ciphertext only. Restoring secrets requires the same master.key.
            item["password_enc"] = host.password_enc
            item["ssh_key_enc"] = host.ssh_key_enc
        hosts.append(item)
    payload = {
        "format": "remotemgr-backup", "version": 1,
        "exported_at": datetime.now().isoformat(timespec="seconds"),
        "groups": [group_dict(g) for g in session.query(Group).order_by(Group.id).all()],
        "hosts": hosts,
        "settings": get_settings_map(),
    }
    log_action("export", "", f"hosts={len(hosts)}")
    raw = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(raw, mimetype="application/json", headers={
        "Content-Disposition": 'attachment; filename="remotemgr-backup.json"'})


@app.post("/api/import")
@require("admin")
def import_backup():
    data = body()
    if data.get("format") != "remotemgr-backup":
        return fail("不是有效的备份文件")
    session = db()
    group_map: dict[int, int] = {}
    created_hosts = 0
    try:
        for item in data.get("groups", []):
            old_id = int(item["id"])
            existing = session.query(Group).filter(
                Group.name == _clean(item.get("name"), "", 64)).first()
            if existing:
                group_map[old_id] = existing.id
                continue
            group = Group(name=_clean(item.get("name"), "未命名", 64),
                          parent_id=0, sort_order=int(item.get("sort_order", 0) or 0))
            session.add(group)
            session.flush()
            group_map[old_id] = group.id
        for item in data.get("groups", []):
            parent_old = int(item.get("parent_id", 0) or 0)
            if parent_old in group_map:
                group = session.get(Group, group_map[int(item["id"])])
                if group and group_map[parent_old] != group.id:
                    group.parent_id = group_map[parent_old]
        for item in data.get("hosts", []):
            old_group = int(item.get("group_id", 0) or 0)
            group_id = group_map.get(old_group, 0)
            fields = _validate_host(item)
            if session.query(Host).filter(Host.name == fields["name"],
                                          Host.group_id == group_id,
                                          Host.protocol == fields["protocol"]).count():
                continue
            host = Host()
            _apply_host(host, fields)
            host.group_id = group_id
            if item.get("password_enc") and not host.password_enc:
                host.password_enc = str(item["password_enc"])
            elif item.get("password"):
                host.password_enc = encrypt_secret(str(item["password"]), config.MASTER_KEY)
            if item.get("ssh_key_enc") and not host.ssh_key_enc:
                host.ssh_key_enc = str(item["ssh_key_enc"])
            session.add(host)
            created_hosts += 1
        session.commit()
    except Exception as exc:  # roll back the whole import on any error
        session.rollback()
        return fail(f"导入失败：{exc}")
    log_action("import", "", f"hosts={created_hosts}")
    return ok({"groups": len(group_map), "hosts": created_hosts})


# --------------------------------------------------------------------------- #
# static WebUI
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.errorhandler(404)
def _not_found(_exc):
    if request.path.startswith("/api/"):
        return fail("接口不存在", 404)
    return send_from_directory(app.static_folder, "index.html")


@app.errorhandler(500)
def _server_error(_exc):
    return fail("服务端内部错误，请查看日志", 500)


bootstrap()


if __name__ == "__main__":
    print(f"[RemoteMgr] listening on http://{config.BIND_HOST}:{config.BIND_PORT}")
    print(f"[RemoteMgr] database: {config.DATABASE_URL}")
    try:
        import waitress
        waitress.serve(app, host=config.BIND_HOST, port=config.BIND_PORT, threads=8)
    except ImportError:
        # waitress is bundled for the standalone binary; fall back for dev runs.
        app.run(host=config.BIND_HOST, port=config.BIND_PORT, threaded=True)
