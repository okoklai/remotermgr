#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RemoteMgr local connection agent (zero third-party dependencies).

The WebUI cannot launch mstsc / PuTTY / VNC viewer because of the browser
sandbox. This agent runs on the operator's own machine, fetches the credential
on demand and starts the local client, preserving the original "double click
to connect" experience.

    python remotemgr_agent.py login --user admin --password '...'
    python remotemgr_agent.py list
    python remotemgr_agent.py connect 12
    python remotemgr_agent.py serve            # WebUI one-click connect

The agent only binds 127.0.0.1. A one-shot, 60-second ticket from the server
is required for every connection; the login token is never put in a URL.
"""
from __future__ import annotations

import argparse
import atexit
import ctypes
import html
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEFAULT_SERVER = os.environ.get("REMOTEMGR_SERVER", "http://192.168.10.121:8800")
DEFAULT_PORT = int(os.environ.get("REMOTEMGR_AGENT_PORT", "17860"))
CONFIG_PATH = Path(os.environ.get("REMOTEMGR_AGENT_CONFIG",
                                  str(Path.home() / ".remotemgr_agent.json")))
IS_WINDOWS = platform.system() == "Windows"


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
def http_json(server: str, path: str, payload=None, token: str | None = None,
             timeout: int = 10) -> dict:
    url = server.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST" if data is not None else "GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not result.get("ok"):
        raise RuntimeError(result.get("error", "服务端返回错误"))
    return result.get("data")


def load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(config: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass  # Windows has no POSIX mode bits


def _config_json_path() -> "Path | None":
    """Locate an optional config.json carrying server connection info.

    Search order: REMOTEMGR_CONFIG_JSON env → next to the executable (frozen)
    or script (dev) → current working directory.
    """
    env = os.environ.get("REMOTEMGR_CONFIG_JSON")
    if env:
        p = Path(env).expanduser()
        if p.is_file():
            return p
    if getattr(sys, "frozen", False):
        candidate = Path(sys.executable).resolve().parent / "config.json"
    else:
        candidate = Path(__file__).resolve().parent / "config.json"
    for c in (candidate, Path.cwd() / "config.json"):
        if c.is_file():
            return c
    return None


def load_json_config() -> dict:
    """Load the optional connection config.json (server / port / token / ...)."""
    p = _config_json_path()
    if not p:
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def resolve_token(args) -> str:
    if args.token:
        return args.token
    jc = load_json_config()
    if jc.get("token") and (not jc.get("server") or jc.get("server") == args.server):
        return jc["token"]
    home = load_config()
    if home.get("token") and (not home.get("server") or home.get("server") == args.server):
        return home["token"]
    raise RuntimeError("尚未登录：先执行 login，或传 --token / --user + --password")


# --------------------------------------------------------------------------- #
# Windows DPAPI: mstsc expects a CryptProtectData-encrypted password blob
# --------------------------------------------------------------------------- #
def crypt_rdp_password(password: str) -> str:
    if not IS_WINDOWS:
        raise RuntimeError("DPAPI 只在 Windows 可用")

    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.c_void_p)]

    # The original MFC code widens every byte to UTF-16LE; do the same for ASCII.
    wide = password.encode("utf-16-le") + b"\x00\x00"
    buffer = ctypes.create_string_buffer(wide)
    blob_in = DATA_BLOB(len(wide), ctypes.cast(buffer, ctypes.c_void_p))
    blob_out = DATA_BLOB()

    crypt32 = ctypes.windll.crypt32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.c_wchar_p, ctypes.c_wchar_p,
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    if not crypt32.CryptProtectData(ctypes.byref(blob_in), "psw", None, None, None,
                                    0x1, ctypes.byref(blob_out)):
        raise OSError("CryptProtectData 失败，错误码 %s" % ctypes.get_last_error())
    kernel32 = ctypes.windll.kernel32
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    try:
        raw = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        # pbData is a 64-bit pointer; without argtypes ctypes would cast it
        # to a 32-bit int and raise OverflowError.
        kernel32.LocalFree(ctypes.c_void_p(blob_out.pbData))
    return raw.hex().upper()


# --------------------------------------------------------------------------- #
# client launchers
# --------------------------------------------------------------------------- #
# One source of truth for "where a viewer may live", shared by connect_host()
# and the /clients probe used by the WebUI settings dialog.
CLIENT_CANDIDATES = {
    "radmin_path": {
        "label": "Radmin Viewer", "names": ("radmin.exe",),
        "paths": (r"C:\Program Files\Radmin\radmin.exe",
                  r"C:\Program Files (x86)\Radmin\radmin.exe",
                  r"C:\Program Files\Famatech\Radmin Viewer 3\radmin.exe"),
    },
    "ssh_path": {
        "label": "PuTTY / SSH 客户端", "names": ("putty.exe",),
        "paths": (r"C:\Program Files\PuTTY\putty.exe",
                  r"C:\Program Files (x86)\PuTTY\putty.exe"),
    },
    "vnc_path": {
        "label": "VNC Viewer", "names": ("vncviewer.exe", "tvnviewer.exe", "vncviewer"),
        "paths": (r"C:\Program Files\TightVNC\tvnviewer.exe",
                  r"C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe"),
    },
    "flashfxp_path": {
        "label": "FlashFXP", "names": ("flashfxp.exe",),
        "paths": (r"C:\Program Files\FlashFXP\flashfxp.exe",
                  r"C:\Program Files (x86)\FlashFXP\flashfxp.exe"),
    },
    "winscp_path": {
        "label": "WinSCP", "names": ("winscp.exe",),
        # WinSCP 6 installs per-user or to Program Files; 5.x used (x86).
        "paths": (r"C:\Program Files\WinSCP\WinSCP.exe",
                  r"C:\Program Files (x86)\WinSCP\WinSCP.exe"),
    },
    "browser_path": {
        "label": "浏览器（Web 记录，留空用系统默认）",
        "names": ("chrome.exe", "msedge.exe", "firefox.exe"),
        "paths": (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                  r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                  r"C:\Program Files\Mozilla Firefox\firefox.exe"),
    },
}

EXE_FILE_FILTER = "可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*"
# /browse also serves the per-record SSH private key picker. It must not be
# part of CLIENT_CANDIDATES or /clients would try to "discover" a key file.
BROWSE_KINDS = {
    key: {"label": spec["label"], "filter": EXE_FILE_FILTER}
    for key, spec in CLIENT_CANDIDATES.items()
}
BROWSE_KINDS["ssh_key_path"] = {
    "label": "SSH 私钥文件",
    "title": "选择 SSH 私钥文件（本机 .ppk / .pem / .key）",
    "filter": "私钥文件 (*.ppk;*.pem;*.key)|*.ppk;*.pem;*.key|所有文件 (*.*)|*.*",
}


def _find_executable(names, extra_paths=()):
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    # Original MFC behaviour: an exe sitting next to the program is usable too.
    if getattr(sys, "frozen", False):
        here = Path(sys.executable).resolve().parent
    else:
        here = Path(__file__).resolve().parent
    for name in names:
        for folder in (here, here.parent):
            candidate = folder / name
            if candidate.is_file():
                return str(candidate)
    for path in extra_paths:
        if path and Path(path).is_file():
            return path
    return None


def _client_setting(settings: dict, key: str) -> str:
    """Prefer a per-machine override in the local config, then server settings."""
    local = (load_config().get("client_paths") or {}).get(key, "")
    return str(local or (settings or {}).get(key, "") or "").strip().strip('"').strip("'")


def _find_client(settings: dict, key: str, names=None, extra_paths=None, label=None):
    """Resolve a viewer path, honouring the original project's custom-path setting."""
    spec = CLIENT_CANDIDATES.get(key, {})
    names = names if names is not None else spec.get("names", ())
    extra_paths = extra_paths if extra_paths is not None else spec.get("paths", ())
    label = label or spec.get("label", "客户端")
    custom = _client_setting(settings, key)
    if custom:
        if Path(custom).is_file():
            return custom
        raise RuntimeError(
            f"设置的 {label} 路径不存在：{custom}。"
            f"请到 WebUI「系统设置 → {key}」改成正确路径，或清空让 Agent 自动查找。")
    found = _find_executable(names, extra_paths)
    if found:
        return found
    hint = names[0] if names else "客户端程序"
    raise RuntimeError(
        f"未找到 {label}。请到 WebUI「系统设置 → {key}」填写 {hint} 的完整路径"
        "（指运行 Agent 的那台机器），或把它加入 PATH。")


def _radmin_autologin(address: str, account: str, password: str, wait_s: float = 8.0):
    """Port of the original MFC RadminConnent(): fill the security dialog.

    Radmin Viewer 2.2 / 3.x title it "Radmin 安全性：<host>"; the account and
    password boxes are control ids 0x7ff / 0x800 and OK is WM_COMMAND 0x78.
    Best effort only: a different locale or version just means manual input.
    """
    if not IS_WINDOWS or not password:
        return
    u = ctypes.windll.user32
    u.FindWindowW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    u.FindWindowW.restype = ctypes.c_void_p
    u.GetDlgItem.argtypes = [ctypes.c_void_p, ctypes.c_int]
    u.GetDlgItem.restype = ctypes.c_void_p
    u.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                               ctypes.c_size_t, ctypes.c_wchar_p]
    u.PostMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                               ctypes.c_size_t, ctypes.c_ssize_t]
    titles = (f"Radmin 安全性：{address}", f"Radmin 安全性: {address}",
              f"Radmin Security: {address}")
    deadline = time.time() + wait_s
    hwnd = None
    while time.time() < deadline and not hwnd:
        for title in titles:
            hwnd = u.FindWindowW(None, title)
            if hwnd:
                break
        if not hwnd:
            time.sleep(0.2)
    if not hwnd:
        print("[agent] 未等到 Radmin 登录窗口，需手动输入凭据", flush=True)
        return
    user_box = u.GetDlgItem(hwnd, 0x7FF)
    pass_box = u.GetDlgItem(hwnd, 0x800)
    if user_box and account:
        u.SendMessageW(user_box, 0x000C, 0, account)      # WM_SETTEXT
    if pass_box:
        u.SendMessageW(pass_box, 0x000C, 0, password)
    u.PostMessageW(hwnd, 0x0111, 0x78, 0)                 # WM_COMMAND, OK
    print("[agent] Radmin 登录窗口已自动填写", flush=True)


def _launch(argv) -> str:
    subprocess.Popen(argv, close_fds=not IS_WINDOWS)
    return " ".join(str(item) for item in argv)


# --------------------------------------------------------------------------- #
# Per-record connection options
# --------------------------------------------------------------------------- #
RADMIN_CONTROL_FLAGS = {
    "full": "", "view": "/noinput", "file": "/file",
    "telnet": "/telnet", "shutdown": "/shutdown",
}
# Records use the literal bit depth; "0/1/2" maps the old global index so a
# mixed-version deployment still resolves to a valid Radmin switch.
RADMIN_COLOR_FLAGS = {
    "8": "/8bpp", "16": "/16bpp", "24": "/24bpp",
    "0": "/8bpp", "1": "/16bpp", "2": "/24bpp",
}
RDP_BOOL_DEFAULTS = {"rdp_wallpaper": "0", "rdp_drives": "0", "rdp_audio": "0"}
# FlashFXP Quick Connect URL prefixes (see its help file / Site Manager).
FTP_SCHEMES = ("ftp", "ftps", "ftpes", "sftp")
FTP_SCHEME_PORTS = {"ftp": 21, "ftps": 990, "ftpes": 21, "sftp": 22}
FTP_AUTHS = ("password", "anonymous")
FTP_WINDOWS = {"normal": "", "max": "-max", "min": "-min", "tray": "-tray"}
WEB_SCHEMES = ("https", "http")
WEB_SCHEME_PORTS = {"https": 443, "http": 80}
WEB_AUTHS = ("none", "basic")
# WinSCP session URL prefixes (sftp/scp/ftp/ftps/webdav/webdavs) and the
# default port each scheme implies. Switches: /minimized, /newinstance.
WINSCP_SCHEMES = ("sftp", "scp", "ftp", "ftps", "webdav", "webdavs")
WINSCP_SCHEME_PORTS = {"sftp": 22, "scp": 22, "ftp": 21, "ftps": 990,
                       "webdav": 80, "webdavs": 443}
WINSCP_AUTHS = ("password", "anonymous")
WINSCP_WINDOWS = {"normal": "", "min": "/minimized", "new": "/newinstance"}


def _effective_settings(host: dict, settings: dict) -> dict:
    """Per-record options win over global settings.

    Values are whitelisted here as well, so even a hand-edited record cannot
    inject arbitrary switches into a client's command line.
    """
    eff = dict(settings or {})
    opts = host.get("options")
    if not isinstance(opts, dict) or not opts:
        return eff

    resolution = opts.get("rdp_resolution")
    if resolution == "fullscreen":
        eff["rdp_fullscreen"] = "1"
    elif isinstance(resolution, str) and re.fullmatch(r"\d{3,5}x\d{3,5}", resolution):
        width, height = resolution.lower().split("x")
        eff["rdp_width"], eff["rdp_height"] = width, height
        # A fixed resolution only takes effect in windowed mode.
        eff["rdp_fullscreen"] = "0"
    color = str(opts.get("rdp_color", ""))
    if color in ("16", "24", "32"):
        eff["rdp_color"] = color
    for key, default in RDP_BOOL_DEFAULTS.items():
        value = opts.get(key)
        if isinstance(value, bool):
            eff[key] = "1" if value else "0"
        elif value is not None:
            eff[key] = ("1" if str(value).strip().lower() in
                        ("1", "true", "yes", "on") else "0")
        else:
            eff.setdefault(key, default)

    display = opts.get("radmin_display")
    if display in ("fullscreen", "window"):
        eff["radmin_fullscreen"] = "1" if display == "fullscreen" else "0"
    control = opts.get("radmin_ctrl")
    if control in RADMIN_CONTROL_FLAGS:
        eff["radmin_ctrl"] = control
    colour = str(opts.get("radmin_color", ""))
    if colour in RADMIN_COLOR_FLAGS:
        eff["radmin_color"] = colour
    auth = opts.get("ssh_auth")
    eff["ssh_auth"] = auth if auth in ("password", "key") else "password"
    if "ssh_key_path" in opts:
        raw = opts.get("ssh_key_path")
        path = ("".join(ch for ch in raw if " " <= ch != "\x7f").strip()
                if isinstance(raw, str) else "")
        eff["ssh_key_path"] = path.strip('"').strip("'").strip()[:512]
    else:
        eff.setdefault("ssh_key_path", "")
    # The record is authoritative for the SSH template: an explicitly empty
    # value must also disable a legacy global format string.
    if "ssh_param_format" in opts:
        raw = opts.get("ssh_param_format")
        fmt = "".join(ch for ch in raw if ch >= " ").strip()[:512] if isinstance(raw, str) else ""
        eff["ssh_param_format"] = fmt if "%1" in fmt else ""

    # FTP / Web records: these have no legacy global equivalents, so the
    # per-record value is the only source. Validate enums and templates here
    # as a second layer behind the server's whitelist.
    for key, allowed in (("ftp_scheme", FTP_SCHEMES), ("ftp_auth", FTP_AUTHS),
                         ("ftp_window", tuple(FTP_WINDOWS)),
                         ("web_scheme", WEB_SCHEMES), ("web_auth", WEB_AUTHS),
                         ("winscp_scheme", WINSCP_SCHEMES),
                         ("winscp_auth", WINSCP_AUTHS),
                         ("winscp_window", tuple(WINSCP_WINDOWS))):
        value = opts.get(key)
        eff[key] = value if value in allowed else allowed[0]
    for key in ("ftp_path", "web_path", "ftp_local_path", "winscp_dir",
                "ftp_param_format", "web_param_format", "winscp_param_format"):
        raw = opts.get(key)
        text = ("".join(ch for ch in raw if " " <= ch != "\x7f").strip()
                if isinstance(raw, str) else "")
        if key in ("ftp_path", "web_path", "winscp_dir"):
            text = (text.replace("\\", "/").replace('"', "").replace("'", "")
                    .strip().lstrip("/")[:256])
        else:
            text = text.strip('"').strip("'").strip()[:512]
            if key.endswith("_param_format") and "%5" not in text:
                text = ""
        eff[key] = text
    return eff


def _ssh_flags(auth: str, password: str, key_path: str, fmt: str):
    """Normalise SSH credentials and drop switches whose value would be empty.

    A key login must never send ``-pw``: PuTTY would submit an empty password
    and can stall before it tries Pageant / ``-i``. Likewise an empty password
    or a missing ``%5`` must not leave a dangling ``-pw ""`` / ``-i ""`` token.
    """
    key_mode = auth == "key"
    pwd = "" if key_mode else (password or "")
    key = (key_path or "").strip()
    if key and not Path(key).is_file():
        raise RuntimeError(
            "SSH 私钥文件不存在：%s（路径必须指运行 Agent 那台机器上的文件）" % key)
    cleaned = fmt or ""
    if cleaned:
        if not pwd:
            cleaned = re.sub(r"(?:^|\s)-pw\s+%4\b", " ", cleaned)
        if not key:
            cleaned = re.sub(r"(?:^|\s)-i\s+%5\b", " ", cleaned)
    return key_mode, pwd, key, cleaned.strip()


def ssh_template_argv(fmt, address, port, account, password, key_path,
                      auth="password", posix=None):
    """Expand a per-record command template, or return None to use defaults."""
    key_mode, pwd, key, fmt = _ssh_flags(auth, password, key_path, fmt)
    if not fmt or "%1" not in fmt:
        return None
    template = shlex.split(fmt, posix=(not IS_WINDOWS if posix is None else posix))
    argv = [token.replace("%1", address).replace("%2", str(port))
                 .replace("%3", account).replace("%4", pwd).replace("%5", key)
            for token in template]
    argv = [token for token in argv if token != ""]
    # An older template written for password auth has no %5: still honour a
    # record that switched to key auth by inserting -i right after the exe.
    if key_mode and key and "%5" not in fmt and "-i" not in argv:
        argv[1:1] = ["-i", key]
    return argv or None


def ssh_default_argv(executable, address, port, account, password,
                     key_path, auth):
    key_mode, pwd, key, _ = _ssh_flags(auth, password, key_path, "")
    argv = [executable, "-ssh"]
    if account:
        argv += ["-l", account]
    if key_mode and key:
        argv += ["-i", key]
    elif not key_mode and pwd:
        argv += ["-pw", pwd]
    argv += ["-P", str(port), address]
    return argv


def ssh_linux_argv(address, port, account, password, key_path, auth):
    key_mode, pwd, key, _ = _ssh_flags(auth, password, key_path, "")
    argv = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-p", str(port)]
    if key:
        argv += ["-i", key]
    argv.append(f"{account or 'root'}@{address}")
    return argv, key_mode, pwd


# --------------------------------------------------------------------------- #
# SSH private keys delivered by the server (encrypted at rest in the DB)
# --------------------------------------------------------------------------- #
_SSH_KEY_TEMP_FILES: list[str] = []
_KEY_CLEANUP_SECONDS = 45


def _cleanup_ssh_key_files():
    """Last-resort cleanup when the Agent process exits."""
    for path in list(_SSH_KEY_TEMP_FILES):
        try:
            os.remove(path)
        except OSError:
            pass
        try:
            os.rmdir(os.path.dirname(path))
        except OSError:
            pass


atexit.register(_cleanup_ssh_key_files)


def _materialize_ssh_key(ssh_key, fallback_path: str, auth: str):
    """Write a server-held private key to a private temp file for the client.

    Returns ``(key_path, used_database_key)``. A key stored in the database
    takes precedence over the Agent-local ``ssh_key_path``, so the same record
    can be used from any PC. The file sits in a 0700 directory and is 0600 on
    POSIX (OpenSSH refuses anything looser); it is deleted shortly after the
    client starts and again at process exit. Windows relies on the per-user
    temp directory ACL because POSIX mode bits do not apply there.
    """
    if auth != "key":
        return fallback_path, False
    payload = ssh_key if isinstance(ssh_key, dict) else {}
    content = str(payload.get("content") or "")
    if not content:
        return fallback_path, False
    raw_name = str(payload.get("filename") or "private_key")
    name = os.path.basename(raw_name.replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:64] or "private_key"
    if name in (".", ".."):     # never let a crafted name point outside the dir
        name = "private_key"
    if Path(name).suffix.lower() not in (".ppk", ".pem", ".key", ".txt"):
        name += ".key"
    folder = tempfile.mkdtemp(prefix="remotemgr_key_")
    path = str(Path(folder) / name)
    # newline="" keeps PEM / PPK line endings exactly as uploaded.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
        stream.write(content)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    _SSH_KEY_TEMP_FILES.append(path)

    def cleanup():
        time.sleep(_KEY_CLEANUP_SECONDS)
        try:
            os.remove(path)
            os.rmdir(folder)
            _SSH_KEY_TEMP_FILES.remove(path)
        except (OSError, ValueError):
            pass
    threading.Thread(target=cleanup, daemon=True).start()
    return path, True


def _rdp_windows(host: dict, password: str, settings: dict) -> str:
    address = host["address"]
    port = host["port"]
    full_address = address if port == 3389 else f"{address}:{port}"
    lines = [
        "screen mode id:i:2" if settings.get("rdp_fullscreen", "1") == "1" else "screen mode id:i:1",
        f"desktopwidth:i:{settings.get('rdp_width', '1024')}",
        f"desktopheight:i:{settings.get('rdp_height', '768')}",
        f"session bpp:i:{settings.get('rdp_color', '32')}",
        f"full address:s:{full_address}",
        f"username:s:{host.get('account', '')}",
        "compression:i:1", "keyboardhook:i:2", "redirectclipboard:i:1",
        "autoreconnection enabled:i:1", "authentication level:i:0",
        "networkautodetect:i:0", "connection type:i:6",
    ]
    # Per-record display options, mirroring the original MstscConnent() flags.
    disabled = "0" if settings.get("rdp_wallpaper", "0") == "1" else "1"
    drives = settings.get("rdp_drives", "0") == "1"
    audio = settings.get("rdp_audio", "0") == "1"
    lines += [
        f"disable wallpaper:i:{disabled}", f"disable themes:i:{disabled}",
        "allow font smoothing:i:1", "disable menu anims:i:1",
        "drivestoredirect:s:" + ("*" if drives else ""),
        "redirectdrives:i:" + ("1" if drives else "0"),
        "audiomode:i:" + ("0" if audio else "2"),
    ]
    if password:
        try:
            lines.append("password 51:b:" + crypt_rdp_password(password))
            lines.append("prompt for credentials:i:0")
        except Exception as exc:  # fall back to prompting the user
            lines.append("prompt for credentials:i:1")
            print(f"[agent] 无法生成自动登录密码：{exc}", file=sys.stderr)
    else:
        lines.append("prompt for credentials:i:1")

    handle, path = tempfile.mkstemp(prefix="remotemgr_", suffix=".rdp")
    with os.fdopen(handle, "w", encoding="ascii") as stream:
        stream.write("\r\n".join(lines) + "\r\n")
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    mstsc = str(Path(system_root) / "System32" / "mstsc.exe")
    argv = [mstsc, path]
    _launch(argv)

    def cleanup():
        time.sleep(8)
        try:
            os.remove(path)
        except OSError:
            pass
    threading.Thread(target=cleanup, daemon=True).start()
    return f"mstsc 已启动：{full_address}（临时 .rdp 8 秒后删除）"


# --------------------------------------------------------------------------- #
# FTP (FlashFXP) / Web (browser) URL + command line helpers
# --------------------------------------------------------------------------- #
WEB_URL_RE = re.compile(r"^https?://", re.I)


def _url_netloc(address: str, port: int, default_port: int) -> str:
    host = str(address or "").strip()
    # IPv6 literals must be bracketed inside a URL.
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    return host if port == default_port else f"{host}:{port}"


def _url_userinfo(account: str, password: str) -> str:
    if not account and not password:
        return ""
    user = urllib.parse.quote(str(account or ""), safe="")
    if password:
        return f"{user}:{urllib.parse.quote(password, safe='')}@"
    return f"{user}@" if user else ""


def _url_tail(raw: str) -> str:
    """Encode a URL path while KEEPING ?query and #fragment as-is.

    A pasted SPA route such as ``static/#/proxies/tcp`` must stay a fragment:
    percent-encoding the '#' would turn it into an ordinary path segment and
    the page would never open. Same for ``?a=1&b=2`` query strings.
    """
    value = str(raw or "").strip().lstrip("/")
    value = "".join(ch for ch in value if " " <= ch != "\x7f"
                    and ch not in "\"'\\")[:256]
    fragment = None
    if "#" in value:
        value, fragment = value.split("#", 1)
    query = None
    if "?" in value:
        value, query = value.split("?", 1)
    tail = "/" + urllib.parse.quote(value, safe="/%:@!$&()*+,;=~._-")
    if query is not None:
        tail += "?" + urllib.parse.quote(query, safe="/%?&=+~._-:@!,;")
    if fragment is not None:
        tail += "#" + urllib.parse.quote(fragment, safe="/%?&=+~._-:@!,;")
    return tail


def parse_web_address(address: str):
    """Split a full http(s):// URL pasted into the host-address field.

    Web records are commonly just a bookmark: the operator pastes the whole
    address, including port, path, query and hash route. In that case the URL
    itself is authoritative and the split fields (web_scheme / port /
    web_path) must NOT be re-applied, or we would end up with something like
    ``http://[http://host/path]:443/``.

    Returns None for a plain hostname, which keeps the legacy split-field mode.
    """
    raw = str(address or "").strip()
    if not WEB_URL_RE.match(raw):
        return None
    try:
        parts = urllib.parse.urlsplit(raw)
        hostname, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not hostname:
        return None
    hostpart = "[" + hostname + "]" if ":" in hostname else hostname
    if port:
        hostpart += f":{port}"
    userinfo = ""
    if parts.username:
        userinfo = urllib.parse.quote(
            urllib.parse.unquote(parts.username), safe="")
        if parts.password:
            userinfo += ":" + urllib.parse.quote(
                urllib.parse.unquote(parts.password), safe="")
        userinfo += "@"
    return {
        "scheme": parts.scheme.lower(),
        "hostname": hostname,
        "hostpart": hostpart,
        "userinfo": userinfo,
        "path": parts.path or "/",
        "query": parts.query,
        "fragment": parts.fragment,
        "port": port or WEB_SCHEME_PORTS.get(parts.scheme.lower(), 443),
    }


def connection_url(host: dict, password: str, settings: dict, kind: str) -> str:
    """Build the ftp:// / sftp:// / http(s):// URL handed to the local client."""
    if kind == "web":
        # A full URL in the address field wins: keep its scheme, port, path,
        # query and fragment verbatim. Only Basic credentials may be inserted.
        page = parse_web_address(host.get("address", ""))
        if page:
            userinfo = page["userinfo"]
            if not userinfo and settings.get("web_auth") == "basic":
                userinfo = _url_userinfo(str(host.get("account") or ""), password)
            tail = page["path"]
            if page["query"]:
                tail += "?" + page["query"]
            if page["fragment"]:
                tail += "#" + page["fragment"]
            return f"{page['scheme']}://{userinfo}{page['hostpart']}{tail}"
    if kind == "ftp":
        scheme = settings.get("ftp_scheme")
        if scheme not in FTP_SCHEMES:
            scheme = "ftp"
        default_port = FTP_SCHEME_PORTS[scheme]
        show_cred = settings.get("ftp_auth") != "anonymous"
        path = settings.get("ftp_path", "")
    elif kind == "winscp":
        scheme = settings.get("winscp_scheme")
        if scheme not in WINSCP_SCHEMES:
            scheme = "sftp"
        default_port = WINSCP_SCHEME_PORTS[scheme]
        show_cred = settings.get("winscp_auth") != "anonymous"
        path = settings.get("winscp_dir", "")
    else:
        scheme = settings.get("web_scheme")
        if scheme not in WEB_SCHEMES:
            scheme = "https"
        default_port = WEB_SCHEME_PORTS[scheme]
        show_cred = settings.get("web_auth") == "basic"
        path = settings.get("web_path", "")
    try:
        port = int(host.get("port") or default_port)
    except (TypeError, ValueError):
        port = default_port
    netloc = _url_netloc(host.get("address", ""), port, default_port)
    # Anonymous FTP / plain Web records must not carry any userinfo at all:
    # FlashFXP does anonymous login when the URL has no credentials.
    if kind == "winscp" and not show_cred:
        # WinSCP has no "implicit anonymous" mode: a URL without credentials
        # pops its Login dialog. Synthesize a conventional anonymous login so
        # one-click connect stays one click. The stored password never leaves
        # the server for anonymous records.
        user = urllib.parse.quote(str(host.get("account") or "") or "anonymous",
                                  safe="")
        return f"{scheme}://{user}:anonymous@{netloc}" + _url_tail(path)
    userinfo = (_url_userinfo(str(host.get("account") or ""), password)
                if show_cred else "")
    return f"{scheme}://{userinfo}{netloc}" + _url_tail(path)


def client_template_argv(fmt: str, exe: str, host: dict, password: str,
                         url: str, remote_path: str = ""):
    """Expand a full per-record command line, or return None for the default.

    Placeholders: %0 client path, %1 address, %2 port, %3 account, %4
    password, %5 complete URL, %6 remote path (FTP only). A template without
    %5 is ignored: it could not possibly connect to the intended target.
    """
    if not fmt or "%5" not in fmt:
        return None
    mapping = {
        "%0": exe, "%1": str(host.get("address", "")),
        "%2": str(host.get("port", "")), "%3": str(host.get("account") or ""),
        "%4": password, "%5": url, "%6": remote_path,
    }
    # posix=True strips quotes correctly; %0 is substituted AFTER splitting
    # so a Windows path with backslashes never gets mangled.
    argv = []
    for token in shlex.split(fmt, posix=True):
        token = re.sub(r"%[0-6]", lambda m: mapping.get(m.group(0), m.group(0)), token)
        if token:
            argv.append(token)
    if not argv:
        return None
    first = argv[0]
    if first == exe or first.lower() in ("flashfxp.exe", "browser.exe",
                                         "winscp.exe", "winscp.com",
                                         "chrome.exe", "msedge.exe", "firefox.exe"):
        argv[0] = exe
    elif not Path(first).is_file():
        raise RuntimeError(
            "命令行参数格式首项必须是 %0（客户端路径）或有效的可执行文件路径")
    return argv


def _redact(text: str, password: str) -> str:
    """Never echo a credential into the /connect page or the Agent log."""
    if not password:
        return text
    return (text.replace(urllib.parse.quote(password, safe=""), "******")
                .replace(password, "******"))


def connect_host(host: dict, password: str, settings: dict | None = None,
                 ssh_key: dict | None = None) -> str:
    settings = _effective_settings(host, settings or {})
    protocol = host["protocol"]
    address, port = host["address"], host["port"]
    account = host.get("account", "") or ""

    if protocol == "rdp":
        if IS_WINDOWS:
            return _rdp_windows(host, password, settings)
        viewer = _find_executable(("xfreerdp3", "xfreerdp", "wlfreerdp"))
        if not viewer:
            raise RuntimeError("未找到 xfreerdp，请先安装 freerdp2-x11 / freerdp3-x11")
        argv = [viewer, f"/v:{address}:{port}"]
        if account:
            argv.append(f"/u:{account}")
        if password:
            argv.append(f"/p:{password}")
        argv.append("/bpp:" + str(settings.get("rdp_color", "32")))
        if settings.get("rdp_fullscreen", "1") == "1":
            argv.append("/f")
        else:
            argv.append("/w:" + str(settings.get("rdp_width", "1024")))
            argv.append("/h:" + str(settings.get("rdp_height", "768")))
        return "已启动：" + _launch(argv)

    if protocol == "ssh":
        auth = settings.get("ssh_auth", "password")
        if auth not in ("password", "key"):
            auth = "password"
        key_path = str(settings.get("ssh_key_path", "") or "")
        fmt = str(settings.get("ssh_param_format", "") or "")
        # A key stored in the server database wins over the local path: the
        # Agent writes it to a private temp file and passes that file to -i/%5.
        key_path, from_database = _materialize_ssh_key(ssh_key, key_path, auth)
        if from_database:
            print("[agent] 使用服务端数据库下发的 SSH 私钥（临时文件，%d 秒后删除）"
                  % _KEY_CLEANUP_SECONDS, flush=True)
        # Split the template into arguments FIRST, then substitute inside each
        # token. Replacing on the raw string lets an empty password swallow the
        # next switch: "-pw %4 %1" -> "-pw <address>".
        argv = ssh_template_argv(fmt, address, port, account, password,
                                 key_path, auth)
        if argv:
            return "已启动：" + _launch(argv)
        if IS_WINDOWS:
            try:
                putty = _find_client(settings, "ssh_path")
            except RuntimeError as exc:
                return (f"{exc} 也可手动执行：ssh -p {port} "
                        f"{account or 'root'}@{address}")
            return "已启动：" + _launch(
                ssh_default_argv(putty, address, port, account, password,
                                 key_path, auth))
        linux_argv, key_mode, pwd = ssh_linux_argv(
            address, port, account, password, key_path, auth)
        if key_mode or not pwd:
            # Key auth / interactive prompt needs no sshpass wrapper.
            return "已启动：" + _launch(linux_argv)
        sshpass = shutil.which("sshpass")
        if sshpass:
            return "已启动：" + _launch([sshpass, "-p", pwd] + linux_argv)
        return ("未找到 sshpass，请手动执行：" +
                " ".join(shlex.quote(item) for item in linux_argv))

    if protocol == "radmin":
        if not IS_WINDOWS:
            raise RuntimeError("Radmin Viewer 只在 Windows 可用")
        radmin = _find_client(settings, "radmin_path")
        # Faithful to the original RadminConnent(): /connect:host[:port]
        # followed by control mode, colour depth and optional fullscreen.
        # A per-record radmin_ctrl wins; otherwise fall back to the global
        # numeric radmin_ctrl_mode used by older settings.
        control = settings.get("radmin_ctrl")
        if control not in RADMIN_CONTROL_FLAGS:
            try:
                index = int(settings.get("radmin_ctrl_mode", "0"))
            except (TypeError, ValueError):
                index = 0
            legacy = ("full", "view", "file", "shutdown")
            control = legacy[index] if 0 <= index < len(legacy) else "full"
        mode = RADMIN_CONTROL_FLAGS[control]
        colour = RADMIN_COLOR_FLAGS.get(str(settings.get("radmin_color", "24")), "/24bpp")
        target = address if port == 4899 else f"{address}:{port}"
        argv = [radmin, "/connect:" + target]
        if mode:
            argv.append(mode)
        argv.append(colour)
        if settings.get("radmin_fullscreen", "1") == "1":
            argv.append("/fullscreen")
        message = "已启动：" + _launch(argv)
        if settings.get("radmin_autologin", "1") == "1" and password:
            threading.Thread(target=_radmin_autologin,
                             args=(address, account, password), daemon=True).start()
            message += "（后台尝试自动填写 Radmin 登录窗口）"
        return message

    if protocol in ("realvnc", "tightvnc"):
        viewer = _find_client(settings, "vnc_path")
        target = f"{address}:{port}"
        argv = [viewer, target]
        if protocol == "tightvnc" and password:
            argv.append(f"-password={password}")
        return "已启动：" + _launch(argv)

    if protocol == "ftp":
        url = connection_url(host, password, settings, "ftp")
        safe_url = _redact(url, password)
        if not IS_WINDOWS:
            raise RuntimeError("FlashFXP 只在 Windows 可用；可手动打开：" + safe_url)
        exe = _find_client(settings, "flashfxp_path")
        fmt = str(settings.get("ftp_param_format", "") or "")
        remote_path = str(settings.get("ftp_path", "") or "")
        argv = client_template_argv(fmt, exe, host, password, url, remote_path)
        if argv is None:
            # Official FlashFXP form: FLASHFXP.EXE [-switches] ftp://user:pass@host:port/path
            argv = [exe]
            flag = FTP_WINDOWS.get(settings.get("ftp_window"), "")
            if flag:
                argv.append(flag)
            argv.append(url)
            local = str(settings.get("ftp_local_path", "") or "")
            if local:
                argv.append("-localpath=" + local)
        _launch(argv)
        # Credentials are inside the URL: never echo them back to the browser.
        return "已启动 FlashFXP：" + " ".join(
            _redact(str(item), password) for item in argv)

    if protocol == "winscp":
        url = connection_url(host, password, settings, "winscp")
        safe_url = _redact(url, password)
        if not IS_WINDOWS:
            raise RuntimeError("WinSCP 只在 Windows 可用；可手动打开：" + safe_url)
        exe = _find_client(settings, "winscp_path")
        fmt = str(settings.get("winscp_param_format", "") or "")
        remote_dir = str(settings.get("winscp_dir", "") or "")
        argv = client_template_argv(fmt, exe, host, password, url, remote_dir)
        if argv is None:
            # Official GUI form: WINSCP.EXE [switches] sftp://user:pass@host:port/dir
            argv = [exe]
            flag = WINSCP_WINDOWS.get(settings.get("winscp_window"), "")
            if flag:
                argv.append(flag)
            argv.append(url)
        _launch(argv)
        return "已启动 WinSCP：" + " ".join(
            _redact(str(item), password) for item in argv)

    if protocol == "web":
        url = connection_url(host, password, settings, "web")
        safe_url = _redact(url, password)
        browser = _client_setting(settings, "browser_path")
        fmt = str(settings.get("web_param_format", "") or "")
        if browser and not Path(browser).is_file():
            raise RuntimeError(
                f"设置的浏览器路径不存在：{browser}。请到 WebUI「系统设置 → "
                "browser_path」改成正确路径，或清空使用系统默认浏览器。")
        if fmt:
            if not browser:
                raise RuntimeError(
                    "Web 记录使用了自定义命令行参数格式，请先在「系统设置 → "
                    "客户端程序路径」配置浏览器路径；留空则用系统默认浏览器直接打开。")
            # %1 / %2 are the *host* and *port*, not the pasted URL string.
            template_host = host
            page = parse_web_address(host.get("address", ""))
            if page:
                template_host = dict(host, address=page["hostname"],
                                     port=page["port"])
            argv = client_template_argv(fmt, browser, template_host,
                                         password, url)
            if argv:
                _launch(argv)
                return "已启动浏览器：" + " ".join(
                    _redact(str(item), password) for item in argv)
        if browser:
            _launch([browser, url])
            return "已启动浏览器：" + browser + " " + safe_url
        try:
            opened = webbrowser.open(url)
        except Exception as exc:
            raise RuntimeError(
                f"系统默认浏览器打开失败：{exc}；可手动打开 {safe_url}") from exc
        if not opened:
            raise RuntimeError(
                "未找到系统默认浏览器；请在「系统设置 → 客户端程序路径」"
                "指定浏览器路径，或手动打开 " + safe_url)
        return "已用系统默认浏览器打开：" + safe_url

    raise RuntimeError(f"未知连接类型：{protocol}")


# --------------------------------------------------------------------------- #
# CLI commands
# --------------------------------------------------------------------------- #
def cmd_login(args):
    user = getattr(args, "login_user", "") or args.user
    password = getattr(args, "login_password", "") or args.password
    if not user or not password:
        raise RuntimeError("login 需要 --user 和 --password")
    data = http_json(args.server, "/api/login",
                     {"username": user, "password": password})
    save_config({"server": args.server, "token": data["token"],
                 "user": data["user"]["username"]})
    print("登录成功，令牌已保存到", CONFIG_PATH)


def cmd_list(args):
    token = resolve_token(args)
    hosts = http_json(args.server, "/api/hosts", token=token)
    print(f"{'ID':>5}  {'类型':<9} {'名称':<20} {'地址':<24} {'端口':>6}  账号")
    for host in hosts:
        print(f"{host['id']:>5}  {host['protocol']:<9} {host['name'][:20]:<20} "
              f"{host['address'][:24]:<24} {host['port']:>6}  {host['account']}")
    print(f"合计 {len(hosts)} 台")


def cmd_connect(args):
    token = resolve_token(args)
    credential = http_json(args.server, f"/api/hosts/{args.host_id}/credential",
                            payload={}, token=token)
    try:
        settings = http_json(args.server, "/api/settings", token=token)
    except Exception:
        settings = {}
    print(connect_host(credential["host"], credential["password"], settings,
                      credential.get("ssh_key")))


def cmd_connect_ticket(args):
    """Connect using a one-shot ticket (mainly for debugging the WebUI flow)."""
    data = http_json(args.server, "/api/connect-ticket/redeem", {"ticket": args.ticket})
    print(connect_host(data["host"], data["password"], data.get("settings") or {},
                       data.get("ssh_key")))


def _scan_common_folders(names) -> str:
    """Best-effort search for viewers installed outside the usual directories
    (the original MFC program was often unpacked into a Downloads folder).
    Bounded in both depth and directory count so /clients stays responsive."""
    home = Path.home()
    roots = (home / "Downloads", home / "下载", home / "Desktop", home / "桌面",
             Path("D:/下载"), Path("D:/Downloads"), Path("D:/tools"),
             home / "AppData" / "Local" / "Programs")
    wanted = {name.lower() for name in names}
    visited = 0
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for current, dirs, files in os.walk(root):
                visited += 1
                if visited > 800:
                    return ""
                if len(Path(current).relative_to(root).parts) >= 3:
                    dirs[:] = []
                for name in files:
                    if name.lower() in wanted:
                        return str(Path(current) / name)
        except OSError:
            continue
    return ""


def probe_clients() -> dict:
    """Client paths discovered on the machine that actually runs the Agent."""
    result = {}
    for key, spec in CLIENT_CANDIDATES.items():
        configured = _client_setting({}, key)
        found = (_find_executable(spec["names"], spec["paths"])
                 or _scan_common_folders(spec["names"]))
        result[key] = {
            "label": spec["label"],
            "path": found or "",
            "configured": configured,
            "configured_exists": bool(configured and Path(configured).is_file()),
        }
    return {"platform": platform.system(), "clients": result}


def probe_targets(targets, timeout_ms=500) -> dict:
    """TCP reachability check from the machine that actually runs the Agent.

    The server deliberately has no probe endpoint any more: it may sit on a
    different LAN segment and mark every host "离线" even though the operator's
    own PC can connect. This is the ONLY source of online state in the WebUI.
    The WebUI forwards the (id, address, port) triples it already has from
    /api/hosts; the Agent never queries the server itself.
    """
    cleaned = []
    for item in (targets or [])[:300]:
        try:
            hid = str(item["id"])
            address = str(item["address"]).strip()
            port = int(item["port"])
        except (TypeError, ValueError, KeyError, AttributeError):
            continue
        # A Web record may hold a full http(s) URL in the address field.
        # Probe its real host/port instead of the URL string (an older WebUI
        # still sends the raw URL, so this also keeps those clients working).
        if WEB_URL_RE.match(address):
            page = parse_web_address(address)
            if not page:
                continue
            address, port = page["hostname"], page["port"]
        if not address or len(address) > 253 or not (1 <= port <= 65535):
            continue
        # Host names / IP literals only; a page must not turn the Agent into
        # an arbitrary network scanner.
        if not re.fullmatch(r"[A-Za-z0-9._:\-]+", address):
            continue
        cleaned.append((hid, address, port))
    try:
        timeout_s = max(0.05, min(5.0, float(timeout_ms or 500) / 1000.0))
    except (TypeError, ValueError):
        timeout_s = 0.5

    def one(entry):
        hid, address, port = entry
        try:
            with socket.create_connection((address, port), timeout=timeout_s):
                return hid, True
        except OSError:
            return hid, False

    if not cleaned:
        return {}
    with ThreadPoolExecutor(max_workers=min(32, len(cleaned))) as pool:
        results = list(pool.map(one, cleaned))
    return {hid: online for hid, online in results}


def pick_client_file(label: str, file_filter: str = EXE_FILE_FILTER,
                      title: str = "") -> dict:
    """Open a native file picker on the Agent's machine (like the original MFC
    "RADMIN路径" button). Runs in a child process so a missing desktop session
    cannot hang the Agent's HTTP thread forever.

    A plain ``ShowDialog()`` has no owner, so Windows puts the dialog behind
    the browser that triggered it — the button then looks dead. We give it a
    hidden, always-on-top owner form so the dialog is guaranteed to be visible.
    """
    title = title or ("选择 %s 的可执行文件（本机）" % label)
    if IS_WINDOWS:
        script = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try {
  Add-Type -AssemblyName System.Windows.Forms | Out-Null
  Add-Type -AssemblyName System.Drawing | Out-Null
  # An invisible 1x1 always-on-top owner centred on screen: the modal dialog
  # inherits its top-most z-order and is positioned in the middle of the
  # screen, so it can never be hidden behind the browser window.
  $owner = New-Object System.Windows.Forms.Form
  $owner.FormBorderStyle = 'None'
  $owner.ShowInTaskbar = $false
  $owner.TopMost = $true
  $owner.StartPosition = 'CenterScreen'
  $owner.Size = New-Object System.Drawing.Size(1, 1)
  $owner.Opacity = 0
  $owner.Show()
  $owner.Activate()
  $d = New-Object System.Windows.Forms.OpenFileDialog
  $d.Title = '__TITLE__'
  $d.Filter = '__FILTER__'
  $d.CheckFileExists = $true
  $d.Multiselect = $false
  if ($d.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($d.FileName)
  }
  $d.Dispose()
  $owner.Dispose()
} catch {
  [Console]::Error.Write($_.Exception.Message)
  exit 1
}
""".replace("__TITLE__", title.replace("'", "''")) \
   .replace("__FILTER__", file_filter.replace("'", "''"))
        powershell = shutil.which("powershell") or "powershell"
        try:
            done = subprocess.run(
                [powershell, "-NoProfile", "-STA", "-Command", script],
                capture_output=True, timeout=90)
            path = (done.stdout or b"").decode("utf-8", errors="replace").strip()
            if path:
                return {"path": os.path.normpath(path), "error": ""}
            err = (done.stderr or b"").decode("utf-8", errors="replace").strip()
            return {"path": "", "error": ("本机文件选择框不可用：" + err[-160:]) if err else ""}
        except subprocess.TimeoutExpired:
            return {"path": "", "error": "选择超时（90 秒），请直接粘贴绝对路径"}
        except Exception as exc:
            return {"path": "", "error": "本机无法弹出文件选择框：%s" % exc}

    for tool, argv in (("zenity", ["zenity", "--file-selection", "--title=" + title]),
                       ("kdialog", ["kdialog", "--getopenfilename", "."])):
        if not shutil.which(tool):
            continue
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=90)
            path = (done.stdout or "").strip()
            return ({"path": os.path.abspath(path), "error": ""} if path
                    else {"path": "", "error": ""})
        except Exception:
            continue
    return {"path": "", "error": "本机没有可用的图形文件选择框，请直接粘贴绝对路径"}


def cmd_serve(args):
    jc = load_json_config()
    port = args.port or jc.get("agent_port") or DEFAULT_PORT
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = DEFAULT_PORT

    class Handler(BaseHTTPRequestHandler):
        server_version = "RemoteMgrAgent/1.0"

        def log_message(self, *_unused):
            pass

        def _reply(self, text: str, status: int = 200, content_type="text/html; charset=utf-8"):
            raw = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Access-Control-Allow-Origin", "*")
            # Chrome's Private Network Access: the WebUI may be served from a
            # LAN address while the Agent listens on 127.0.0.1.
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.end_headers()
            self.wfile.write(raw)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            """Local online probe. Reachable only from the WebUI's origin."""
            if urllib.parse.urlparse(self.path).path != "/probe":
                return self._reply("not found", 404, "text/plain; charset=utf-8")
            if not self._origin_ok():
                return self._reply('{"error":"forbidden"}', 403,
                                   "application/json; charset=utf-8")
            try:
                length = min(int(self.headers.get("Content-Length", "0")), 65536)
                raw = self.rfile.read(length) if length else b"{}"
                payload = json.loads(raw.decode("utf-8") or "{}")
                data = probe_targets(payload.get("targets"),
                                      payload.get("timeout_ms", 500))
                reply, status = {"ok": True, "data": data, "source": "agent"}, 200
            except Exception as exc:
                reply, status = {"ok": False, "error": str(exc)}, 400
            return self._reply(json.dumps(reply, ensure_ascii=False), status,
                               "application/json; charset=utf-8")

        def _origin_ok(self) -> bool:
            """Only the configured server / loopback may probe or open a picker."""
            origin = self.headers.get("Origin", "")
            if not origin:
                return True
            host = (urllib.parse.urlparse(origin).hostname or "").lower()
            allowed = {"127.0.0.1", "localhost", "::1"}
            server_host = urllib.parse.urlparse(args.server).hostname
            if server_host:
                allowed.add(server_host.lower())
            return host in allowed

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/ping":
                return self._reply("pong", content_type="text/plain; charset=utf-8")
            if parsed.path in ("/clients", "/browse"):
                if not self._origin_ok():
                    return self._reply('{"error":"forbidden"}', 403,
                                       "application/json; charset=utf-8")
                if parsed.path == "/clients":
                    payload = probe_clients()
                else:
                    kind = urllib.parse.parse_qs(parsed.query).get("kind", [""])[0]
                    spec = BROWSE_KINDS.get(kind)
                    if not spec:
                        return self._reply('{"error":"unknown browse kind"}', 400,
                                           "application/json; charset=utf-8")
                    payload = pick_client_file(spec["label"], spec["filter"],
                                               spec.get("title", ""))
                return self._reply(json.dumps(payload, ensure_ascii=False),
                                   content_type="application/json; charset=utf-8")
            if parsed.path != "/connect":
                return self._reply("not found", 404, "text/plain; charset=utf-8")
            query = urllib.parse.parse_qs(parsed.query)
            ticket = query.get("ticket", [""])[0]
            server = query.get("server", [args.server])[0]
            try:
                if not ticket:
                    raise RuntimeError("缺少连接票据")
                # Basic host allow-list: never let a page steer the agent to an
                # arbitrary host through the server parameter.
                if not server.startswith(("http://", "https://")):
                    raise RuntimeError("服务端地址不合法")
                data = http_json(server, "/api/connect-ticket/redeem", {"ticket": ticket})
                message = connect_host(data["host"], data["password"],
                                       data.get("settings") or {},
                                       data.get("ssh_key"))
                title, css_class, ok = "连接已发起", "ok", True
            except Exception as exc:
                message, title, css_class, ok = str(exc), "连接失败", "err", False
            print(f"[agent] {title}: {message}", flush=True)
            page = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>RemoteMgr 本地连接</title><style>
body{{font:14px/1.6 -apple-system,"Microsoft YaHei",sans-serif;background:#f6f7f9;
color:#1f2933;display:flex;align-items:center;justify-content:center;height:90vh;margin:0}}
.card{{background:#fff;border:1px solid #e3e6ea;border-radius:12px;padding:26px 30px;
max-width:520px}}.ok{{color:#0f6e56}}.err{{color:#a32d2d}}
code{{background:#f0f2f5;padding:2px 5px;border-radius:4px}}</style></head><body>
<div class="card"><h2 class="{css_class}">{title}</h2>
<p>{html.escape(message)}</p>
<p style="color:#6b7684">此窗口可关闭。若客户端没弹出，请确认本机已安装对应远程客户端。</p>
</div>{'<script>setTimeout(function(){window.close()},6000)</script>' if ok else ''}
</body></html>"""
            return self._reply(page)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[agent] 监听 http://127.0.0.1:{port} ，服务端 {args.server}")
    print("[agent] WebUI 点「连接」即可一键拉起本机客户端；"
          "在线检测走 /probe（从本机发包），路径按钮走 /clients 与 /browse；Ctrl+C 退出")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[agent] 已退出")


def main():
    parser = argparse.ArgumentParser(description="RemoteMgr 本地连接 Agent")
    parser.add_argument("--server", default=None,
                        help="服务端地址（缺省依次读 config.json → 环境变量 "
                             "REMOTEMGR_SERVER → ~/.remotemgr_agent.json → 内置默认）")
    parser.add_argument("--token", default="", help="登录令牌（也可用 login 命令缓存）")
    parser.add_argument("--user", default="", help="登录账号")
    parser.add_argument("--password", default="", help="登录密码")
    sub = parser.add_subparsers(dest="command", required=True)

    p_login = sub.add_parser("login", help="登录并缓存令牌")
    p_login.add_argument("--user", dest="login_user", default="", help="登录账号")
    p_login.add_argument("--password", dest="login_password", default="", help="登录密码")
    p_login.set_defaults(func=cmd_login)
    sub.add_parser("list", help="列出主机").set_defaults(func=cmd_list)
    p_connect = sub.add_parser("connect", help="按 ID 连接主机")
    p_connect.add_argument("host_id", type=int)
    p_connect.set_defaults(func=cmd_connect)
    p_ticket = sub.add_parser("connect-ticket", help="用一次性票据连接（调试用）")
    p_ticket.add_argument("ticket")
    p_ticket.set_defaults(func=cmd_connect_ticket)
    p_serve = sub.add_parser("serve", help="启动本地一键连接服务")
    p_serve.add_argument("--port", type=int, default=None,
                         help="本地监听端口（缺省读 config.json 的 agent_port → "
                              "环境变量 REMOTEMGR_AGENT_PORT → 17860）")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    # 服务器地址优先级：--server > REMOTEMGR_SERVER > config.json > 家目录配置 > 内置默认
    jc = load_json_config()
    args.server = (args.server
                   or os.environ.get("REMOTEMGR_SERVER")
                   or jc.get("server")
                   or load_config().get("server")
                   or DEFAULT_SERVER)
    try:
        args.func(args)
    except Exception as exc:
        print(f"错误：{exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
