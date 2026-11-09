"""RemoteMgr server configuration.

Every setting comes from the environment or an optional ``.env`` file at the
project root. Nothing is hard-coded to a particular database: set
``DATABASE_URL`` to a cloud MySQL/PostgreSQL instance and the same code runs.
"""
from __future__ import annotations

import base64
import os
import secrets
import sys
from pathlib import Path


def _load_dotenv() -> None:
    """Minimal .env reader; real environment variables always win."""
    if not ENV_FILE.is_file():
        return
    for raw in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


# Project root: when frozen into a standalone binary, resolve relative to the
# executable so the deployment is self-contained under any install path.
if getattr(sys, "frozen", False):
    ROOT = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parent.parent

# The .env location is taken from the real environment only (it cannot
# self-reference a value defined inside itself).
ENV_FILE = Path(os.environ.get("REMOTEMGR_ENV", str(ROOT / ".env"))).expanduser()
_load_dotenv()

# Other environment-backed paths are read after .env is loaded, so a .env file
# may override them (e.g. REMOTEMGR_DATA=/opt/remotemgrserver/dat).
DATA_DIR = Path(os.environ.get("REMOTEMGR_DATA", str(ROOT / "data"))).expanduser()


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def env_int(key: str, default: int) -> int:
    try:
        return int(env(key, str(default)))
    except ValueError:
        return default


def _default_sqlite_url() -> str:
    return "sqlite:///" + (DATA_DIR / "remotemgr.db").as_posix()


def _read_or_create_key(filename: str, env_name: str) -> bytes:
    """Load a 32-byte key from env, or create it once in DATA_DIR (mode 0600).

    The key never enters the database. Back it up: losing it means stored
    credentials can no longer be decrypted.
    """
    raw = env(env_name)
    if raw:
        try:
            key = base64.urlsafe_b64decode(raw.encode("ascii"))
        except Exception as exc:  # noqa: BLE001 - config error, fail loudly
            raise RuntimeError(f"{env_name} must be urlsafe-base64 of 32 bytes") from exc
        if len(key) != 32:
            raise RuntimeError(f"{env_name} must decode to exactly 32 bytes")
        return key

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / filename
    if path.exists():
        key = base64.urlsafe_b64decode(path.read_text(encoding="ascii").strip().encode())
        if len(key) != 32:
            raise RuntimeError(f"invalid key file: {path}")
        return key

    key = secrets.token_bytes(32)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(base64.urlsafe_b64encode(key).decode("ascii"))
    return key


DATABASE_URL = env("DATABASE_URL", _default_sqlite_url())
SQL_ECHO = env("SQL_ECHO", "0") == "1"
BIND_HOST = env("BIND_HOST", "0.0.0.0")
BIND_PORT = env_int("BIND_PORT", 8800)
TOKEN_TTL = env_int("TOKEN_TTL", 43200)        # login token, seconds
TICKET_TTL = env_int("TICKET_TTL", 60)         # one-shot connect ticket, seconds
# Default timeout the WebUI forwards to the LOCAL Agent for POST /probe.
# The server itself never runs a TCP probe; see the note in app.py.
PROBE_TIMEOUT_MS = env_int("PROBE_TIMEOUT_MS", 500)
WOL_BROADCAST = env("WOL_BROADCAST", "255.255.255.255")
AGENT_PORT = env_int("AGENT_PORT", 17860)
CORS_ORIGINS = [item.strip() for item in env("CORS_ORIGINS", "*").split(",") if item.strip()]

# Only used when the user table is empty (first boot).
BOOTSTRAP_ADMIN = env("BOOTSTRAP_ADMIN", "admin")
BOOTSTRAP_PASSWORD = env("BOOTSTRAP_PASSWORD", "")

MASTER_KEY = _read_or_create_key("master.key", "MASTER_KEY")
SECRET_KEY = _read_or_create_key("secret.key", "SECRET_KEY")

# Settings that are genuinely global: no per-record equivalent exists.
DEFAULT_SETTINGS = {
    "probe_timeout_ms": str(PROBE_TIMEOUT_MS),
    "wol_broadcast": WOL_BROADCAST,
    "agent_port": str(AGENT_PORT),
    # Mirrors the original MFC ConfigTab: clients may live outside PATH, so the
    # operator can point at an absolute path on the machine running the Agent.
    "radmin_path": "",
    "ssh_path": "",
    "vnc_path": "",
    "flashfxp_path": "",        # FTP / FTPS / SFTP records (Windows client)
    "winscp_path": "",          # WinSCP records (SFTP / SCP / FTP / WebDAV)
    "browser_path": "",         # empty = OS default browser for Web records
    "radmin_autologin": "1",    # fill the Radmin security dialog (Windows only)

    # Legacy fallbacks. Since v2 every display/control option lives on the host
    # record (rm_hosts.options); these are consulted only for older records that
    # have no options yet. The WebUI keeps them behind a collapsed section.
    "rdp_width": "1024",
    "rdp_height": "768",
    "rdp_color": "32",
    "rdp_fullscreen": "1",
    "radmin_fullscreen": "1",
    "radmin_ctrl_mode": "0",     # 0 full / 1 view only / 2 file transfer / 3 shutdown
}

# Keys from earlier builds that have no effect any more; bootstrap() removes
# their rows so stale values never reach the WebUI or the Agent.
# radmin_color / ssh_param_format moved onto each host record (rm_hosts.options);
# rdp_console (mstsc /admin) was dropped as redundant.
DEPRECATED_SETTINGS = ("show_parent_hosts", "radmin_color",
                      "ssh_param_format", "rdp_console")
