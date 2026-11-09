"""Database models. Portable across SQLite / MySQL / PostgreSQL."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    func,
    inspect,
    text,
)
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


def local_now() -> datetime:
    """Store wall-clock time of the server (respects TZ in the systemd unit)."""
    return datetime.now()


class User(Base):
    __tablename__ = "rm_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, unique=True, index=True)
    password_hash = Column(String(256), nullable=False)
    # admin: everything | editor: hosts/groups | viewer: read-only, no secrets
    role = Column(String(16), nullable=False, default="viewer")
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=local_now, server_default=func.now())


class Group(Base):
    __tablename__ = "rm_groups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), nullable=False)
    parent_id = Column(Integer, nullable=False, default=0, index=True)
    sort_order = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=local_now, server_default=func.now())


class Host(Base):
    __tablename__ = "rm_hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), nullable=False)
    group_id = Column(Integer, nullable=False, default=0, index=True)
    protocol = Column(String(16), nullable=False, default="rdp", index=True)
    address = Column(String(128), nullable=False)
    port = Column(Integer, nullable=False, default=3389)
    mac = Column(String(24), nullable=False, default="")
    account = Column(String(64), nullable=False, default="")
    password_enc = Column(Text, nullable=False, default="")
    # AES-256-GCM ciphertext of {"filename": ..., "content": ...} for an SSH
    # private key stored IN the database. The master key never leaves the server
    # filesystem, so a leaked/cloud database dump cannot reveal the key. The
    # plaintext is only handed to the local Agent on a one-shot connect ticket.
    ssh_key_enc = Column(Text, nullable=False, default="")
    note = Column(String(512), nullable=False, default="")
    # Per-record connection options (JSON text), e.g. RDP resolution / colour /
    # wallpaper / drive / audio and Radmin display + control mode. Keeping it as
    # one JSON column means new options never need another schema migration, and
    # the same definition works on SQLite, MySQL and PostgreSQL.
    options = Column(Text, nullable=False, default="{}")
    sort_order = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=local_now, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, default=local_now,
                       server_default=func.now(), onupdate=local_now)


class Setting(Base):
    __tablename__ = "rm_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False, default="")


class AuditLog(Base):
    __tablename__ = "rm_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, nullable=False, default=local_now,
                       server_default=func.now(), index=True)
    username = Column(String(64), nullable=False, default="")
    action = Column(String(48), nullable=False)
    target = Column(String(128), nullable=False, default="")
    detail = Column(String(512), nullable=False, default="")
    ip = Column(String(64), nullable=False, default="")


def make_engine(url: str, echo: bool = False):
    kwargs = {"echo": echo, "pool_pre_ping": True, "future": True}
    if url.startswith("sqlite:"):
        # check_same_thread is a sqlite3 driver argument, not a URL option.
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 15}
    else:
        kwargs["pool_recycle"] = 1800
    return create_engine(url, **kwargs)


def utcnow() -> datetime:
    return datetime.utcnow()


SessionMaker = None  # set by init_db(); keeps a single configurable factory


def _add_missing_columns(engine) -> None:
    """Idempotent lightweight migration for databases created by older builds.

    ``create_all`` never alters an existing table. We only add what is missing
    and backfill NULLs; no data is ever dropped or rewritten in place.
    """
    inspector = inspect(engine)
    if "rm_hosts" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("rm_hosts")}
    # Plain TEXT with no DEFAULT keeps MySQL (<8.0.13) happy as well. Column
    # names and fills are constants here, never user-controlled SQL fragments.
    additions = (("options", "'{}'"), ("ssh_key_enc", "''"))
    with engine.begin() as conn:
        for name, fill in additions:
            if name in columns:
                continue
            conn.execute(text(f"ALTER TABLE rm_hosts ADD COLUMN {name} TEXT"))
            conn.execute(text(f"UPDATE rm_hosts SET {name} = {fill} "
                              f"WHERE {name} IS NULL OR {name} = ''"))


def init_db(engine) -> sessionmaker:
    global SessionMaker
    Base.metadata.create_all(engine)
    _add_missing_columns(engine)
    SessionMaker = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    return SessionMaker
