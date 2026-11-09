"""Command-line maintenance for RemoteMgr.

    python manage.py init-db
    python manage.py user list
    python manage.py user add <name> <password> --role admin
    python manage.py user passwd <name> <new-password>
    python manage.py import-legacy /path/to/User.db [--dry-run] [--group-id N]
    python manage.py selftest
    python manage.py check-db
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

import config
from crypto import encrypt_secret, hash_password, legacy_decrypt_password, verify_password
from models import Group, Host, User, make_engine, init_db

# RemoteMan.cpp: {"RDP", "Radmin", "SSH", "RealVNC", "TightVNC"}
LEGACY_PROTOCOLS = ("rdp", "radmin", "ssh", "realvnc", "tightvnc")
LEGACY_DEFAULT_PORTS = (3389, 4899, 22, 5900, 5900)


def session_factory():
    """Return an open Session (init_db returns a sessionmaker, not a session)."""
    factory = init_db(make_engine(config.DATABASE_URL))
    return factory()


def _decode(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        for encoding in ("utf-8", "gbk", "latin-1"):
            try:
                return value.decode(encoding)
            except UnicodeDecodeError:
                continue
        return ""
    return str(value)


def cmd_init_db(_args):
    session = session_factory()
    session.close()
    print("OK: tables created / verified")
    print("    database:", config.DATABASE_URL)
    return 0


def cmd_check_db(_args):
    session = session_factory()
    try:
        print("database :", config.DATABASE_URL)
        print("users    :", session.query(User).count())
        print("groups   :", session.query(Group).count())
        print("hosts    :", session.query(Host).count())
        return 0
    finally:
        session.close()


def cmd_user(args):
    session = session_factory()
    try:
        if args.action == "list":
            for user in session.query(User).order_by(User.id).all():
                print(f"{user.id:>4}  {user.username:<24} {user.role:<8} "
                      f"{'enabled' if user.enabled else 'disabled'}")
            return 0
        if args.action == "add":
            if len(args.password) < 8:
                print("ERROR: password must be at least 8 characters", file=sys.stderr)
                return 2
            if session.query(User).filter(User.username == args.name).count():
                print("ERROR: user already exists", file=sys.stderr)
                return 2
            session.add(User(username=args.name, password_hash=hash_password(args.password),
                             role=args.role))
            session.commit()
            print("OK: user created")
            return 0
        if args.action == "passwd":
            user = session.query(User).filter(User.username == args.name).first()
            if not user:
                print("ERROR: user not found", file=sys.stderr)
                return 2
            if len(args.password) < 8:
                print("ERROR: password must be at least 8 characters", file=sys.stderr)
                return 2
            user.password_hash = hash_password(args.password)
            session.commit()
            print("OK: password changed")
            return 0
    finally:
        session.close()
    return 1


def cmd_import_legacy(args):
    legacy_path = Path(args.dbfile).expanduser()
    if not legacy_path.is_file():
        print(f"ERROR: file not found: {legacy_path}", file=sys.stderr)
        return 2
    conn = sqlite3.connect(f"file:{legacy_path}?mode=ro", uri=True)
    conn.text_factory = bytes
    try:
        tables = {row[0].decode() for row in
                  conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "GroupTab" not in tables or "HostTab" not in tables:
            print("ERROR: GroupTab / HostTab not found - is this the original User.db?",
                  file=sys.stderr)
            return 2
        groups = [(int(r[0]), _decode(r[2]), int(r[1] or 0))
                  for r in conn.execute("SELECT id, ParentId, Name FROM GroupTab ORDER BY id")]
        hosts = list(conn.execute(
            "SELECT id, Name, ParentId, CtrlMode, HostAddress, HostPort, "
            "MacAddr, Account, Password, HostReadme FROM HostTab ORDER BY id"))
    finally:
        conn.close()

    print(f"legacy: {len(groups)} groups, {len(hosts)} hosts")
    if args.dry_run:
        for row in hosts[:5]:
            print("  sample:", _decode(row[1]), _decode(row[4]), _decode(row[5]))
        print("dry-run: nothing written")
        return 0

    session = session_factory()
    group_map: dict[int, int] = {}
    try:
        if args.group_id:
            root = session.get(Group, args.group_id)
            if not root:
                print(f"ERROR: group id {args.group_id} does not exist", file=sys.stderr)
                return 2
        for old_id, name, parent_id in groups:
            existing = session.query(Group).filter(Group.name == name).first()
            if existing:
                group_map[old_id] = existing.id
                continue
            group = Group(name=name, parent_id=0, sort_order=0)
            session.add(group)
            session.flush()
            group_map[old_id] = group.id
        for old_id, name, parent_id in groups:
            parent_new = group_map.get(parent_id, args.group_id or 0)
            group = session.get(Group, group_map[old_id])
            if group and parent_new != group.id:
                group.parent_id = parent_new
        session.flush()

        added, skipped, bad_password = 0, 0, []
        for row in hosts:
            old_id = int(row[0])
            name = _decode(row[1]) or _decode(row[4])
            parent_id = int(row[2] or 0)
            try:
                mode = int(row[3] or 0)
            except (TypeError, ValueError):
                mode = 0
            protocol = LEGACY_PROTOCOLS[mode] if 0 <= mode < len(LEGACY_PROTOCOLS) else "rdp"
            address = _decode(row[4])
            try:
                port = int(row[5] or 0) or LEGACY_DEFAULT_PORTS[mode if 0 <= mode < 5 else 0]
            except (TypeError, ValueError):
                port = LEGACY_DEFAULT_PORTS[0]
            mac = _decode(row[6]).upper()
            account = _decode(row[7])
            password_hex = _decode(row[8])
            note = _decode(row[9])
            group_id = group_map.get(parent_id, args.group_id or 0)
            if not address:
                skipped += 1
                continue
            if session.query(Host).filter(Host.name == name, Host.group_id == group_id,
                                           Host.protocol == protocol).count():
                skipped += 1
                continue
            password = ""
            if password_hex:
                try:
                    password = legacy_decrypt_password(password_hex)
                except Exception as exc:  # keep the host, leave the secret empty
                    bad_password.append(f"{name} (id={old_id}): {exc}")
            host = Host(name=name[:64], group_id=group_id, protocol=protocol,
                        address=address[:128], port=port, mac=mac[:24],
                        account=account[:64], note=note[:512],
                        password_enc=encrypt_secret(password, config.MASTER_KEY))
            session.add(host)
            added += 1
        session.commit()
        print(f"OK: imported {added} hosts, skipped {skipped}")
        if bad_password:
            print(f"WARNING: {len(bad_password)} password(s) could not be decrypted; "
                  f"re-enter them in the WebUI:")
            for line in bad_password[:20]:
                print("   -", line)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    return 0


def cmd_selftest(_args):
    """Round-trip check for new encryption and the legacy AES format."""
    key = b"0" * 32
    token = encrypt_secret("p@ssw0rd-中文", key)
    from crypto import decrypt_secret
    assert decrypt_secret(token, key) == "p@ssw0rd-中文"
    assert verify_password("abc12345", hash_password("abc12345"))
    assert not verify_password("wrong", hash_password("abc12345"))

    # Reproduce the C program's padding + AES-128-ECB, then decrypt it.
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    plain = b"hello-legacy"
    pad = 16 - len(plain) % 16
    padded = plain + bytes([pad]) * pad
    encryptor = Cipher(algorithms.AES("远程连接管理软件".encode("gbk")),
                       modes.ECB()).encryptor()
    hex_text = (encryptor.update(padded) + encryptor.finalize()).hex().upper()
    assert legacy_decrypt_password(hex_text) == "hello-legacy"

    session = session_factory()
    try:
        print("OK: encryption / hashing / legacy AES round-trip verified")
        print("    users=%d groups=%d hosts=%d" % (
            session.query(User).count(), session.query(Group).count(),
            session.query(Host).count()))
    finally:
        session.close()
    return 0


def cmd_copy_db(args):
    """Copy all rows from one database to another (e.g. SQLite -> cloud MySQL).

    Uses primary-key merge, so it is safe to re-run. Table structures are
    created in the target automatically. Useful when switching DATABASE_URL.
    """
    from sqlalchemy.orm import Session
    from models import AuditLog, Setting

    source = args.source or config.DATABASE_URL
    target = args.target
    if source == target:
        print("ERROR: source and target are identical", file=sys.stderr)
        return 2
    src_engine, dst_engine = make_engine(source), make_engine(target)
    init_db(dst_engine)
    counts = {}
    try:
        with Session(src_engine) as src, Session(dst_engine) as dst:
            for model in (User, Group, Host, Setting, AuditLog):
                rows = src.query(model).all()
                for row in rows:
                    values = {column.name: getattr(row, column.name)
                              for column in model.__table__.columns}
                    dst.merge(model(**values))
                counts[model.__tablename__] = len(rows)
            dst.commit()
    except Exception as exc:
        print(f"ERROR: copy failed: {exc}", file=sys.stderr)
        return 1
    print("OK: copied", ", ".join(f"{k}={v}" for k, v in counts.items()))
    print("    from:", source)
    print("    to  :", target)
    print("    next: set DATABASE_URL in .env and restart the service")
    return 0


def main():
    parser = argparse.ArgumentParser(description="RemoteMgr maintenance CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create/verify tables").set_defaults(func=cmd_init_db)
    sub.add_parser("check-db", help="show database and row counts").set_defaults(func=cmd_check_db)
    sub.add_parser("selftest", help="verify crypto and database connectivity").set_defaults(func=cmd_selftest)

    p_user = sub.add_parser("user", help="manage users")
    p_user.add_argument("action", choices=["list", "add", "passwd"])
    p_user.add_argument("name", nargs="?", default="")
    p_user.add_argument("password", nargs="?", default="")
    p_user.add_argument("--role", choices=["admin", "editor", "viewer"], default="editor")
    p_user.set_defaults(func=cmd_user)

    p_import = sub.add_parser("import-legacy", help="import the original MFC User.db")
    p_import.add_argument("dbfile")
    p_import.add_argument("--dry-run", action="store_true")
    p_import.add_argument("--group-id", type=int, default=0)
    p_import.set_defaults(func=cmd_import_legacy)

    p_copy = sub.add_parser("copy-db", help="复制全部数据到另一个数据库（切换云端库用）")
    p_copy.add_argument("--source", default="", help="源连接串，默认当前 .env 的 DATABASE_URL")
    p_copy.add_argument("--target", required=True, help="目标连接串")
    p_copy.set_defaults(func=cmd_copy_db)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
