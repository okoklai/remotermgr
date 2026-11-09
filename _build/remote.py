#!/usr/bin/env python3
"""Tiny paramiko helper for deploying RemoteMgr to a Linux host.

Usage:
    remote.py run   "<shell command>" [--sudo]
    remote.py put   <local> <remote>
    remote.py get   <remote> <local>
    remote.py mkdir <remote> [--sudo]

Password auth; host/user/pass default to the 192.168.10.121 deployment box.
This is a LOCAL build helper only — never commit real credentials.
"""
from __future__ import annotations

import argparse
import base64
import os
import paramiko
import posixpath
import shlex
import sys

HOST = os.environ.get("RMT_HOST", "192.168.10.121")
PORT = int(os.environ.get("RMT_PORT", "22"))
USER = os.environ.get("RMT_USER", "acaiplus")
PASS = os.environ.get("RMT_PASS", "a1234567")
SUDO_PASS = os.environ.get("RMT_SUDO_PASS", PASS)


def client():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS, timeout=25)
    return c


def run(cmd: str, sudo: bool = False):
    c = client()
    if sudo:
        cmd = f'echo {shlex.quote(SUDO_PASS)} | sudo -S bash -c {shlex.quote(cmd)}'
    stdin, stdout, stderr = c.exec_command(cmd, timeout=600)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    c.close()
    return rc, out, err


def put(local: str, remote: str, sudo: bool = False):
    """Upload a file via base64 piped over an SSH exec channel.

    Avoids the paramiko/OpenSSH SFTP quirk on this host where stat/mkdir of an
    existing path returns ENOENT. Parent directory is created with mkdir -p.
    """
    data = open(local, "rb").read()
    b64 = base64.b64encode(data).decode("ascii")
    remote_dir = os.path.dirname(remote)
    mkdir_cmd = f"mkdir -p {shlex.quote(remote_dir)}"
    c = client()
    if sudo:
        # write to a temp file owned by root, then chown/install
        tmp = "/tmp/" + os.path.basename(remote) + ".upload"
        _pipe_base64(c, b64, tmp)
        _, out, err = run(f"install -D -m 0644 {shlex.quote(tmp)} {shlex.quote(remote)} "
                          f"&& rm -f {shlex.quote(tmp)}", sudo=True)
        c.close()
        return 0, out, err
    _pipe_base64(c, b64, remote)
    c.close()
    return 0, "", ""


def _pipe_base64(c, b64: str, remote: str):
    """Decode base64 content straight into a remote file via printf|base64 -d.

    Reliable for the file sizes we transfer (the large binary is built on the
    remote, so it is never uploaded this way).
    """
    cmd = (f"mkdir -p {shlex.quote(posixpath.dirname(remote))} && "
           f"printf '%s' {shlex.quote(b64)} | base64 -d > {shlex.quote(remote)}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=300)
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    if rc != 0:
        raise RuntimeError(f"upload of {remote} failed (rc={rc}): {err}")


def get(remote: str, local: str):
    c = client()
    sftp = c.open_sftp()
    sftp.get(remote, local)
    sftp.close()
    c.close()
    return 0, "", ""


def mkdir(path: str, sudo: bool = False):
    return run(f"mkdir -p {shlex.quote(path)}", sudo=sudo)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run"); p.add_argument("command"); p.add_argument("--sudo", action="store_true")
    p = sub.add_parser("put"); p.add_argument("local"); p.add_argument("remote"); p.add_argument("--sudo", action="store_true")
    p = sub.add_parser("get"); p.add_argument("remote"); p.add_argument("local")
    p = sub.add_parser("mkdir"); p.add_argument("path"); p.add_argument("--sudo", action="store_true")
    args = ap.parse_args()

    if args.cmd == "run":
        rc, out, err = run(args.command, sudo=args.sudo)
        sys.stdout.write(out)
        if err:
            sys.stderr.write(err)
        sys.exit(rc)
    elif args.cmd == "put":
        rc, out, err = put(args.local, args.remote, sudo=args.sudo)
        sys.stdout.write(out); sys.stderr.write(err); sys.exit(rc)
    elif args.cmd == "get":
        rc, out, err = get(args.remote, args.local)
        sys.stdout.write(out); sys.stderr.write(err); sys.exit(rc)
    elif args.cmd == "mkdir":
        rc, out, err = mkdir(args.path, sudo=args.sudo)
        sys.stdout.write(out); sys.stderr.write(err); sys.exit(rc)


if __name__ == "__main__":
    main()
