#!/usr/bin/env python3
"""End-to-end API smoke test (no third-party dependencies).

    python smoke_test.py http://127.0.0.1:8800 <admin-password>

Creates a temporary group + hosts, verifies online probing is offloaded to the
local Agent (no server endpoint, no WebUI fallback), then exercises credential
/ one-shot ticket / encrypted SSH private key storage / FTP (FlashFXP) / Web
(HTTP/HTTPS) / WinSCP records / export / audit and deletes what it created.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8800").rstrip("/")
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else ""
TOKEN = ""


def call(path: str, method: str = "GET", payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if TOKEN:
        headers["Authorization"] = "Bearer " + TOKEN
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))
            status = response.status
    except urllib.error.HTTPError as exc:
        result = json.loads(exc.read().decode("utf-8") or "{}")
        status = exc.code
    if not result.get("ok"):
        raise RuntimeError(f"{method} {path} -> HTTP {status}: {result.get('error')}")
    return result.get("data")


def call_raw(path: str):
    """Endpoints that stream a file (export) return bare JSON, not the wrapper."""
    request = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + TOKEN})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def get_text(path: str) -> str:
    with urllib.request.urlopen(BASE + path, timeout=15) as response:
        return response.read().decode("utf-8")


def status_of(path: str, method: str = "POST", payload=None) -> int:
    """HTTP status without parsing the body (404 pages are HTML, not JSON)."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if TOKEN:
        headers["Authorization"] = "Bearer " + TOKEN
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def main() -> int:
    global TOKEN
    health = call("/api/health")
    print(f"[1/13] health ok, database={health['database']}")
    index_html, ui_js = get_text("/"), get_text("/static/app.js")
    assert "RemoteMgr" in index_html and "api/login" in ui_js
    assert "hostTip" in index_html and "hostTipHtml" in ui_js, "hover card not deployed"
    assert ".host-tip" in get_text("/static/style.css"), "hover card styles not deployed"
    assert "ssh_auth" in ui_js and "ssh_key_path" in ui_js and "%5" in ui_js, \
        "SSH key-auth UI not deployed"
    assert "f_ssh_key_file" in ui_js and "ssh_key_fingerprint" in ui_js, \
        "SSH private-key upload UI not deployed"
    for marker in ("ftp_scheme", "web_scheme", "f_ftp_path", "f_web_path",
                   "flashfxp_path", "browser_path",
                   "winscp_scheme", "f_winscp_dir", "winscp_path"):
        assert marker in ui_js, f"FTP / Web / WinSCP UI not deployed (missing {marker})"
    assert ".tag.web" in get_text("/static/style.css"), "FTP / Web tag styles not deployed"
    assert ".tag.winscp" in get_text("/static/style.css"), "WinSCP tag style not deployed"
    assert "parseWebUrl" in ui_js and "f_address_caption" in ui_js, \
        "Web full-URL address support not deployed"
    print("      WebUI served ok (hover card + SSH key upload + FTP/Web forms present)")

    if not PASSWORD:
        print("SKIP: pass the admin password as the 2nd argument to run authenticated checks")
        return 0
    login = call("/api/login", "POST", {"username": "admin", "password": PASSWORD})
    TOKEN = login["token"]
    print(f"[2/13] login ok, user={login['user']['username']} role={login['user']['role']}")

    suffix = str(int(time.time()))
    group = call("/api/groups", "POST", {"name": "_smoke_group_" + suffix, "parent_id": 0})
    host = call("/api/hosts", "POST", {
        "name": "_smoke_host_" + suffix, "protocol": "ssh", "address": "127.0.0.1",
        "port": 22, "account": "tester", "password": "s3cret-value",
        "mac": "AA:BB:CC:DD:EE:FF", "group_id": group["id"], "note": "smoke"})
    print(f"[3/13] created group={group['id']} host={host['id']}")

    hosts = call("/api/hosts?group_id=%d" % group["id"])
    assert len(hosts) == 1 and hosts[0]["has_password"]
    assert "password" not in hosts[0], "list API leaked a plaintext password"
    assert hosts[0]["has_ssh_key"] is False
    print("[4/13] list ok, no plaintext password / key in list response")

    # Online detection belongs exclusively to the local Agent. The old server
    # endpoint must be gone, and the shipped WebUI must have no server fallback.
    code = status_of("/api/hosts/probe", "POST", {"ids": [host["id"]]})
    assert code in (404, 405), f"server-side probe endpoint still alive: HTTP {code}"
    ui = get_text("/static/app.js")
    assert "/api/hosts/probe" not in ui, "WebUI still falls back to server probing"
    assert "/probe'" in ui, "WebUI no longer calls the local Agent /probe"
    settings = call("/api/settings")
    assert "probe_timeout_ms" in settings, "Agent probe timeout setting missing"
    print(f"[5/13] online probe offloaded to local Agent (server endpoint HTTP {code}, "
          f"no WebUI fallback, timeout={settings['probe_timeout_ms']}ms)")

    credential = call(f"/api/hosts/{host['id']}/credential", "POST")
    assert credential["password"] == "s3cret-value"
    assert credential.get("ssh_key") == {}, "password-auth host must not receive a key"
    print("[6/13] credential decrypt ok (no key for password auth)")

    ticket = call("/api/connect-ticket", "POST", {"host_id": host["id"]})
    redeemed = call("/api/connect-ticket/redeem", "POST", {"ticket": ticket["ticket"]})
    assert redeemed["password"] == "s3cret-value"
    assert redeemed.get("ssh_key") == {}, "password-auth ticket must not receive a key"
    try:
        call("/api/connect-ticket/redeem", "POST", {"ticket": ticket["ticket"]})
        raise AssertionError("ticket was reusable")
    except RuntimeError:
        pass
    print("[7/13] one-shot connect ticket ok (cannot be reused)")

    # ------------------------------------------------------------------------ #
    # SSH key auth + private key ENCRYPTED IN THE SERVER DATABASE
    # ------------------------------------------------------------------------ #
    pem = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
           "b3BlbnNzaC1rZXktdjEAAAAAsmoke-test\n"
           "-----END OPENSSH PRIVATE KEY-----\n")
    key_host = call("/api/hosts", "POST", {
        "name": "_smoke_key_" + suffix, "protocol": "ssh", "address": "127.0.0.1",
        "port": 22, "account": "deploy", "password": "s3cret-value",
        "group_id": group["id"],
        "options": {"ssh_auth": "key", "ssh_key_path": r"C:\keys\id_ed25519.ppk",
                    "ssh_param_format": "putty.exe -i %5 -P %2 -l %3 %1",
                    "unknown_key": "must be dropped"},
        "ssh_key": {"filename": "id_ed25519.pem", "content": pem}})
    opts = key_host["options"]
    assert set(opts) == {"ssh_auth", "ssh_key_path", "ssh_param_format"}, \
        f"SSH option whitelist broken: {opts}"
    assert opts["ssh_auth"] == "key" and opts["ssh_key_path"] == r"C:\keys\id_ed25519.ppk"
    assert key_host["has_ssh_key"] is True
    assert key_host["ssh_key_filename"] == "id_ed25519.pem"
    assert len(key_host["ssh_key_fingerprint"]) == 16
    assert "b3BlbnNzaC1rZXktdjEAAAAAsmoke-test" not in json.dumps(key_host), \
        "host response leaked the private key body"
    print("      private key stored in DB: only filename + SHA-256 fingerprint in responses")

    listed = [h for h in call("/api/hosts?group_id=%d" % group["id"])
              if h["id"] == key_host["id"]][0]
    assert listed["has_ssh_key"] and "ssh_key_enc" not in listed, \
        "list response leaked the ciphertext column"
    assert "content" not in json.dumps(listed)

    # A wrong file must be rejected before it is ever written to the database.
    try:
        call("/api/hosts", "POST", {
            "name": "_smoke_badkey_" + suffix, "protocol": "ssh", "address": "127.0.0.1",
            "group_id": group["id"],
            "ssh_key": {"filename": "notes.txt", "content": "just some notes"}})
        raise AssertionError("a non-key file was accepted")
    except RuntimeError:
        pass

    key_cred = call(f"/api/hosts/{key_host['id']}/credential", "POST")
    assert key_cred["password"] == "", "key-auth credential leaked a password"
    assert key_cred["ssh_key"]["content"] == pem
    key_ticket = call("/api/connect-ticket", "POST", {"host_id": key_host["id"]})
    key_redeem = call("/api/connect-ticket/redeem", "POST", {"ticket": key_ticket["ticket"]})
    assert key_redeem["password"] == "", "key-auth ticket leaked a password"
    assert key_redeem["ssh_key"]["content"] == pem, "ticket did not deliver the DB key"
    assert key_redeem["host"]["options"]["ssh_auth"] == "key"
    print("      credential + one-shot ticket deliver the key body only for key auth")

    swapped = call(f"/api/hosts/{key_host['id']}/ssh-key", "PUT",
                   {"filename": "other.ppk",
                    "content": pem.replace("smoke-test", "swapped")})
    assert swapped["ssh_key_filename"] == "other.ppk"
    dumped = call(f"/api/hosts/{key_host['id']}/ssh-key", "GET")
    assert "swapped" in dumped["content"]
    removed = call(f"/api/hosts/{key_host['id']}/ssh-key", "PUT", {"remove": True})
    assert removed["has_ssh_key"] is False
    assert call(f"/api/hosts/{key_host['id']}/credential", "POST")["ssh_key"] == {}
    print("[8/13] key upload / replace / read / delete API ok, no plaintext in list")

    backup = call_raw("/api/export")
    assert backup["format"] == "remotemgr-backup" and len(backup["hosts"]) >= 2
    assert "ssh_key_enc" in backup["hosts"][0], "backup omitted the encrypted key column"
    assert "b3BlbnNzaC1rZXktdjEAAAAAsmoke-test" not in json.dumps(backup), \
        "backup contains a plaintext private key"
    audit = call("/api/audit?limit=50")
    assert any(row["action"] == "credential_read" for row in audit)
    assert any(row["action"] == "ssh_key_upload" for row in audit)
    assert any(row["action"] == "ssh_key_delete" for row in audit)
    print(f"[9/13] export holds ciphertext only ({len(backup['hosts'])} hosts), "
          f"audit ok ({len(audit)} rows)")

    # ------------------------------------------------------------------------ #
    # FTP (FlashFXP) and Web (HTTP/HTTPS) records
    # ------------------------------------------------------------------------ #
    settings = call("/api/settings")
    assert "flashfxp_path" in settings and "browser_path" in settings, \
        "new client-path settings not deployed"

    ftp_host = call("/api/hosts", "POST", {
        "name": "_smoke_ftp_" + suffix, "protocol": "ftp", "address": "ftp.example.com",
        "account": "alice", "password": "ftp-pass", "group_id": group["id"],
        "options": {"ftp_scheme": "sftp", "ftp_auth": "password",
                    "ftp_path": "pub/files", "ftp_local_path": r"D:\Downloads",
                    "ftp_window": "max", "ftp_param_format": "%0 -min %5",
                    "unknown": "drop"}})
    assert ftp_host["port"] == 21, "ftp default port missing"
    ftp_opts = ftp_host["options"]
    assert set(ftp_opts) == {"ftp_scheme", "ftp_auth", "ftp_path", "ftp_local_path",
                             "ftp_window", "ftp_param_format"}, \
        f"FTP option whitelist broken: {ftp_opts}"
    assert ftp_opts["ftp_scheme"] == "sftp" and ftp_opts["ftp_window"] == "max"
    assert ftp_opts["ftp_local_path"] == r"D:\Downloads"
    assert ftp_opts["ftp_param_format"] == "%0 -min %5"

    anon_host = call("/api/hosts", "POST", {
        "name": "_smoke_anon_" + suffix, "protocol": "ftp", "address": "ftp.example.com",
        "port": 990, "group_id": group["id"],
        "options": {"ftp_scheme": "ftps", "ftp_auth": "anonymous",
                    "ftp_param_format": "no-url-placeholder", "web_scheme": "http"}})
    assert set(anon_host["options"]) == {"ftp_scheme", "ftp_auth", "ftp_path",
                                         "ftp_local_path", "ftp_window",
                                         "ftp_param_format"}
    assert anon_host["options"]["ftp_param_format"] == "", \
        "a template without %5 was accepted"
    assert "web_scheme" not in anon_host["options"], "cross-protocol option leaked"

    web_host = call("/api/hosts", "POST", {
        "name": "_smoke_web_" + suffix, "protocol": "web", "address": "portal.lan",
        "account": "admin", "password": "web-pass", "group_id": group["id"],
        "options": {"web_scheme": "http", "web_auth": "none", "web_path": "admin/login",
                    "web_param_format": "%0 --incognito %5"}})
    assert web_host["port"] == 443, "web default port missing"
    web_opts = web_host["options"]
    assert set(web_opts) == {"web_scheme", "web_auth", "web_path", "web_param_format"}, \
        f"Web option whitelist broken: {web_opts}"
    assert web_opts["web_scheme"] == "http" and web_opts["web_auth"] == "none"

    basic_host = call("/api/hosts", "POST", {
        "name": "_smoke_basic_" + suffix, "protocol": "web", "address": "portal.lan",
        "port": 8080, "account": "admin", "password": "web-pass",
        "group_id": group["id"], "options": {"web_auth": "basic"}})

    def ticket_password(host_id):
        ticket = call("/api/connect-ticket", "POST", {"host_id": host_id})
        return call("/api/connect-ticket/redeem", "POST",
                    {"ticket": ticket["ticket"]})["password"]

    assert ticket_password(ftp_host["id"]) == "ftp-pass", "FTP lost its password"
    assert ticket_password(anon_host["id"]) == "", "anonymous FTP received a password"
    assert ticket_password(web_host["id"]) == "", "plain Web record received a password"
    assert ticket_password(basic_host["id"]) == "web-pass", \
        "Web Basic auth record did not receive its password"

    try:
        call("/api/hosts", "POST", {"name": "_smoke_badproto_" + suffix,
                                   "protocol": "gopher", "address": "x",
                                   "group_id": group["id"]})
        raise AssertionError("unknown protocol accepted")
    except RuntimeError:
        pass
    print("[10/13] FTP (FlashFXP) / Web records: whitelist, default ports, "
          "templates and per-mode ticket credentials ok")

    # A Web record commonly IS a bookmark: the address field can hold the
    # complete URL including port, path, query and SPA hash route. It must be
    # stored verbatim (up to 512 chars); other protocols must reject URLs.
    full_url = "http://49.234.138.90:6443/static/#/proxies/tcp"
    full_host = call("/api/hosts", "POST", {
        "name": "_smoke_fullurl_" + suffix, "protocol": "web",
        "address": full_url, "port": 6443, "account": "admin",
        "password": "web-pass", "group_id": group["id"],
        "options": {"web_scheme": "https", "web_auth": "basic",
                    "web_path": "ignored"}})
    assert full_host["address"] == full_url, "full URL was altered on save"
    assert full_host["options"]["web_scheme"] == "https", "options were dropped"
    assert ticket_password(full_host["id"]) == "web-pass", \
        "Basic auth over a full URL lost its password"
    try:
        call("/api/hosts", "POST", {"name": "_smoke_badurl_" + suffix,
                                   "protocol": "rdp", "address": "http://x.example/path",
                                   "group_id": group["id"]})
        raise AssertionError("a full URL was accepted for a non-Web record")
    except RuntimeError:
        pass
    print("[11/13] Web full-URL address stored verbatim; URLs rejected for other protocols")

    # ------------------------------------------------------------------------ #
    # WinSCP records (SFTP / SCP / FTP / FTPS / WebDAV)
    # ------------------------------------------------------------------------ #
    assert "winscp_path" in settings, "winscp_path client setting not deployed"
    winscp_host = call("/api/hosts", "POST", {
        "name": "_smoke_winscp_" + suffix, "protocol": "winscp",
        "address": "files.example.com", "account": "bob",
        "password": "scp-pass", "group_id": group["id"],
        "options": {"winscp_scheme": "sftp", "winscp_auth": "password",
                    "winscp_dir": "/srv/data", "winscp_window": "min",
                    "winscp_param_format": "%0 /newinstance %5",
                    "unknown": "drop"}})
    assert winscp_host["port"] == 22, "winscp default port missing"
    winscp_opts = winscp_host["options"]
    assert set(winscp_opts) == {"winscp_scheme", "winscp_auth", "winscp_dir",
                                "winscp_window", "winscp_param_format"}, \
        f"WinSCP option whitelist broken: {winscp_opts}"
    assert winscp_opts["winscp_scheme"] == "sftp"
    assert winscp_opts["winscp_window"] == "min"
    assert winscp_opts["winscp_param_format"] == "%0 /newinstance %5"

    winscp_anon = call("/api/hosts", "POST", {
        "name": "_smoke_winscpanon_" + suffix, "protocol": "winscp",
        "address": "ftp.example.com", "port": 21, "group_id": group["id"],
        "options": {"winscp_scheme": "ftp", "winscp_auth": "anonymous",
                    "winscp_param_format": "no-url-placeholder",
                    "ftp_scheme": "sftp"}})
    assert set(winscp_anon["options"]) == {"winscp_scheme", "winscp_auth",
                                           "winscp_dir", "winscp_window",
                                           "winscp_param_format"}
    assert winscp_anon["options"]["winscp_param_format"] == "", \
        "a winscp template without %5 was accepted"
    assert "ftp_scheme" not in winscp_anon["options"], "cross-protocol option leaked"

    assert ticket_password(winscp_host["id"]) == "scp-pass", "WinSCP lost its password"
    assert ticket_password(winscp_anon["id"]) == "", \
        "anonymous WinSCP record received a password"
    print("[12/13] WinSCP records: whitelist, default port, templates, "
          "per-mode ticket credentials ok")

    for item in (key_host, host, ftp_host, anon_host, web_host, basic_host,
                 full_host, winscp_host, winscp_anon):
        call(f"/api/hosts/{item['id']}", "DELETE")
    call(f"/api/groups/{group['id']}", "DELETE")
    print("[13/13] cleanup done — ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("SMOKE TEST FAILED:", exc, file=sys.stderr)
        sys.exit(1)
