"""Acceptance tests against a disposable Dovecot server in Docker (never a real mailbox).

Enable with BG_IMAP_DOVECOT_TESTS=1 (needs docker). Test data is written through a separate "admin"
IMAP connection; every call through the MCP tools is recorded to prove only read-only commands are sent.
"""
import email.utils
import imaplib
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import pytest

from bg_imap_mcp import server
from bg_imap_mcp.imap_client import MailError, _quote, _utf7_encode

pytestmark = pytest.mark.skipif(os.getenv("BG_IMAP_DOVECOT_TESTS") != "1" or not shutil.which("docker"),
                                reason="set BG_IMAP_DOVECOT_TESTS=1 (requires docker)")

IMAGE = os.getenv("BG_IMAP_DOVECOT_IMAGE", "dovecot/dovecot:latest")
USER = "tester@example.test"
READ_ONLY_COMMANDS = {"LOGIN", "CAPABILITY", "EXAMINE", "UID", "LIST", "STATUS", "LOGOUT", "NOOP"}
RECORDED: list[tuple[str, tuple]] | None = None


def _run(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout.strip()


@pytest.fixture(scope="module")
def dovecot(tmp_path_factory):
    d = tmp_path_factory.mktemp("dovecot")
    certs = d / "ssl"
    certs.mkdir()
    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=bg-imap test CA",
         "-keyout", str(d / "ca.key"), "-out", str(d / "ca.crt"),
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    _run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
         "-keyout", str(certs / "tls.key"), "-out", str(d / "tls.csr"))
    (d / "ext.cnf").write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n"
                               "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    _run("openssl", "x509", "-req", "-in", str(d / "tls.csr"), "-CA", str(d / "ca.crt"), "-CAkey", str(d / "ca.key"),
         "-CAcreateserial", "-days", "1", "-out", str(certs / "tls.crt"), "-extfile", str(d / "ext.cnf"))
    for f in certs.iterdir():
        f.chmod(0o644)  # readable by the container's vmail user; throwaway test key
    certs.chmod(0o755)
    password = secrets.token_urlsafe(24)
    cid = _run("docker", "run", "-d", "--rm", "-e", f"USER_PASSWORD={password}", "-p", "127.0.0.1::31993",
               "-v", f"{certs}:/etc/dovecot/ssl:ro", IMAGE)
    try:
        port = int(_run("docker", "port", cid, "31993/tcp").splitlines()[0].rsplit(":", 1)[1])
        ctx = ssl.create_default_context(cafile=str(d / "ca.crt"))
        for _ in range(60):
            try:
                c = imaplib.IMAP4_SSL("localhost", port, ssl_context=ctx, timeout=5)
                c.login(USER, password)
                c.logout()
                break
            except (OSError, imaplib.IMAP4.error):
                time.sleep(0.5)
        else:
            pytest.fail("dovecot did not start:\n" + _run("docker", "logs", cid))
        env = {"IMAP_HOST": "localhost", "IMAP_PORT": str(port), "IMAP_USERNAME": USER, "IMAP_PASSWORD": password,
               "IMAP_CA_FILE": str(d / "ca.crt"), "OAUTH_STATE_DB": str(d / "state" / "oauth.sqlite3"),
               "IMAP_DEFAULT_FOLDER": "INBOX", "IMAP_MAX_BODY_CHARS": "20000", "IMAP_MAX_MESSAGE_BYTES": "3000000",
               "IMAP_MAX_PAGE_SIZE": "500", "IMAP_MAX_BATCH": "100", "IMAP_BATCH_OUTPUT_CHARS": "150000"}
        with pytest.MonkeyPatch.context() as mp:
            for k, v in env.items():
                mp.setenv(k, v)
            yield {"port": port, "password": password, "ctx": ctx, "state": d / "state"}
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)


@pytest.fixture(autouse=True)
def record_commands(monkeypatch):
    """Record every IMAP command issued while a tool runs (admin connections are excluded)."""
    real = imaplib.IMAP4._command

    def recording(self, name, *args):
        if RECORDED is not None and not getattr(self, "_is_admin", False):
            RECORDED.append((name, args))
        return real(self, name, *args)
    monkeypatch.setattr(imaplib.IMAP4, "_command", recording)


def tool(name, **kwargs):
    """Call an MCP tool function, asserting it only issued read-only IMAP commands."""
    global RECORDED
    RECORDED = []
    try:
        result = getattr(server, name)(**kwargs)
    finally:
        cmds, RECORDED = RECORDED, None
    for cmd, args in cmds:
        assert cmd in READ_ONLY_COMMANDS, cmd
        if cmd == "UID":
            assert args[0] in ("SEARCH", "FETCH"), args[0]
            if args[0] == "FETCH":
                assert "BODY[" not in args[2].replace("BODY.PEEK[", ""), args[2]
    return result


class Admin:
    """Test-data writer on its own connection (the tools under test never write)."""

    def __init__(self, dv):
        self.dv = dv

    def __enter__(self):
        self.c = imaplib.IMAP4_SSL("localhost", self.dv["port"], ssl_context=self.dv["ctx"])
        self.c._is_admin = True
        self.c.login(USER, self.dv["password"])
        return self

    def __exit__(self, *exc):
        self.c.logout()

    def mbox(self, folder):
        return _quote(_utf7_encode(folder))

    def create(self, folder):
        self.c.create(self.mbox(folder))

    def delete(self, folder):
        self.c.delete(self.mbox(folder))

    def append(self, folder, msg, when: datetime, flags=None):
        typ, data = self.c.append(self.mbox(folder), flags, imaplib.Time2Internaldate(when.timestamp()),
                                  msg if isinstance(msg, bytes) else msg.as_bytes())
        assert typ == "OK", data
        return int(data[0].split(b"APPENDUID ")[1].split()[1].rstrip(b"]")) if b"APPENDUID" in data[0] else None

    def expunge(self, folder, uid):
        self.c.select(self.mbox(folder))
        self.c.uid("STORE", str(uid), "+FLAGS.SILENT", "(\\Deleted)")
        self.c.expunge()
        self.c.close()

    def flags(self, folder):
        self.c.select(self.mbox(folder), readonly=True)
        typ, data = self.c.uid("FETCH", "1:*", "(FLAGS)")
        self.c.close()
        out = {}
        for item in data:
            if isinstance(item, bytes) and b"UID" in item:
                uid = int(item.split(b"UID ")[1].split()[0].rstrip(b")"))
                out[uid] = item.split(b"FLAGS (")[1].split(b")")[0].decode()
        return out


def utc(y, m, d, h=12):
    return datetime(y, m, d, h, tzinfo=timezone.utc)


def recent():
    return datetime.now(timezone.utc) - timedelta(hours=1)


def mail(subject, body="hello", sender="alice@example.org", to="tester@example.test", **headers):
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, sender, to
    msg["Message-ID"] = email.utils.make_msgid(domain="example.org")
    msg["Date"] = email.utils.format_datetime(datetime.now(timezone.utc))
    for k, v in headers.items():
        msg[k.replace("_", "-")] = v
    msg.set_content(body)
    return msg


def enumerate_all(**query):
    pages, cursor, uv = [], None, None
    while True:
        page = tool("search_messages_advanced", cursor=cursor, **query) if cursor else tool(
            "search_messages_advanced", **query)
        uv = uv or page["uidvalidity"]
        assert page["uidvalidity"] == uv
        pages.append(page)
        cursor = page["next_cursor"]
        if not cursor:
            return pages
        query = {"limit": query.get("limit", 200)}


# --- Historical enumeration --------------------------------------------------------------------

@pytest.fixture(scope="module")
def history(dovecot):
    # A year in the past: Dovecot clamps future INTERNALDATEs to "now".
    folder = "History 2025"
    dates = [utc(2024, 11, 4), utc(2024, 11, 5, 1), utc(2024, 11, 5)] + \
            [utc(2024, 11, 6) + timedelta(days=11 * i) for i in range(33)] + \
            [utc(2025, 11, 5, 23), utc(2025, 11, 6), utc(2025, 12, 1)]
    with Admin(dovecot) as a:
        a.create(folder)
        uids = {a.append(folder, mail(f"history {i}", sender=f"s{i % 4}@example.org"), when): when
                for i, when in enumerate(dates)}
    expected = sorted(u for u, w in uids.items() if utc(2024, 11, 5, 0) <= w < utc(2025, 11, 6, 0))
    return {"folder": folder, "uids": uids, "expected": expected}


def test_enumeration_pages_exactly_once_with_date_bounds(history):
    pages = enumerate_all(folder=history["folder"], date_from="2024-11-05", date_to="2025-11-06", limit=7)
    got = [m["uid"] for p in pages for m in p["messages"]]
    assert len(pages) > 1 and got == history["expected"]  # inclusive from, exclusive to, ascending, no dups
    assert pages[0]["matching_count"] == len(history["expected"]) and pages[-1]["remaining_count"] == 0
    first = pages[0]["messages"][0]
    assert first["internal_date"].endswith("Z") and first["from"].endswith("@example.org")
    assert {"seen", "answered", "flagged", "has_attachments", "list_id", "size_bytes"} <= set(first)


def test_enumeration_descending_and_repeatable(history):
    q = dict(folder=history["folder"], date_from="2024-11-05", date_to="2025-11-06", limit=10)
    desc = [m["uid"] for p in enumerate_all(sort="uid_desc", **q) for m in p["messages"]]
    assert desc == history["expected"][::-1]
    again = [m["uid"] for p in enumerate_all(**q) for m in p["messages"]]
    assert again == history["expected"]


def test_sender_filter(history):
    got = [m["uid"] for p in enumerate_all(folder=history["folder"], sender="s1@example.org") for m in p["messages"]]
    assert got and all(history["uids"][u] for u in got) and len(got) == sum(
        1 for i in range(len(history["uids"])) if i % 4 == 1)


def test_arrivals_and_expunge_during_enumeration(dovecot):
    folder = "Moving"
    with Admin(dovecot) as a:
        a.create(folder)
        uids = [a.append(folder, mail(f"m{i}"), utc(2026, 3, 1) + timedelta(hours=i)) for i in range(12)]
    page1 = tool("search_messages_advanced", folder=folder, date_from="2026-01-01", limit=5)
    assert [m["uid"] for m in page1["messages"]] == uids[:5]
    with Admin(dovecot) as a:
        late = a.append(folder, mail("late arrival"), utc(2026, 3, 2))
        a.expunge(folder, uids[7])
    rest, cursor = [], page1["next_cursor"]
    while cursor:
        page = tool("search_messages_advanced", cursor=cursor, limit=5)
        rest += [m["uid"] for m in page["messages"]]
        cursor = page["next_cursor"]
    assert rest == uids[5:7] + uids[8:]  # expunged one gone, late arrival excluded by the snapshot bound
    fresh = [m["uid"] for p in enumerate_all(folder=folder, date_from="2026-01-01") for m in p["messages"]]
    assert late in fresh and uids[7] not in fresh


def test_cursor_integrity_and_query_binding(history):
    page = tool("search_messages_advanced", folder=history["folder"], limit=3)
    body, mac = page["next_cursor"].split(".")
    with pytest.raises(MailError, match="INVALID_CURSOR"):
        tool("search_messages_advanced", cursor=body[:-1] + ("A" if body[-1] != "A" else "B") + "." + mac)
    with pytest.raises(MailError, match="INVALID_CURSOR"):
        tool("search_messages_advanced", cursor=page["next_cursor"], sender="other@example.org")
    tool("search_messages_advanced", cursor=page["next_cursor"], folder=history["folder"], limit=50)  # same is ok


def test_uidvalidity_change_detected(dovecot):
    folder = "Volatile"
    with Admin(dovecot) as a:
        a.create(folder)
        for i in range(4):
            a.append(folder, mail(f"v{i}"), utc(2026, 5, 1))
    page = tool("search_messages_advanced", folder=folder, limit=2)
    cp = tool("get_mailbox_changes", folder=folder)["next_checkpoint"]
    time.sleep(1.1)  # Dovecot derives UIDVALIDITY from the clock
    with Admin(dovecot) as a:
        a.delete(folder)
        a.create(folder)
        a.append(folder, mail("after reset"), utc(2026, 5, 2))
    with pytest.raises(MailError, match="UIDVALIDITY_CHANGED"):
        tool("search_messages_advanced", cursor=page["next_cursor"])
    with pytest.raises(MailError, match="UIDVALIDITY_CHANGED"):
        tool("get_messages_batch", folder=folder, uids=[1], uidvalidity=page["uidvalidity"])
    res = tool("get_mailbox_changes", checkpoint=cp)
    assert res["resync_required"] and res["changes"]["new_messages"] == []
    assert tool("get_mailbox_changes", checkpoint=res["next_checkpoint"])["resync_required"] is False


# --- Bulk retrieval ----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def corpus(dovecot):
    folder = "Corpus"
    msgs = {}
    plain = mail("plain", "Plain text body\nsecond line")
    html = EmailMessage()
    html["Subject"], html["From"] = "html only", "news@example.org"
    html.set_content('<html><body><p>Hello <b>reader</b></p><p><a href="https://example.org/a">Read more</a></p>'
                     '<script>evil()</script></body></html>', subtype="html")
    alt = mail("alternative", "The plain alternative " * 20)
    alt.add_alternative("<p>The html alternative</p>", subtype="html")
    att = mail("with attachment", "See attached")
    att.add_attachment(b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="résumé.pdf")
    uni = mail("Grüße 日本語", "Ünïcödé body ☕", sender="Zoë <zoe@example.org>")
    big = mail("big", "".join(f"line {i:05d}\n" for i in range(6000)))
    lst = mail("list post", "list body", List_ID="Dev Talk <dev.lists.example.org>", Precedence="list",
               List_Unsubscribe="<mailto:unsub@example.org>")
    malformed = (b"Subject: broken\r\nFrom: x@example.org\r\nContent-Type: multipart/mixed; boundary=\"zz\"\r\n\r\n"
                 b"--zz\r\nContent-Type: text/plain; charset=bogus-charset\r\n\r\nstill readable\r\n--zz")
    with Admin(dovecot) as a:
        a.create(folder)
        for key, m in (("plain", plain), ("html", html), ("alt", alt), ("att", att), ("uni", uni), ("big", big),
                       ("list", lst), ("malformed", malformed)):
            msgs[key] = a.append(folder, m, utc(2026, 6, 1))
        root = mail("thread root", "root")
        reply = mail("Re: thread root", "reply", In_Reply_To=root["Message-ID"], References=root["Message-ID"])
        msgs["root"], msgs["reply"] = a.append(folder, root, utc(2026, 6, 2)), a.append(folder, reply, utc(2026, 6, 3))
        for i in range(16):
            msgs[f"filler{i}"] = a.append(folder, mail(f"filler {i}"), utc(2026, 6, 4))
        msgs["seen"] = a.append(folder, mail("already read"), utc(2026, 6, 5), flags="(\\Seen)")
    return {"folder": folder, "uids": msgs}


def test_batch_of_25_decodes_everything(dovecot, corpus):
    u = corpus["uids"]
    with Admin(dovecot) as a:
        before = a.flags(corpus["folder"])
    uids = list(u.values())[:25]
    assert len(uids) == 25
    res = tool("get_messages_batch", folder=corpus["folder"], uids=uids, include_headers=True)
    by = {m["uid"]: m for m in res["messages"]}
    assert len(by) == 25 and all(m["status"] == "ok" for m in by.values())
    assert by[u["plain"]]["body"] == "Plain text body\nsecond line" and by[u["plain"]]["body_source"] == "text/plain"
    h = by[u["html"]]
    assert h["body_source"] == "text/html" and "Hello reader" in h["body"] and "evil" not in h["body"]
    assert "Read more (https://example.org/a)" in h["body"]
    assert by[u["alt"]]["body"].startswith("The plain alternative")
    a = by[u["att"]]
    assert a["has_attachments"] and a["attachments"] == [
        {"filename": "résumé.pdf", "content_type": "application/pdf", "size_bytes": 13}]
    assert by[u["uni"]]["subject"] == "Grüße 日本語" and by[u["uni"]]["from_name"] == "Zoë"
    assert "Ünïcödé body ☕" in by[u["uni"]]["body"]
    assert by[u["list"]]["headers_normalized"]["list_id"] == "dev.lists.example.org"
    assert "still readable" in by[u["malformed"]]["body"]
    with Admin(dovecot) as a:
        assert a.flags(corpus["folder"]) == before  # nothing marked read
    assert "\\Seen" in before[u["seen"]] and not any("\\Seen" in f for k, f in before.items() if k != u["seen"])


def test_truncated_body_continues_with_offset(corpus):
    uid = corpus["uids"]["big"]
    original = "".join(f"line {i:05d}\n" for i in range(6000)).strip()
    parts, offset = [], 0
    while offset is not None:
        m = tool("get_messages_batch", folder=corpus["folder"], uids=[uid], max_body_chars=17000,
                 body_offset=offset)["messages"][0]
        assert m["body_total_chars"] == len(original)
        parts.append(m["body"])
        offset = m["next_body_offset"]
    assert len(parts) == 4 and "".join(parts) == original


def test_output_budget_spreads_over_batch(monkeypatch, corpus):
    monkeypatch.setenv("IMAP_BATCH_OUTPUT_CHARS", "20000")
    res = tool("get_messages_batch", folder=corpus["folder"], uids=[corpus["uids"]["big"], corpus["uids"]["plain"]])
    assert res["per_message_body_limit"] == 10000
    assert res["messages"][0]["body_truncated"] and len(res["messages"][0]["body"]) == 10000


def test_missing_and_oversized_uids_fail_individually(monkeypatch, corpus):
    monkeypatch.setenv("IMAP_MAX_MESSAGE_BYTES", "50000")
    u = corpus["uids"]
    res = tool("get_messages_batch", folder=corpus["folder"], uids=[u["plain"], 999999, u["big"]])
    status = {m["uid"]: m["status"] for m in res["messages"]}
    assert status == {u["plain"]: "ok", 999999: "MESSAGE_NOT_FOUND", u["big"]: "MESSAGE_TOO_LARGE"}
    assert res["messages"][2]["subject"] == "big"  # metadata still returned for the oversized one


def test_headers_threads_and_lists(corpus):
    u = corpus["uids"]
    res = tool("get_message_headers", folder=corpus["folder"], uids=[u["root"], u["reply"], u["list"]])
    by = {m["uid"]: m for m in res["messages"]}
    root_id = by[u["root"]]["normalized"]["message_id"]
    assert by[u["reply"]]["normalized"]["in_reply_to"] == [root_id]
    assert by[u["reply"]]["normalized"]["references"] == [root_id]
    assert by[u["list"]]["normalized"]["list_id"] == "dev.lists.example.org"
    assert by[u["list"]]["normalized"]["list_unsubscribe"] == ["mailto:unsub@example.org"]
    everything = tool("get_message_headers", folder=corpus["folder"], uids=[u["plain"]], headers=["*"])
    assert {"Subject", "From", "Message-ID"} <= set(everything["messages"][0]["headers"])


def test_read_message_enhancements(corpus):
    m = tool("read_message", folder=corpus["folder"], uid=corpus["uids"]["att"])
    assert m["seen"] is False and m["has_attachments"] and m["internal_date"] == "2026-06-01T12:00:00Z"
    assert m["from_address"] == "alice@example.org" and m["body_format"] == "text"
    assert {"uid", "subject", "from", "to", "cc", "date", "message_id", "body", "body_truncated",
            "attachments", "folder", "uidvalidity", "size_bytes"} <= set(m)  # original fields kept


# --- Inventory ---------------------------------------------------------------------------------

def test_inventory(dovecot, corpus):
    with Admin(dovecot) as a:
        for name in ("Sent", "Drafts", "Trash", "Junk", "Projekt Ü/Unterordner"):
            a.create(name)  # special-use flags come from the server config, not the name
    inv = {f["name"]: f for f in tool("get_mailbox_inventory")["folders"]}
    assert inv["Corpus"]["total_messages"] == len(corpus["uids"]) and inv["Corpus"]["unread_messages"] == len(
        corpus["uids"]) - 1
    assert inv["Corpus"]["uidvalidity"] and inv["Corpus"]["uidnext"] > max(corpus["uids"].values())
    assert inv["Sent"]["special_use"] == "\\Sent" and inv["Sent"]["include_in_history_default"]
    for name in ("Trash", "Junk", "Drafts"):
        assert not inv[name]["include_in_history_default"]
    assert inv["Projekt Ü/Unterordner"]["parent"] == "Projekt Ü"


# --- Incremental monitoring --------------------------------------------------------------------

def test_monitoring_flow(dovecot):
    folder = "Monitor"
    with Admin(dovecot) as a:
        a.create(folder)
        a.append(folder, mail("old unread"), utc(2026, 1, 1))  # unread but not new: must never be reported
    base = tool("get_mailbox_changes", folder=folder)
    assert base["baseline"] and base["changes"]["new_messages"] == []
    assert base["changes"]["deleted_uids"] is None and "deleted_uids" in base["unsupported"]
    with Admin(dovecot) as a:
        three = [a.append(folder, mail(f"new {i}"), recent()) for i in range(3)]
    r1 = tool("get_mailbox_changes", checkpoint=base["next_checkpoint"])
    assert [m["uid"] for m in r1["changes"]["new_messages"]] == three and not r1["has_more"]
    retry = tool("get_mailbox_changes", checkpoint=base["next_checkpoint"])  # failed-poll retry is safe
    assert [m["uid"] for m in retry["changes"]["new_messages"]] == three
    r2 = tool("get_mailbox_changes", checkpoint=r1["next_checkpoint"])
    assert r2["changes"]["new_messages"] == [] and r2["next_checkpoint"]

    # Pagination across several pages, with a message arriving mid-way.
    with Admin(dovecot) as a:
        five = [a.append(folder, mail(f"burst {i}"), recent()) for i in range(5)]
    seen, cp, polls = [], r2["next_checkpoint"], 0
    while True:
        r = tool("get_mailbox_changes", checkpoint=cp, limit=2)
        seen += [m["uid"] for m in r["changes"]["new_messages"]]
        cp, polls = r["next_checkpoint"], polls + 1
        if polls == 1:
            with Admin(dovecot) as a:
                five.append(a.append(folder, mail("mid-pagination"), recent()))
        if not r["has_more"]:
            break
    assert seen == five and polls == 3

    # Expunged before the poll: reported nowhere, nothing else lost.
    with Admin(dovecot) as a:
        x, y = (a.append(folder, mail(f"x{i}"), recent()) for i in range(2))
        a.expunge(folder, x)
    r = tool("get_mailbox_changes", checkpoint=cp)
    assert [m["uid"] for m in r["changes"]["new_messages"]] == [y]

    # "Restart": every call reloads the signing key from the state dir, so an old checkpoint still works.
    assert tool("get_mailbox_changes", checkpoint=cp)["changes"]["new_messages"][0]["uid"] == y


def test_checkpoint_errors(corpus):
    cp = tool("get_mailbox_changes", folder="INBOX")["next_checkpoint"]
    with pytest.raises(MailError, match="INVALID_CURSOR"):
        tool("get_mailbox_changes", checkpoint=cp, folder="Sent")
    with pytest.raises(MailError, match="INVALID_CURSOR"):
        tool("get_mailbox_changes", checkpoint=cp[:-3] + "AAA")
    search_cursor = tool("search_messages_advanced", folder=corpus["folder"], limit=1)["next_cursor"]
    with pytest.raises(MailError, match="INVALID_CURSOR"):
        tool("get_mailbox_changes", checkpoint=search_cursor)  # a search cursor is not a checkpoint


# --- Safety ------------------------------------------------------------------------------------

def test_no_credentials_in_results_or_errors(dovecot, corpus):
    pw = dovecot["password"]
    out = [tool("check_connection"), tool("get_mailbox_inventory"),
           tool("search_messages_advanced", folder=corpus["folder"]),
           tool("get_messages_batch", folder=corpus["folder"], uids=list(corpus["uids"].values())[:5])]
    assert pw not in json.dumps(out)
    with pytest.raises(MailError) as info:
        tool("folder_status", folder="No Such Folder")
    assert info.value.code == "FOLDER_NOT_FOUND" and pw not in str(info.value)
    key = (dovecot["state"] / "cursor.key").read_bytes()
    assert key.hex() not in json.dumps(out)


def test_wrong_password_and_untrusted_cert(dovecot, monkeypatch):
    monkeypatch.setenv("IMAP_PASSWORD", "wrong-password")
    with pytest.raises(MailError, match="AUTHENTICATION_FAILED"):
        tool("check_connection")
    monkeypatch.setenv("IMAP_PASSWORD", dovecot["password"])
    monkeypatch.delenv("IMAP_CA_FILE")  # system trust store does not know the test CA
    with pytest.raises(MailError, match="IMAP_CONNECTION_ERROR: TLS certificate verification failed"):
        tool("check_connection")


def test_unicode_search(dovecot, corpus):
    got = [m["uid"] for p in enumerate_all(folder=corpus["folder"], subject="Grüße") for m in p["messages"]]
    assert got == [corpus["uids"]["uni"]]
    legacy = tool("search_messages", folder=corpus["folder"], query="日本語", field="subject")
    assert [m["uid"] for m in legacy["messages"]] == [corpus["uids"]["uni"]]


def test_timeout_is_reported(dovecot, monkeypatch):
    # A listener that accepts TCP but never speaks TLS.
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    monkeypatch.setenv("IMAP_PORT", str(srv.getsockname()[1]))
    monkeypatch.setenv("IMAP_TIMEOUT", "1")
    monkeypatch.setattr("bg_imap_mcp.imap_client.time.sleep", lambda s: None)
    try:
        with pytest.raises(MailError, match="IMAP_TIMEOUT"):
            tool("check_connection")
    finally:
        srv.close()
