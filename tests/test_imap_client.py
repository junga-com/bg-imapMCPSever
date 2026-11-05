import imaplib
from contextlib import contextmanager
from email.message import EmailMessage

import pytest

from bg_imap_mcp import imap_client
from bg_imap_mcp.imap_client import (Settings, MailError, _fetch_records, _message_summary, _parse_list,
                                     _parse_search_query, _utf7_decode, _utf7_encode, _validate_folder,
                                     _validate_uid, html_to_text, IMAPClient)


def sample_email(subject="Test message"):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "Sender <sender@example.org>"
    msg["To"] = "recipient@example.org"
    msg.set_content("Plain body\n")
    msg.add_attachment(b"data", maintype="application", subtype="octet-stream", filename="file.bin")
    return msg.as_bytes()


def test_summary_and_attachments():
    info = _message_summary(sample_email(), 123, 100, True)
    assert info["uid"] == 123
    assert info["subject"] == "Test message"
    assert "Plain body" in info["body"]
    assert info["attachments"][0]["filename"] == "file.bin"
    assert info["attachments"][0]["size_bytes"] == 4


def test_plain_headers_only():
    assert "body" not in _message_summary(sample_email(), 5, 100, False)


def test_unicode_headers_and_body():
    msg = EmailMessage()
    msg["Subject"] = "Grüße – 日本語"
    msg["From"] = "Zoë <zoe@example.org>"
    msg.set_content("Café ☕\n", charset="utf-8", cte="quoted-printable")
    info = _message_summary(msg.as_bytes(), 1, 100, True)
    assert info["subject"] == "Grüße – 日本語"
    assert "Zoë" in info["from"]
    assert "Café ☕" in info["body"]


def test_body_truncation():
    msg = EmailMessage()
    msg.set_content("x" * 50)
    info = _message_summary(msg.as_bytes(), 1, 10, True)
    assert info["body"] == "x" * 10 and info["body_truncated"]


def test_html_fallback():
    msg = EmailMessage()
    msg.set_content("<p>Hello <b>world</b></p><script>ignore me</script>", subtype="html")
    result = _message_summary(msg.as_bytes(), 1, 200, True)
    assert "Hello world" in result["body"]
    assert "ignore me" not in result["body"]


def test_stub_plain_part_falls_back_to_html():
    msg = EmailMessage()
    msg.set_content("View in browser")
    msg.add_alternative("<p>" + "Real newsletter content. " * 20 + "</p>", subtype="html")
    result = _message_summary(msg.as_bytes(), 1, 2000, True)
    assert result["body_source"] == "text/html" and "Real newsletter content" in result["body"]


def test_real_plain_part_preferred():
    msg = EmailMessage()
    msg.set_content("A genuine plain text reply. " * 10)
    msg.add_alternative("<p>" + "Different html. " * 50 + "</p>", subtype="html")
    assert _message_summary(msg.as_bytes(), 1, 2000, True)["body_source"] == "text/plain"


def test_html_entities_decoded_once():
    assert html_to_text("<p>a &amp;lt; b</p>") == "a &lt; b"


def test_search_escaping():
    assert _parse_search_query('hello "there"') == '"hello \\"there\\""'
    for bad in ("hello\r\nBAD", "tab\there", "", "x" * 301):
        with pytest.raises(MailError):
            _parse_search_query(bad)


def test_uid_validation():
    for invalid in (0, -1, True, "3", 2**32):
        with pytest.raises(MailError):
            _validate_uid(invalid)


def test_missing_configuration():
    with pytest.raises(MailError):
        Settings(host="", port=993, username="a", password="b").validate()


def test_settings_repr_hides_password():
    assert "hunter2" not in repr(Settings("h", 993, "u", "hunter2"))


@pytest.mark.parametrize("name,encoded", [
    ("INBOX", "INBOX"),
    ("Entwürfe", "Entw&APw-rfe"),
    ("A & B", "A &- B"),
    ("~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-"),
])
def test_modified_utf7(name, encoded):
    assert _utf7_encode(name) == encoded
    assert _utf7_decode(encoded) == name


def test_folder_quoting_and_injection():
    assert _validate_folder("INBOX.Sent Items") == '"INBOX.Sent Items"'
    assert _validate_folder('a"b\\c') == '"a\\"b\\\\c"'
    assert _validate_folder("Brouillons é") == '"Brouillons &AOk-"'
    for bad in ("", "INBOX\r\nA1 DELETE INBOX", "x\x00", "x\ty", "x" * 513, None):
        with pytest.raises(MailError):
            _validate_folder(bad)


def test_parse_list():
    data = [b'(\\HasNoChildren) "." INBOX',
            b'(\\HasNoChildren \\Sent) "." "INBOX.Sent Items"',
            b'(\\Noselect) NIL "Public"',
            b'(\\HasNoChildren) "." "INBOX.Entw&APw-rfe"',
            (b'(\\HasNoChildren) "." {11}', b'INBOX."odd"')]
    folders = _parse_list(data)
    assert [f["name"] for f in folders] == ["INBOX", "INBOX.Sent Items", "Public", "INBOX.Entwürfe", 'INBOX."odd"']
    assert folders[1]["flags"] == ["\\HasNoChildren", "\\Sent"]
    assert folders[2]["delimiter"] is None and folders[0]["delimiter"] == "."


def test_fetch_records_trailing_flags_and_unsolicited():
    data = [(b'1 (UID 8 RFC822.SIZE 99 BODY[] {3}', b'abc'), b' FLAGS (\\Seen))',
            b'2 (UID 8 FLAGS (\\Seen \\Answered))',  # unsolicited update must not drop the literal
            b'3 (FLAGS ())']
    rec = _fetch_records(data)
    assert list(rec) == [8]
    assert rec[8]["literal"] == b"abc" and rec[8]["size"] == 99
    assert rec[8]["flags"] == ["\\Seen", "\\Answered"]


class FakeConn:
    def __init__(self, uids=b"1 3 8", size=500, uidvalidity=b"42"):
        self.commands = []
        self.literal = None
        self.uids, self.size, self.uidvalidity = uids, size, uidvalidity

    def select(self, folder, readonly=False):
        self.commands.append(("select", folder, readonly))
        return "OK", [b"4"]

    def response(self, code):
        return code, [self.uidvalidity] if code == "UIDVALIDITY" else [None]

    def uid(self, *args):
        self.commands.append(("uid", *args, self.literal))
        self.literal = None
        if args[0] == "SEARCH":
            return "OK", [self.uids]
        uidset, items = args[1], args[2]
        out = []
        for i, uid in enumerate(uidset.split(","), 1):
            if items == "(UID FLAGS RFC822.SIZE)":
                out.append(f"{i} (UID {uid} FLAGS () RFC822.SIZE {self.size})".encode())
            else:
                raw = sample_email(f"msg {uid}")
                out += [(f"{i} (UID {uid} FLAGS () RFC822.SIZE {len(raw)} BODY[] {{{len(raw)}}}".encode(), raw),
                        b")"]
        return "OK", out


def fake_client(fake, **kw):
    obj = IMAPClient(Settings("example.org", 993, "me", "secret", **kw))

    @contextmanager
    def mock_connect():
        yield fake
    obj.connect = mock_connect
    return obj


READ_ONLY_COMMANDS = {"select", "SEARCH", "FETCH"}


def assert_read_only(fake):
    for cmd in fake.commands:
        assert cmd[1] in READ_ONLY_COMMANDS or cmd[0] == "select"
        if cmd[0] == "select":
            assert cmd[2] is True  # EXAMINE
        if cmd[1] == "FETCH":
            assert "BODY[" not in cmd[3]  # only BODY.PEEK[...]


def test_read_only_uid_search():
    fake = FakeConn()
    result = fake_client(fake).search("INBOX", "hello", limit=2)
    assert result["matching_count"] == 3
    assert [m["uid"] for m in result["messages"]] == [8, 3]
    assert result["messages"][0]["subject"] == "msg 8"
    assert result["uidvalidity"] == 42
    assert ("select", '"INBOX"', True) in fake.commands
    assert ("uid", "SEARCH", None, "TEXT", '"hello"', None) in fake.commands
    fetches = [c for c in fake.commands if c[1] == "FETCH"]
    assert len(fetches) == 1 and fetches[0][2] == "8,3" and "HEADER.FIELDS" in fetches[0][3]
    assert_read_only(fake)


def test_search_field_and_unicode_literal():
    fake = FakeConn()
    fake_client(fake).search("INBOX", "café", field="subject", unseen_only=True)
    assert ("uid", "SEARCH", "CHARSET", "UTF-8", "UNSEEN", "SUBJECT", "café".encode()) in fake.commands
    with pytest.raises(MailError):
        fake_client(FakeConn()).search("INBOX", "x", field="ALL")


def test_search_no_matches():
    fake = FakeConn(uids=b"")
    result = fake_client(fake).search("INBOX", "nothing")
    assert result["messages"] == [] and not any(c[1] == "FETCH" for c in fake.commands)


def test_recent_lists_newest_first():
    fake = FakeConn(uids=b"10 2 7")
    result = fake_client(fake).recent("Sent Items", limit=5)
    assert [m["uid"] for m in result["messages"]] == [10, 7, 2]
    assert ("select", '"Sent Items"', True) in fake.commands
    assert_read_only(fake)


def test_read_message():
    fake = FakeConn()
    result = fake_client(fake).read("INBOX", 8, uidvalidity=42)
    assert result["subject"] == "msg 8" and "Plain body" in result["body"] and result["seen"] is False
    assert_read_only(fake)


def test_read_rejects_oversize_before_download():
    fake = FakeConn(size=10_000)
    with pytest.raises(MailError, match="over the configured maximum"):
        fake_client(fake, max_message_bytes=1000).read("INBOX", 8)
    assert not any(c[1] == "FETCH" and "BODY" in c[3] for c in fake.commands)


def test_read_stale_uidvalidity():
    with pytest.raises(MailError, match="UIDVALIDITY"):
        fake_client(FakeConn()).read("INBOX", 8, uidvalidity=41)


def test_status():
    assert fake_client(FakeConn(uids=b"2 3")).status("INBOX") == {
        "folder": "INBOX", "total": 4, "unread": 2, "uidvalidity": 42}


class FakeIMAP:
    instances = []

    def __init__(self, *a, **kw):
        self.logged_out = False
        FakeIMAP.instances.append(self)

    def login(self, user, password):
        password.encode("ascii")  # mimics imaplib's ASCII command encoding
        if password != "good":
            raise imaplib.IMAP4.error("b'[AUTHENTICATIONFAILED] Authentication failed.'")

    def logout(self):
        self.logged_out = True


@pytest.mark.parametrize("password,match", [("wrong", "login failed"), ("pässwörd", "must be ASCII")])
def test_login_errors_do_not_leak_password(monkeypatch, password, match):
    monkeypatch.setattr(imap_client.imaplib, "IMAP4_SSL", FakeIMAP)
    with pytest.raises(MailError, match=match) as exc:
        with IMAPClient(Settings("h", 993, "u", password)).connect():
            pass
    assert password not in str(exc.value) and "ä" not in str(exc.value)
    assert exc.value.__cause__ is None and exc.value.__suppress_context__
    assert FakeIMAP.instances[-1].logged_out


def test_imap_errors_wrapped_and_connection_closed(monkeypatch):
    monkeypatch.setattr(imap_client.imaplib, "IMAP4_SSL", FakeIMAP)
    with pytest.raises(MailError, match="IMAP connection error"):
        with IMAPClient(Settings("h", 993, "u", "good")).connect():
            raise TimeoutError("timed out")
    assert FakeIMAP.instances[-1].logged_out
