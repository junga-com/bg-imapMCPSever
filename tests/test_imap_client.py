from email.message import EmailMessage
import pytest
from bg_imap_mcp.imap_client import (Settings, MailError, _message_summary, _parse_search_query,
                                     _validate_uid, html_to_text, IMAPClient)


def sample_email():
    msg = EmailMessage()
    msg["Subject"] = "Test message"
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


def test_html_fallback():
    msg = EmailMessage()
    msg.set_content("<p>Hello <b>world</b></p><script>ignore me</script>", subtype="html")
    result = _message_summary(msg.as_bytes(), 1, 200, True)
    assert "Hello world" in result["body"]
    assert "ignore me" not in result["body"]


def test_search_escaping():
    assert _parse_search_query('hello "there"') == '"hello \\"there\\""'
    with pytest.raises(MailError):
        _parse_search_query("hello\r\nBAD")


def test_uid_validation():
    for invalid in (0, -1, True, "3"):
        with pytest.raises(MailError):
            _validate_uid(invalid)


def test_missing_configuration():
    with pytest.raises(MailError):
        Settings(host="", port=993, username="a", password="b").validate()


class FakeConn:
    def __init__(self):
        self.commands = []
    def select(self, folder, readonly=False):
        self.commands.append(("select", folder, readonly))
        return "OK", [b"4"]
    def uid(self, *args):
        self.commands.append(("uid", *args))
        if args[0] == "SEARCH":
            return "OK", [b"1 3 8"]
        return "OK", [(b"8 (BODY[] {123}", sample_email()), b")"]
    def search(self, *args):
        return "OK", [b"2 3"]


def test_read_only_uid_search(monkeypatch):
    from contextlib import contextmanager
    obj = IMAPClient(Settings("example.org", 993, "me", "secret"))
    fake = FakeConn()
    @contextmanager
    def mock_connect():
        yield fake
    monkeypatch.setattr(obj, "connect", mock_connect)
    result = obj.search("INBOX", "hello", limit=2)
    assert result["matching_count"] == 3
    assert len(result["messages"]) == 2
    assert ("select", "INBOX", True) in fake.commands
    assert any(c[0] == "uid" and c[1] == "FETCH" and c[3] == "(BODY.PEEK[])" for c in fake.commands)


def test_status(monkeypatch):
    from contextlib import contextmanager
    obj = IMAPClient(Settings("example.org", 993, "me", "secret"))
    @contextmanager
    def mock_connect():
        yield FakeConn()
    monkeypatch.setattr(obj, "connect", mock_connect)
    assert obj.status("INBOX") == {"folder": "INBOX", "total": 4, "unread": 2}
