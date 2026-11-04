"""IMAP operations. All mailbox access uses UID commands and read-only EXAMINE."""
from __future__ import annotations

import imaplib
import ssl
from contextlib import contextmanager
from dataclasses import dataclass
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from html import unescape
from html.parser import HTMLParser
from typing import Iterator


class MailError(RuntimeError):
    """Safe-to-display IMAP error (never contains secrets)."""


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    username: str
    password: str
    timeout: int = 20
    default_folder: str = "INBOX"
    max_results: int = 50
    max_body_chars: int = 20000
    max_message_bytes: int = 3_000_000

    def validate(self) -> None:
        if not self.host or not self.username or not self.password:
            raise MailError("IMAP_HOST, IMAP_USERNAME and IMAP_PASSWORD are required")
        if not (1 <= self.port <= 65535):
            raise MailError("Invalid IMAP_PORT")
        if self.max_results < 1 or self.max_body_chars < 1 or self.max_message_bytes < 1:
            raise MailError("Configured limits must be positive")


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        elif tag in ("p", "br", "div", "li", "tr"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(value: str) -> str:
    p = _TextExtractor()
    p.feed(value)
    return unescape("".join(p.parts)).strip()


def _header(value: object) -> str:
    try:
        return str(make_header(decode_header(str(value or ""))))
    except (UnicodeError, ValueError, LookupError):
        return str(value or "")


def _decode(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        content = part.get_payload()
        return content if isinstance(content, str) else ""
    try:
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _message_summary(raw: bytes, uid: int, body_limit: int, include_body: bool) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    out = {"uid": uid, "subject": _header(msg.get("Subject")),
           "from": _header(msg.get("From")), "to": _header(msg.get("To")),
           "date": str(msg.get("Date", "")), "message_id": str(msg.get("Message-ID", ""))}
    if include_body:
        plain, html, attachments = [], [], []
        for part in msg.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            if filename or part.get_content_disposition() == "attachment":
                attachments.append({"filename": _header(filename), "content_type": part.get_content_type(),
                                    "size_bytes": len(part.get_payload(decode=True) or b"")})
                continue
            if part.get_content_type() == "text/plain":
                plain.append(_decode(part))
            elif part.get_content_type() == "text/html":
                html.append(_decode(part))
        content = "\n".join(plain) if plain else html_to_text("\n".join(html))
        out.update(body=content[:body_limit], body_truncated=len(content) > body_limit,
                   attachments=attachments)
    return out


def _validate_folder(folder: str) -> str:
    if not folder or any(ch in folder for ch in "\r\n\x00") or len(folder) > 512:
        raise MailError("Invalid folder")
    return folder


def _validate_uid(uid: int) -> str:
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1:
        raise MailError("UID must be a positive integer")
    return str(uid)


def _parse_search_query(query: str) -> str:
    # IMAP SEARCH TEXT is quoted/escaped; never accept raw IMAP criteria from the model.
    if not isinstance(query, str) or not query.strip() or len(query) > 300 or any(c in query for c in "\r\n\x00"):
        raise MailError("Query must be 1-300 characters without control characters")
    return '"' + query.replace('\\', '\\\\').replace('"', '\\"') + '"'


class IMAPClient:
    def __init__(self, settings: Settings):
        settings.validate()
        self.settings = settings

    @contextmanager
    def connect(self) -> Iterator[imaplib.IMAP4_SSL]:
        try:
            conn = imaplib.IMAP4_SSL(self.settings.host, self.settings.port,
                                     ssl_context=ssl.create_default_context(), timeout=self.settings.timeout)
        except (OSError, imaplib.IMAP4.error):
            raise MailError("Unable to connect to IMAP server (verify host, port and TLS)") from None
        try:
            try:
                conn.login(self.settings.username, self.settings.password)
            except imaplib.IMAP4.error:
                raise MailError("IMAP login failed (check username/password)") from None
            yield conn
        finally:
            try:
                conn.logout()
            except (OSError, imaplib.IMAP4.error):
                pass

    def _select(self, conn, folder: str) -> int:
        try:
            status, data = conn.select(_validate_folder(folder), readonly=True)
        except (imaplib.IMAP4.error, OSError):
            raise MailError("Unable to open folder") from None
        if status != "OK":
            raise MailError("Unable to open folder")
        return int(data[0] or b"0")

    def folders(self) -> list[dict]:
        with self.connect() as conn:
            status, data = conn.list()
            if status != "OK":
                raise MailError("Unable to list folders")
            return [{"raw_imap_entry": line.decode("utf-8", "replace")}
                    for line in (data or []) if isinstance(line, bytes)]

    def status(self, folder: str) -> dict:
        with self.connect() as conn:
            total = self._select(conn, folder)
            status, data = conn.search(None, "UNSEEN")
            if status != "OK":
                raise MailError("Unable to count unread messages")
            return {"folder": folder, "total": total,
                    "unread": len((data[0] or b"").split())}

    def search(self, folder: str, query: str, limit: int = 20, unseen_only: bool = False) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise MailError("limit must be a positive integer")
        cap = min(limit, self.settings.max_results)
        criterion = _parse_search_query(query)
        with self.connect() as conn:
            self._select(conn, folder)
            criteria = ["UNSEEN"] if unseen_only else []
            criteria.extend(["TEXT", criterion])
            status, data = conn.uid("SEARCH", None, *criteria)
            if status != "OK":
                raise MailError("IMAP search failed")
            uids = [int(x) for x in (data[0] or b"").split()]
            selected = list(reversed(uids[-cap:]))
            messages = [self._fetch(conn, uid, include_body=False) for uid in selected]
            return {"folder": folder, "matching_count": len(uids), "returned_count": len(messages),
                    "messages": messages}

    def recent(self, folder: str, limit: int = 20, unseen_only: bool = False) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise MailError("limit must be a positive integer")
        cap = min(limit, self.settings.max_results)
        with self.connect() as conn:
            self._select(conn, folder)
            status, data = conn.uid("SEARCH", None, "UNSEEN" if unseen_only else "ALL")
            if status != "OK":
                raise MailError("IMAP listing failed")
            uids = [int(x) for x in (data[0] or b"").split()]
            selected = list(reversed(uids[-cap:]))
            return {"folder": folder, "matching_count": len(uids),
                    "messages": [self._fetch(conn, uid, include_body=False) for uid in selected]}

    def read(self, folder: str, uid: int) -> dict:
        _validate_uid(uid)
        with self.connect() as conn:
            self._select(conn, folder)
            return self._fetch(conn, uid, include_body=True)

    def _fetch(self, conn, uid: int, include_body: bool) -> dict:
        # BODY.PEEK does not set the Seen flag; EXAMINE is read-only as a second guard.
        status, data = conn.uid("FETCH", _validate_uid(uid), "(BODY.PEEK[])")
        if status != "OK" or not data:
            raise MailError("Message fetch failed")
        raw = next((item[1] for item in data if isinstance(item, tuple) and isinstance(item[1], bytes)), None)
        if raw is None:
            raise MailError("Message not found")
        if len(raw) > self.settings.max_message_bytes:
            raise MailError("Message exceeds configured maximum size")
        return _message_summary(raw, uid, self.settings.max_body_chars, include_body)
