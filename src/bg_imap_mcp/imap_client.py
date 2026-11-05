"""IMAP operations. All mailbox access uses UID commands and read-only EXAMINE."""
from __future__ import annotations

import base64
import imaplib
import re
import ssl
from contextlib import contextmanager
from dataclasses import dataclass
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
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
        if self.timeout < 1 or self.max_results < 1 or self.max_body_chars < 1 or self.max_message_bytes < 1:
            raise MailError("Configured timeout and limits must be positive")

    def __repr__(self) -> str:  # keep the password out of tracebacks and logs
        return f"Settings(host={self.host!r}, port={self.port}, username={self.username!r}, password='***')"


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
    # convert_charrefs already decodes entities; unescaping again would turn "&amp;lt;" into "<".
    p = _TextExtractor()
    p.feed(value)
    p.close()
    return "".join(p.parts).strip()


def _header(value: object) -> str:
    try:
        return str(make_header(decode_header(str(value or ""))))
    except (UnicodeError, ValueError, LookupError):
        return str(value or "")


def _get_header(msg, name: str) -> str:
    # Malformed headers can raise from the policy.default header parser.
    try:
        return _header(msg.get(name))
    except Exception:  # noqa: BLE001
        return ""


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
    msg = BytesParser(policy=policy.default).parsebytes(raw, headersonly=not include_body)
    out = {"uid": uid, "subject": _get_header(msg, "Subject"), "from": _get_header(msg, "From"),
           "to": _get_header(msg, "To"), "cc": _get_header(msg, "Cc"), "date": _get_header(msg, "Date"),
           "message_id": _get_header(msg, "Message-ID")}
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
        content, source = "\n".join(plain).strip(), "text/plain"
        if html and len(content) < 200:
            # Bulk mail often ships a stub text/plain part ("view in browser") next to the real HTML.
            html_text = html_to_text("\n".join(html))
            if len(html_text) > 2 * len(content):
                content, source = html_text, "text/html"
        out.update(body=content[:body_limit], body_truncated=len(content) > body_limit,
                   body_source=source if content else None, attachments=attachments)
    return out


# --- Mailbox names (RFC 3501 5.1.3 modified UTF-7) -------------------------------------------

def _utf7_encode(name: str) -> str:
    out, buf = [], []

    def flush():
        if buf:
            b64 = base64.b64encode("".join(buf).encode("utf-16-be")).decode("ascii")
            out.append("&" + b64.rstrip("=").replace("/", ",") + "-")
            buf.clear()

    for ch in name:
        if 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append("&-" if ch == "&" else ch)
        else:
            buf.append(ch)
    flush()
    return "".join(out)


def _utf7_decode(name: str) -> str:
    out, i = [], 0
    while i < len(name):
        if name[i] != "&":
            out.append(name[i])
            i += 1
            continue
        end = name.find("-", i)
        if end == -1:
            out.append(name[i:])
            break
        if end == i + 1:
            out.append("&")
        else:
            b64 = name[i + 1:end].replace(",", "/")
            try:
                out.append(base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-16-be"))
            except (ValueError, UnicodeDecodeError):
                out.append(name[i:end + 1])
        i = end + 1
    return "".join(out)


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value


def _validate_folder(folder: str) -> str:
    """Return the folder as a quoted, modified-UTF-7 IMAP mailbox argument."""
    if (not isinstance(folder, str) or not folder or len(folder) > 512
            or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in folder)):
        raise MailError("Invalid folder")
    return _quote(_utf7_encode(folder))


_LIST_RE = re.compile(r'^\((?P<flags>[^)]*)\) (?P<delim>"(?:[^"\\]|\\.)*"|NIL) ?(?P<name>.*)$', re.S)


def _parse_list(data) -> list[dict]:
    folders = []
    for item in data or []:
        if isinstance(item, tuple):  # mailbox name sent as a literal
            line = item[0].decode("utf-8", "replace")
            line = re.sub(r"\{\d+\}$", "", line) + _quote(item[1].decode("utf-8", "replace"))
        elif isinstance(item, bytes):
            line = item.decode("utf-8", "replace")
        else:
            continue
        m = _LIST_RE.match(line)
        if not m:
            continue
        delim = None if m["delim"] == "NIL" else _unquote(m["delim"])
        folders.append({"name": _utf7_decode(_unquote(m["name"].strip())), "delimiter": delim,
                        "flags": m["flags"].split()})
    return folders


# --- Search / UID helpers --------------------------------------------------------------------

SEARCH_FIELDS = {"text": "TEXT", "subject": "SUBJECT", "from": "FROM", "to": "TO", "body": "BODY"}


def _parse_search_query(query: str) -> str:
    # IMAP SEARCH strings are quoted/escaped; never accept raw IMAP criteria from the model.
    if (not isinstance(query, str) or not query.strip() or len(query) > 300
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in query)):
        raise MailError("Query must be 1-300 characters without control characters")
    return _quote(query)


def _validate_uid(uid: int) -> str:
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1 or uid > 0xFFFFFFFF:
        raise MailError("UID must be a positive 32-bit integer")
    return str(uid)


def _validate_limit(limit: int, cap: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise MailError("limit must be a positive integer")
    return min(limit, cap)


_NEW_FETCH_RE = re.compile(rb"^\d+ \(")


def _fetch_records(data) -> dict[int, dict]:
    """Group an imaplib FETCH response by UID: {uid: {"flags", "size", "literal"}}."""
    chunks: list[list] = []
    for item in data or []:
        if isinstance(item, tuple):
            chunks.append([item[0], item[1]])
        elif isinstance(item, bytes) and chunks and not _NEW_FETCH_RE.match(item):
            chunks[-1][0] += b" " + item  # trailing attributes after a literal, e.g. b' FLAGS (\\Seen))'
        elif isinstance(item, bytes):
            chunks.append([item, None])
    records = {}
    for meta, literal in chunks:
        uid = re.search(rb"UID (\d+)", meta)
        if not uid:
            continue  # unsolicited FETCH (e.g. a flag change) without UID
        flags = re.search(rb"FLAGS \(([^)]*)\)", meta)
        size = re.search(rb"RFC822\.SIZE (\d+)", meta)
        # Merge rather than overwrite: an unsolicited FETCH for the same UID may carry only FLAGS.
        rec = records.setdefault(int(uid[1]), {"flags": None, "size": None, "literal": None})
        if flags:
            rec["flags"] = flags[1].decode("ascii", "replace").split()
        if size:
            rec["size"] = int(size[1])
        if literal is not None:
            rec["literal"] = literal
    return records


_HEADER_ITEMS = "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO CC DATE MESSAGE-ID)])"


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
            except UnicodeError:
                # imaplib's default ASCII encoding error would echo the offending password character.
                raise MailError("IMAP login failed (username/password must be ASCII)") from None
            except (OSError, imaplib.IMAP4.error):
                raise MailError("IMAP login failed (check username/password)") from None
            try:
                yield conn
            except imaplib.IMAP4.error as exc:
                raise MailError(f"IMAP error: {str(exc)[:200]}") from None
            except OSError as exc:
                raise MailError(f"IMAP connection error ({type(exc).__name__})") from None
        finally:
            try:
                conn.logout()  # imaplib always closes the socket, even if LOGOUT fails
            except Exception:  # noqa: BLE001
                pass

    def _select(self, conn, folder: str) -> dict:
        """EXAMINE (read-only SELECT) a folder; return message count and UIDVALIDITY."""
        mailbox = _validate_folder(folder)
        try:
            status, data = conn.select(mailbox, readonly=True)
        except (imaplib.IMAP4.error, OSError):
            raise MailError("Unable to open folder") from None
        if status != "OK":
            raise MailError("Unable to open folder")
        _, validity = conn.response("UIDVALIDITY")
        try:
            uidvalidity = int(validity[0]) if validity and validity[0] else None
        except (TypeError, ValueError):
            uidvalidity = None
        return {"total": int(data[0] or b"0"), "uidvalidity": uidvalidity}

    def folders(self) -> list[dict]:
        with self.connect() as conn:
            status, data = conn.list()
            if status != "OK":
                raise MailError("Unable to list folders")
            return _parse_list(data)

    def status(self, folder: str) -> dict:
        with self.connect() as conn:
            info = self._select(conn, folder)
            status, data = conn.uid("SEARCH", None, "UNSEEN")
            if status != "OK":
                raise MailError("Unable to count unread messages")
            return {"folder": folder, "total": info["total"], "unread": len((data[0] or b"").split()),
                    "uidvalidity": info["uidvalidity"]}

    def search(self, folder: str, query: str, limit: int = 20, unseen_only: bool = False,
               field: str = "text") -> dict:
        cap = _validate_limit(limit, self.settings.max_results)
        key = SEARCH_FIELDS.get(field)
        if key is None:
            raise MailError(f"field must be one of: {', '.join(SEARCH_FIELDS)}")
        criterion = _parse_search_query(query)
        with self.connect() as conn:
            info = self._select(conn, folder)
            criteria = ["UNSEEN"] if unseen_only else []
            if query.isascii():
                status, data = conn.uid("SEARCH", None, *criteria, key, criterion)
            else:
                # Non-ASCII text must be sent as a UTF-8 literal; imaplib appends "{n}" to the command.
                conn.literal = query.encode("utf-8")
                status, data = conn.uid("SEARCH", "CHARSET", "UTF-8", *criteria, key)
            if status != "OK":
                raise MailError("IMAP search failed")
            uids = sorted(int(x) for x in (data[0] or b"").split())
            messages = self._headers(conn, list(reversed(uids[-cap:])))
            return {"folder": folder, "uidvalidity": info["uidvalidity"], "matching_count": len(uids),
                    "returned_count": len(messages), "messages": messages}

    def recent(self, folder: str, limit: int = 20, unseen_only: bool = False) -> dict:
        cap = _validate_limit(limit, self.settings.max_results)
        with self.connect() as conn:
            info = self._select(conn, folder)
            status, data = conn.uid("SEARCH", None, "UNSEEN" if unseen_only else "ALL")
            if status != "OK":
                raise MailError("IMAP listing failed")
            uids = sorted(int(x) for x in (data[0] or b"").split())
            messages = self._headers(conn, list(reversed(uids[-cap:])))
            return {"folder": folder, "uidvalidity": info["uidvalidity"], "matching_count": len(uids),
                    "returned_count": len(messages), "messages": messages}

    def read(self, folder: str, uid: int, uidvalidity: int | None = None) -> dict:
        uid_arg = _validate_uid(uid)
        with self.connect() as conn:
            info = self._select(conn, folder)
            if uidvalidity is not None and info["uidvalidity"] is not None and uidvalidity != info["uidvalidity"]:
                raise MailError("Folder UIDVALIDITY changed; list or search again to get current UIDs")
            # Check the size before downloading anything so IMAP_MAX_MESSAGE_BYTES bounds bandwidth too.
            status, data = conn.uid("FETCH", uid_arg, "(UID FLAGS RFC822.SIZE)")
            meta = _fetch_records(data).get(uid) if status == "OK" else None
            if meta is None:
                raise MailError("Message not found")
            if meta["size"] is not None and meta["size"] > self.settings.max_message_bytes:
                raise MailError(f"Message is {meta['size']} bytes, over the configured maximum "
                                f"({self.settings.max_message_bytes})")
            # BODY.PEEK does not set \Seen; EXAMINE is read-only as a second guard.
            status, data = conn.uid("FETCH", uid_arg, "(UID BODY.PEEK[])")
            record = _fetch_records(data).get(uid) if status == "OK" else None
            if record is None or record["literal"] is None:
                raise MailError("Message not found")
            if len(record["literal"]) > self.settings.max_message_bytes:
                raise MailError("Message exceeds configured maximum size")
            out = _message_summary(record["literal"], uid, self.settings.max_body_chars, True)
            out.update(folder=folder, uidvalidity=info["uidvalidity"], size_bytes=meta["size"],
                       seen="\\Seen" in (meta["flags"] or []))
            return out

    def _headers(self, conn, uids: list[int]) -> list[dict]:
        """Fetch only header fields, flags and size for the UIDs (one round trip), newest first."""
        if not uids:
            return []
        status, data = conn.uid("FETCH", ",".join(_validate_uid(u) for u in uids), _HEADER_ITEMS)
        if status != "OK":
            raise MailError("Message fetch failed")
        records = _fetch_records(data)
        out = []
        for uid in uids:
            rec = records.get(uid)
            if rec is None or rec["literal"] is None:
                continue  # expunged between SEARCH and FETCH
            summary = _message_summary(rec["literal"], uid, self.settings.max_body_chars, False)
            summary.update(size_bytes=rec["size"], seen="\\Seen" in (rec["flags"] or []))
            out.append(summary)
        return out
