"""IMAP operations. All mailbox access uses UID commands and read-only EXAMINE.

Nothing here issues STORE, COPY, MOVE, EXPUNGE, APPEND, DELETE or any other mailbox-modifying
command, and message content is only ever fetched with BODY.PEEK so the \\Seen flag is never set.
"""
from __future__ import annotations

import base64
import imaplib
import re
import ssl
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Iterator

# Stable error codes (prefix of every MailError message).
AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
CONFIG_ERROR = "CONFIG_ERROR"
CURSOR_EXPIRED = "CURSOR_EXPIRED"
FOLDER_NOT_FOUND = "FOLDER_NOT_FOUND"
IMAP_CONNECTION_ERROR = "IMAP_CONNECTION_ERROR"
IMAP_ERROR = "IMAP_ERROR"
IMAP_TIMEOUT = "IMAP_TIMEOUT"
INVALID_ARGUMENT = "INVALID_ARGUMENT"
INVALID_CURSOR = "INVALID_CURSOR"
MESSAGE_NOT_FOUND = "MESSAGE_NOT_FOUND"
MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"
UIDVALIDITY_CHANGED = "UIDVALIDITY_CHANGED"
UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"


class MailError(RuntimeError):
    """Safe-to-display IMAP error (never contains secrets or message content). str() is 'CODE: detail'."""

    def __init__(self, detail: str, code: str = IMAP_ERROR):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


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
    max_page_size: int = 500
    max_batch: int = 100
    batch_output_chars: int = 150_000
    ca_file: str | None = None

    def validate(self) -> None:
        if not self.host or not self.username or not self.password:
            raise MailError("IMAP_HOST, IMAP_USERNAME and IMAP_PASSWORD are required", CONFIG_ERROR)
        if not (1 <= self.port <= 65535):
            raise MailError("Invalid IMAP_PORT", CONFIG_ERROR)
        if min(self.timeout, self.max_results, self.max_body_chars, self.max_message_bytes, self.max_page_size,
               self.max_batch, self.batch_output_chars) < 1:
            raise MailError("Configured timeout and limits must be positive", CONFIG_ERROR)

    def __repr__(self) -> str:  # keep the password out of tracebacks and logs
        return f"Settings(host={self.host!r}, port={self.port}, username={self.username!r}, password='***')"


# --- HTML to text ------------------------------------------------------------------------------

class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "title", "noscript", "template"}
    BLOCK = {"p", "div", "br", "tr", "li", "table", "ul", "ol", "blockquote", "section", "article", "header",
             "footer", "hr", "h1", "h2", "h3", "h4", "h5", "h6", "pre"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0
        self.links: list[tuple[str | None, int]] = []

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
            return
        if tag in self.BLOCK:
            self.parts.append("\n")
        if tag == "li":
            self.parts.append("- ")
        if tag == "a":
            self.links.append((dict(attrs).get("href"), len(self.parts)))

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self.skip = max(0, self.skip - 1)
            return
        if tag == "a" and self.links:
            href, start = self.links.pop()
            text = "".join(self.parts[start:]).strip()
            # Keep link targets (as text only; nothing is fetched). Very long tracking URLs are dropped.
            if (href and href.startswith(("http://", "https://", "mailto:")) and len(href) <= 500
                    and href not in text and not self.skip):
                self.parts.append(f" ({href})")
        if tag in self.BLOCK and tag not in ("br", "li", "hr"):
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(value: str) -> str:
    # convert_charrefs already decodes entities; unescaping again would turn "&amp;lt;" into "<".
    p = _TextExtractor()
    p.feed(value)
    p.close()
    lines = [re.sub(r"[ \t\r\f\v\xa0]+", " ", line).strip() for line in "".join(p.parts).split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


# --- Header and MIME helpers -------------------------------------------------------------------

def _clean(text: str) -> str:
    """Replace lone surrogates (from undeclared 8-bit header bytes) so results stay valid JSON."""
    if any("\udc80" <= ch <= "\udcff" for ch in text):
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return text


def _header(value: object) -> str:
    try:
        return _clean(str(make_header(decode_header(str(value or "")))))
    except (UnicodeError, ValueError, LookupError):
        return _clean(str(value or ""))


def _get_header(msg, name: str) -> str:
    # Malformed headers can raise from the policy.default header parser.
    try:
        return _header(msg.get(name))
    except Exception:  # noqa: BLE001
        return ""


def _addresses(msg, name: str) -> list[dict]:
    """[{'name', 'address'}] for an address header; tolerant of malformed input."""
    try:
        hdr = msg.get(name)
        if hdr is None:
            return []
        if hasattr(hdr, "addresses"):
            return [{"name": _clean(a.display_name) or None, "address": _clean(a.addr_spec)}
                    for a in hdr.addresses if a.addr_spec]
    except Exception:  # noqa: BLE001
        pass
    return [{"name": n or None, "address": a} for n, a in getaddresses([_get_header(msg, name)]) if a]


def _msg_ids(value: str) -> list[str]:
    return re.findall(r"<[^<>\s]+>", value or "")


def _iso_header_date(value: str) -> str | None:
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if dt.tzinfo is None:
        return dt.isoformat()
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _iso_internaldate(value: str | None) -> str | None:
    if not value:
        return None
    try:
        dt = datetime.strptime(value.strip(), "%d-%b-%Y %H:%M:%S %z")
    except ValueError:
        return value
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _decode(part) -> str:
    """Decoded text of a MIME part with line endings normalized to \n (IMAP delivers CRLF)."""
    payload = part.get_payload(decode=True)
    if payload is None:
        content = part.get_payload()
        text = content if isinstance(content, str) else ""
    else:
        try:
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            text = payload.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _message_summary(raw: bytes, uid: int, body_limit: int, include_body: bool, body_offset: int = 0) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw, headersonly=not include_body)
    sender = _addresses(msg, "From")
    out = {"uid": uid, "subject": _get_header(msg, "Subject"), "from": _get_header(msg, "From"),
           "to": _get_header(msg, "To"), "cc": _get_header(msg, "Cc"), "date": _get_header(msg, "Date"),
           "message_id": _get_header(msg, "Message-ID"),
           # Structured additions (backward compatible)
           "from_address": sender[0]["address"] if sender else None,
           "from_name": sender[0]["name"] if sender else None,
           "to_addresses": [a["address"] for a in _addresses(msg, "To")],
           "cc_addresses": [a["address"] for a in _addresses(msg, "Cc")],
           "reply_to": [a["address"] for a in _addresses(msg, "Reply-To")],
           "date_iso": _iso_header_date(_get_header(msg, "Date")),
           "in_reply_to": (_msg_ids(_get_header(msg, "In-Reply-To")) or [None])[0],
           "references": _msg_ids(_get_header(msg, "References")),
           "list_id": _get_header(msg, "List-ID") or None,
           "auto_submitted": _get_header(msg, "Auto-Submitted") or None,
           "precedence": _get_header(msg, "Precedence") or None}
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
        end = body_offset + body_limit
        out.update(body=content[body_offset:end], body_truncated=len(content) > end,
                   body_source=source if content else None, body_format="text", body_offset=body_offset,
                   body_total_chars=len(content), next_body_offset=end if len(content) > end else None,
                   attachments=attachments, has_attachments=bool(attachments))
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
        raise MailError("Invalid folder", INVALID_ARGUMENT)
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


# --- Search helpers --------------------------------------------------------------------------

SEARCH_FIELDS = {"text": "TEXT", "subject": "SUBJECT", "from": "FROM", "to": "TO", "body": "BODY"}
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _check_text(value: str, name: str) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > 300
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)):
        raise MailError(f"{name} must be 1-300 characters without control characters", INVALID_ARGUMENT)
    return value


def _parse_search_query(query: str) -> str:
    # IMAP SEARCH strings are quoted/escaped; never accept raw IMAP criteria from the model.
    _check_text(query, "Query")
    return _quote(query)


def _imap_date(value: str, name: str) -> str:
    try:
        d = date.fromisoformat(value)
    except (TypeError, ValueError):
        raise MailError(f"{name} must be YYYY-MM-DD", INVALID_ARGUMENT) from None
    return f"{d.day}-{_MONTHS[d.month - 1]}-{d.year}"  # locale-independent IMAP date


def build_search_criteria(conn, filters: dict, uid_range: str | None = None) -> list:
    """Translate structured filters into IMAP SEARCH arguments. Strings are always quoted or sent
    as literals, never spliced in raw, so callers cannot inject IMAP syntax."""
    args: list = []
    needs_utf8 = False

    def astring(value: str, name: str):
        nonlocal needs_utf8
        _check_text(value, name)
        if value.isascii():
            return _quote(value)
        caps = getattr(conn, "capabilities", ()) or ()
        if "LITERAL+" not in caps and "LITERAL-" not in caps:
            raise MailError("Non-ASCII search text needs a server with LITERAL+", UNSUPPORTED_OPERATION)
        needs_utf8 = True
        data = value.encode("utf-8")
        return b"{%d+}\r\n" % len(data) + data  # non-synchronizing literal (RFC 7888)

    df, dt = filters.get("date_from"), filters.get("date_to")
    if df:
        args += ["SINCE", _imap_date(df, "date_from")]
    if dt:
        args += ["BEFORE", _imap_date(dt, "date_to")]
    if df and dt and date.fromisoformat(df) >= date.fromisoformat(dt):
        raise MailError("date_from must be before date_to (date_to is exclusive)", INVALID_ARGUMENT)
    if filters.get("sender") is not None:
        args += ["FROM", astring(filters["sender"], "sender")]
    if filters.get("recipient") is not None:
        r = filters["recipient"]
        args += ["OR", "TO", astring(r, "recipient"), "CC", astring(r, "recipient")]
    if filters.get("subject") is not None:
        args += ["SUBJECT", astring(filters["subject"], "subject")]
    if filters.get("text") is not None:
        args += ["TEXT", astring(filters["text"], "text")]
    if filters.get("seen") is True:
        args.append("SEEN")
    elif filters.get("seen") is False:
        args.append("UNSEEN")
    for key, op, delta in (("min_size", "LARGER", -1), ("max_size", "SMALLER", 1)):
        v = filters.get(key)
        if v is not None:
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise MailError(f"{key} must be a non-negative integer", INVALID_ARGUMENT)
            if op == "LARGER" and v == 0:
                continue
            args += [op, str(v + delta)]
    if uid_range:
        args += ["UID", uid_range]
    if not args:
        args.append("ALL")
    return (["CHARSET", "UTF-8"] if needs_utf8 else [None]) + args


def _validate_uid(uid: int) -> str:
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1 or uid > 0xFFFFFFFF:
        raise MailError("UID must be a positive 32-bit integer", INVALID_ARGUMENT)
    return str(uid)


def _validate_uids(uids: list[int], cap: int) -> list[int]:
    if not isinstance(uids, list) or not uids:
        raise MailError("uids must be a non-empty list", INVALID_ARGUMENT)
    if len(uids) > cap:
        raise MailError(f"at most {cap} uids per call", INVALID_ARGUMENT)
    for u in uids:
        _validate_uid(u)
    return list(dict.fromkeys(uids))


def _validate_limit(limit: int, cap: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise MailError("limit must be a positive integer", INVALID_ARGUMENT)
    return min(limit, cap)


# --- FETCH response parsing --------------------------------------------------------------------

@dataclass
class FetchRecord:
    uid: int
    flags: list[str] | None = None
    size: int | None = None
    internaldate: str | None = None
    bodystructure: bytes = b""
    sections: dict[str, bytes] = field(default_factory=dict)

    def section(self, prefix: str) -> bytes | None:
        """First body section whose name starts with prefix, e.g. 'BODY[]' or 'BODY[HEADER'."""
        for name, value in self.sections.items():
            if name == prefix or (prefix.endswith("[HEADER") and name.startswith(prefix)):
                return value
        return None

    @property
    def literal(self) -> bytes | None:
        return next(iter(self.sections.values()), None)


_NEW_FETCH_RE = re.compile(rb"^\d+ \(")
_SECTION_RE = re.compile(rb"(BODY\[[^\]]*\](?:<\d+>)?) \{\d+\}$")


def _parse_fetch(data) -> dict[int, FetchRecord]:
    """Parse an imaplib FETCH response into records keyed by UID.

    imaplib splits a response at each literal: [(prefix + '{n}', literal), ..., b')']. Body sections are
    keyed by name; any other literal (e.g. a filename inside BODYSTRUCTURE) is inlined as a string."""
    responses: list[list] = []
    for item in data or []:
        if isinstance(item, tuple):
            head, literal = item[0], item[1]
            if _NEW_FETCH_RE.match(head) or not responses:
                responses.append([b"", {}])
            m = _SECTION_RE.search(head)
            if m:
                responses[-1][0] += head[:m.start()]
                responses[-1][1][m[1].decode("ascii", "replace").upper()] = literal
            else:
                inlined = literal.replace(b"\\", b"\\\\").replace(b'"', b'\\"')
                responses[-1][0] += re.sub(rb"\{\d+\}$", b"", head) + b'"' + inlined + b'"'
        elif isinstance(item, bytes):
            if _NEW_FETCH_RE.match(item) or not responses:
                responses.append([item, {}])
            else:
                responses[-1][0] += b" " + item  # trailing attributes after a literal, e.g. b' FLAGS (\\Seen))'
    records: dict[int, FetchRecord] = {}
    for meta, sections in responses:
        uid = re.search(rb"UID (\d+)", meta)
        if not uid:
            continue  # unsolicited FETCH (e.g. a flag change) without UID
        # Merge rather than overwrite: an unsolicited FETCH for the same UID may carry only FLAGS.
        rec = records.setdefault(int(uid[1]), FetchRecord(int(uid[1])))
        if flags := re.search(rb"FLAGS \(([^)]*)\)", meta):
            rec.flags = flags[1].decode("ascii", "replace").split()
        if size := re.search(rb"RFC822\.SIZE (\d+)", meta):
            rec.size = int(size[1])
        if idate := re.search(rb'INTERNALDATE "([^"]+)"', meta):
            rec.internaldate = idate[1].decode("ascii", "replace")
        if (pos := meta.find(b"BODYSTRUCTURE ")) >= 0:
            rec.bodystructure = meta[pos:]
        rec.sections.update(sections)
    return records


def _fetch_records(data) -> dict[int, dict]:
    """Backward-compatible view of _parse_fetch: {uid: {"flags", "size", "literal"}}."""
    return {uid: {"flags": r.flags, "size": r.size, "literal": r.literal} for uid, r in _parse_fetch(data).items()}


_SIGNATURE_TYPES = rb"(?:pkcs7-signature|x-pkcs7-signature|pgp-signature)"


def _bodystructure_has_attachments(bs: bytes) -> bool | None:
    """Derived from BODYSTRUCTURE without downloading the message: a part with an 'attachment'
    disposition or an application/* part (signatures excluded)."""
    if not bs:
        return None
    return bool(re.search(rb'\("attachment"', bs, re.I)
                or re.search(rb'\("application" "(?!' + _SIGNATURE_TYPES + rb')', bs, re.I))


def _flag_fields(flags: list[str] | None) -> dict:
    f = set(flags or [])
    return {"seen": "\\Seen" in f, "answered": "\\Answered" in f, "flagged": "\\Flagged" in f,
            "draft": "\\Draft" in f}


_LISTING_FIELDS = ("FROM TO CC REPLY-TO SUBJECT DATE MESSAGE-ID IN-REPLY-TO LIST-ID AUTO-SUBMITTED PRECEDENCE")
_LISTING_ITEMS = f"(UID FLAGS RFC822.SIZE INTERNALDATE BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS ({_LISTING_FIELDS})])"
_HEADER_ITEMS = ("(UID FLAGS RFC822.SIZE "
                 "BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO CC DATE MESSAGE-ID REPLY-TO IN-REPLY-TO REFERENCES "
                 "LIST-ID AUTO-SUBMITTED PRECEDENCE)])")
DEFAULT_HEADERS = ["Message-ID", "In-Reply-To", "References", "List-ID", "List-Unsubscribe", "List-Post",
                   "Auto-Submitted", "Precedence", "Delivered-To", "X-Original-To", "Authentication-Results"]
FETCH_CHUNK = 100


def _listing_record(rec: FetchRecord) -> dict:
    """Compact metadata row. Everything comes from headers/flags/BODYSTRUCTURE, never the body."""
    s = _message_summary(rec.section("BODY[HEADER") or b"", rec.uid, 1, False)
    return {"uid": rec.uid, "message_id": s["message_id"] or None, "date": s["date_iso"] or (s["date"] or None),
            "internal_date": _iso_internaldate(rec.internaldate), "from": s["from_address"],
            "from_name": s["from_name"], "to": s["to_addresses"], "cc": s["cc_addresses"],
            "subject": s["subject"], "size_bytes": rec.size, **_flag_fields(rec.flags),
            "has_attachments": _bodystructure_has_attachments(rec.bodystructure),
            "list_id": s["list_id"], "in_reply_to": s["in_reply_to"],
            "auto_submitted": s["auto_submitted"], "precedence": s["precedence"]}


def _header_map(raw: bytes, names: list[str] | None) -> dict[str, list[str]]:
    msg = BytesParser(policy=policy.compat32).parsebytes(raw, headersonly=True)
    wanted = None if names is None else {n.lower() for n in names}
    out: dict[str, list[str]] = {}
    for key, value in msg.items():
        if wanted is not None and key.lower() not in wanted:
            continue
        values = out.setdefault(key, [])
        if len(values) < 50:
            values.append(_header(value)[:4000])
    return out


def _normalized_headers(headers: dict[str, list[str]]) -> dict:
    get = {k.lower(): v for k, v in headers.items()}

    def first(name):
        return (get.get(name) or [None])[0]
    list_id = first("list-id")
    return {
        "message_id": (_msg_ids(first("message-id") or "") or [None])[0],
        "in_reply_to": _msg_ids(" ".join(get.get("in-reply-to", []))),
        "references": _msg_ids(" ".join(get.get("references", []))),
        "list_id": (re.findall(r"<([^<>]+)>", list_id or "") or [list_id.strip() if list_id else None])[0],
        "list_unsubscribe": re.findall(r"<([^<>]+)>", " ".join(get.get("list-unsubscribe", []))),
        "auto_submitted": first("auto-submitted"),
        "precedence": (first("precedence") or "").strip().lower() or None,
        "delivered_to": [v.strip() for v in get.get("delivered-to", [])],
        "x_original_to": [v.strip() for v in get.get("x-original-to", [])],
    }


# --- Client ------------------------------------------------------------------------------------

class IMAPClient:
    CONNECT_ATTEMPTS = 3

    def __init__(self, settings: Settings):
        settings.validate()
        self.settings = settings

    def _ssl_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=self.settings.ca_file)

    @contextmanager
    def connect(self) -> Iterator[imaplib.IMAP4_SSL]:
        conn = None
        for attempt in range(self.CONNECT_ATTEMPTS):  # bounded retry for transient network failures
            try:
                conn = imaplib.IMAP4_SSL(self.settings.host, self.settings.port, ssl_context=self._ssl_context(),
                                         timeout=self.settings.timeout)
                break
            except ssl.SSLCertVerificationError:
                raise MailError("TLS certificate verification failed", IMAP_CONNECTION_ERROR) from None
            except (OSError, imaplib.IMAP4.error) as exc:
                if attempt + 1 == self.CONNECT_ATTEMPTS:
                    if isinstance(exc, TimeoutError):
                        raise MailError("Timed out connecting to the IMAP server", IMAP_TIMEOUT) from None
                    raise MailError("Unable to connect to IMAP server (verify host, port and TLS)",
                                    IMAP_CONNECTION_ERROR) from None
                time.sleep(0.5 * 3 ** attempt)
        try:
            try:
                conn.login(self.settings.username, self.settings.password)
            except UnicodeError:
                # imaplib's default ASCII encoding error would echo the offending password character.
                raise MailError("IMAP login failed (username/password must be ASCII)", AUTHENTICATION_FAILED) from None
            except imaplib.IMAP4.error:
                raise MailError("IMAP login failed (check username/password)", AUTHENTICATION_FAILED) from None
            except OSError:
                raise MailError("Connection lost during IMAP login", IMAP_CONNECTION_ERROR) from None
            try:
                yield conn
            except imaplib.IMAP4.error as exc:
                raise MailError(f"IMAP error: {str(exc)[:200]}", IMAP_ERROR) from None
            except TimeoutError:
                raise MailError("IMAP server did not respond in time", IMAP_TIMEOUT) from None
            except OSError as exc:
                raise MailError(f"IMAP connection error ({type(exc).__name__})", IMAP_CONNECTION_ERROR) from None
        finally:
            try:
                conn.logout()  # imaplib always closes the socket, even if LOGOUT fails
            except Exception:  # noqa: BLE001
                pass

    def _select(self, conn, folder: str) -> dict:
        """EXAMINE (read-only SELECT) a folder; return message count, UIDVALIDITY and UIDNEXT."""
        mailbox = _validate_folder(folder)
        try:
            status, data = conn.select(mailbox, readonly=True)
        except (imaplib.IMAP4.error, OSError):
            raise MailError("Unable to open folder", FOLDER_NOT_FOUND) from None
        if status != "OK":
            raise MailError("Unable to open folder", FOLDER_NOT_FOUND)

        def code(name):
            _, val = conn.response(name)
            try:
                return int(val[0]) if val and val[0] else None
            except (TypeError, ValueError):
                return None
        return {"total": int(data[0] or b"0"), "uidvalidity": code("UIDVALIDITY"), "uidnext": code("UIDNEXT")}

    @staticmethod
    def _check_uidvalidity(info: dict, expected: int | None) -> None:
        if expected is not None and info["uidvalidity"] is not None and expected != info["uidvalidity"]:
            raise MailError("Folder UIDVALIDITY changed; list or search again to get current UIDs",
                            UIDVALIDITY_CHANGED)

    def _uid_search(self, conn, *args) -> list[int]:
        status, data = conn.uid("SEARCH", *args)
        if status != "OK":
            raise MailError("IMAP search failed", IMAP_ERROR)
        return sorted(int(x) for x in b" ".join(d for d in data if isinstance(d, bytes)).split())

    def _fetch(self, conn, uids: list[int], items: str) -> dict[int, FetchRecord]:
        records: dict[int, FetchRecord] = {}
        for i in range(0, len(uids), FETCH_CHUNK):
            chunk = uids[i:i + FETCH_CHUNK]
            status, data = conn.uid("FETCH", ",".join(_validate_uid(u) for u in chunk), items)
            if status != "OK":
                raise MailError("Message fetch failed", IMAP_ERROR)
            wanted = set(chunk)
            records.update({u: r for u, r in _parse_fetch(data).items() if u in wanted})
        return records

    # Original tools ---------------------------------------------------------------------------

    def folders(self) -> list[dict]:
        with self.connect() as conn:
            status, data = conn.list()
            if status != "OK":
                raise MailError("Unable to list folders", IMAP_ERROR)
            return _parse_list(data)

    def status(self, folder: str) -> dict:
        with self.connect() as conn:
            info = self._select(conn, folder)
            status, data = conn.uid("SEARCH", None, "UNSEEN")
            if status != "OK":
                raise MailError("Unable to count unread messages", IMAP_ERROR)
            return {"folder": folder, "total": info["total"], "unread": len((data[0] or b"").split()),
                    "uidvalidity": info["uidvalidity"]}

    def search(self, folder: str, query: str, limit: int = 20, unseen_only: bool = False,
               field: str = "text") -> dict:
        cap = _validate_limit(limit, self.settings.max_results)
        key = SEARCH_FIELDS.get(field)
        if key is None:
            raise MailError(f"field must be one of: {', '.join(SEARCH_FIELDS)}", INVALID_ARGUMENT)
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
                raise MailError("IMAP search failed", IMAP_ERROR)
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
                raise MailError("IMAP listing failed", IMAP_ERROR)
            uids = sorted(int(x) for x in (data[0] or b"").split())
            messages = self._headers(conn, list(reversed(uids[-cap:])))
            return {"folder": folder, "uidvalidity": info["uidvalidity"], "matching_count": len(uids),
                    "returned_count": len(messages), "messages": messages}

    def read(self, folder: str, uid: int, uidvalidity: int | None = None) -> dict:
        uid_arg = _validate_uid(uid)
        with self.connect() as conn:
            info = self._select(conn, folder)
            self._check_uidvalidity(info, uidvalidity)
            # Check the size before downloading anything so IMAP_MAX_MESSAGE_BYTES bounds bandwidth too.
            status, data = conn.uid("FETCH", uid_arg, "(UID FLAGS RFC822.SIZE INTERNALDATE)")
            meta = _parse_fetch(data).get(uid) if status == "OK" else None
            if meta is None:
                raise MailError("Message not found", MESSAGE_NOT_FOUND)
            if meta.size is not None and meta.size > self.settings.max_message_bytes:
                raise MailError(f"Message is {meta.size} bytes, over the configured maximum "
                                f"({self.settings.max_message_bytes})", MESSAGE_TOO_LARGE)
            # BODY.PEEK does not set \Seen; EXAMINE is read-only as a second guard.
            status, data = conn.uid("FETCH", uid_arg, "(UID BODY.PEEK[])")
            record = _parse_fetch(data).get(uid) if status == "OK" else None
            raw = record.section("BODY[]") if record else None
            if raw is None:
                raise MailError("Message not found", MESSAGE_NOT_FOUND)
            if len(raw) > self.settings.max_message_bytes:
                raise MailError("Message exceeds configured maximum size", MESSAGE_TOO_LARGE)
            out = _message_summary(raw, uid, self.settings.max_body_chars, True)
            out.update(folder=folder, uidvalidity=info["uidvalidity"], size_bytes=meta.size,
                       internal_date=_iso_internaldate(meta.internaldate),
                       seen="\\Seen" in (meta.flags or []))
            return out

    def _headers(self, conn, uids: list[int]) -> list[dict]:
        """Fetch only header fields, flags and size for the UIDs (one round trip), newest first."""
        if not uids:
            return []
        status, data = conn.uid("FETCH", ",".join(_validate_uid(u) for u in uids), _HEADER_ITEMS)
        if status != "OK":
            raise MailError("Message fetch failed", IMAP_ERROR)
        records = _parse_fetch(data)
        out = []
        for uid in uids:
            rec = records.get(uid)
            if rec is None or rec.literal is None:
                continue  # expunged between SEARCH and FETCH
            summary = _message_summary(rec.literal, uid, self.settings.max_body_chars, False)
            summary.update(size_bytes=rec.size, seen="\\Seen" in (rec.flags or []))
            out.append(summary)
        return out

    # Historical analysis ----------------------------------------------------------------------

    def search_advanced(self, folder: str, filters: dict, limit: int, sort: str,
                        cursor: dict | None = None) -> dict:
        """One page of a structured search. The first page fixes an upper UID bound (UIDNEXT-1), so
        mail arriving during enumeration cannot shift pages; each page re-searches only the UID range
        not yet emitted, so nothing is skipped or duplicated and memory stays bounded."""
        if sort not in ("uid_asc", "uid_desc"):
            raise MailError("sort must be uid_asc or uid_desc", INVALID_ARGUMENT)
        page_size = _validate_limit(limit, self.settings.max_page_size)
        with self.connect() as conn:
            build_search_criteria(conn, filters)  # validate before touching the folder
            info = self._select(conn, folder)
            if cursor:
                self._check_uidvalidity(info, cursor["uidvalidity"])
                upper, last = cursor["upper"], cursor["last"]
            else:
                upper, last = (info["uidnext"] or 1) - 1, None
            lo, hi = (last + 1 if last else 1, upper) if sort == "uid_asc" else (1, last - 1 if last else upper)
            uids = [] if hi < lo else [u for u in self._uid_search(conn, *build_search_criteria(
                conn, filters, f"{lo}:{hi}")) if lo <= u <= hi]
            page = uids[:page_size] if sort == "uid_asc" else uids[::-1][:page_size]
            records = self._fetch(conn, page, _LISTING_ITEMS)
            messages = [_listing_record(records[u]) for u in page if u in records and records[u].sections]
            more = len(uids) > len(page)
            return {"folder": folder, "uidvalidity": info["uidvalidity"], "messages": messages,
                    "returned_count": len(messages), "matching_count": len(uids),
                    "remaining_count": len(uids) - len(page),
                    "missing_uids": [u for u in page if u not in records or not records[u].sections],
                    "snapshot_stable": True, "snapshot_upper_uid": upper,
                    "next_state": {"folder": folder, "filters": filters, "sort": sort,
                                   "uidvalidity": info["uidvalidity"], "upper": upper,
                                   "last": page[-1]} if more else None}

    def batch(self, folder: str, uids: list[int], uidvalidity: int | None = None, include_body: bool = True,
              max_body_chars: int | None = None, body_offset: int = 0, include_headers: bool = False,
              include_attachment_metadata: bool = True) -> dict:
        uids = _validate_uids(uids, self.settings.max_batch)
        if isinstance(body_offset, bool) or not isinstance(body_offset, int) or body_offset < 0:
            raise MailError("body_offset must be a non-negative integer", INVALID_ARGUMENT)
        if max_body_chars is not None and (not isinstance(max_body_chars, int) or max_body_chars < 1):
            raise MailError("max_body_chars must be a positive integer", INVALID_ARGUMENT)
        with self.connect() as conn:
            info = self._select(conn, folder)
            self._check_uidvalidity(info, uidvalidity)
            meta = self._fetch(conn, uids, "(UID FLAGS RFC822.SIZE INTERNALDATE BODYSTRUCTURE BODY.PEEK[HEADER])")
            too_large = {u for u, r in meta.items() if (r.size or 0) > self.settings.max_message_bytes}
            to_read = [u for u in uids if u in meta and u not in too_large] if include_body else []
            # Spread the output budget over the bodies so a batch of newsletters cannot flood the context.
            per_message = min(max_body_chars or self.settings.max_body_chars,
                              max(1000, self.settings.batch_output_chars // max(len(to_read), 1)))
            bodies: dict[int, bytes] = {}
            chunk: list[int] = []
            chunk_bytes = 0
            for u in to_read + [None]:  # sentinel flushes the last chunk
                if u is None or (chunk and chunk_bytes + (meta[u].size or 0) > 8_000_000):
                    for uid, rec in self._fetch(conn, chunk, "(UID BODY.PEEK[])").items():
                        if (raw := rec.section("BODY[]")) is not None:
                            bodies[uid] = raw
                    chunk, chunk_bytes = [], 0
                if u is not None:
                    chunk.append(u)
                    chunk_bytes += meta[u].size or 0
            out = []
            for u in uids:
                rec = meta.get(u)
                if rec is None or rec.section("BODY[HEADER") is None:
                    out.append({"uid": u, "status": MESSAGE_NOT_FOUND})
                    continue
                item = {"status": "ok", **_listing_record(rec)}
                header_summary = _message_summary(rec.section("BODY[HEADER"), u, 1, False)
                item.update(reply_to=header_summary["reply_to"], references=header_summary["references"])
                if include_headers:
                    headers = _header_map(rec.section("BODY[HEADER"), DEFAULT_HEADERS)
                    item.update(headers=headers, headers_normalized=_normalized_headers(headers))
                if include_body:
                    if u in too_large:
                        item.update(status=MESSAGE_TOO_LARGE, body=None)
                    elif u not in bodies:
                        item.update(status=MESSAGE_NOT_FOUND, body=None)
                    else:
                        full = _message_summary(bodies[u], u, per_message, True, body_offset)
                        for key in ("body", "body_truncated", "body_source", "body_format", "body_offset",
                                    "body_total_chars", "next_body_offset"):
                            item[key] = full[key]
                        if include_attachment_metadata:
                            item.update(attachments=full["attachments"], has_attachments=full["has_attachments"])
                out.append(item)
            return {"folder": folder, "uidvalidity": info["uidvalidity"], "messages": out,
                    "returned_count": len(out), "per_message_body_limit": per_message if include_body else None}

    def headers(self, folder: str, uids: list[int], uidvalidity: int | None = None,
                names: list[str] | None = None) -> dict:
        uids = _validate_uids(uids, self.settings.max_batch)
        if names is not None:
            if not isinstance(names, list) or len(names) > 100 or not all(
                    isinstance(n, str) and re.fullmatch(r"[!-9;-~]{1,100}|\*", n) for n in names):
                raise MailError("headers must be a list of header field names (or ['*'])", INVALID_ARGUMENT)
        wanted = None if names == ["*"] else (names or DEFAULT_HEADERS)
        with self.connect() as conn:
            info = self._select(conn, folder)
            self._check_uidvalidity(info, uidvalidity)
            records = self._fetch(conn, uids, "(UID BODY.PEEK[HEADER])")
            out = []
            for u in uids:
                raw = records[u].section("BODY[HEADER") if u in records else None
                if raw is None:
                    out.append({"uid": u, "status": MESSAGE_NOT_FOUND})
                    continue
                hdrs = _header_map(raw, wanted)
                normalized = _normalized_headers(_header_map(raw, DEFAULT_HEADERS))
                out.append({"uid": u, "status": "ok", "headers": hdrs, "normalized": normalized})
            return {"folder": folder, "uidvalidity": info["uidvalidity"], "messages": out}

    def inventory(self) -> dict:
        special = ("\\Sent", "\\Drafts", "\\Trash", "\\Junk", "\\Archive", "\\All", "\\Flagged", "\\Important")
        with self.connect() as conn:
            status, data = conn.list()
            if status != "OK":
                raise MailError("Unable to list folders", IMAP_ERROR)
            out = []
            for f in _parse_list(data):
                flags_lower = {x.lower() for x in f["flags"]}
                selectable = not ({"\\noselect", "\\nonexistent"} & flags_lower)
                special_use = next((s for s in special if s.lower() in flags_lower), None)
                delim = f["delimiter"]
                entry = {"name": f["name"], "selectable": selectable, "special_use": special_use,
                         "flags": f["flags"], "delimiter": delim,
                         "parent": f["name"].rsplit(delim, 1)[0] if delim and delim in f["name"] else None,
                         "include_in_history_default": selectable and special_use not in (
                             "\\Trash", "\\Junk", "\\Drafts")}
                if selectable:
                    try:
                        st, sd = conn.status(_validate_folder(f["name"]), "(MESSAGES UNSEEN UIDVALIDITY UIDNEXT)")
                        text = b" ".join(x for x in sd if isinstance(x, bytes)).decode("ascii", "replace")
                        if st != "OK":
                            raise imaplib.IMAP4.error(text)

                        def num(key):
                            m = re.search(rf"\b{key} (\d+)", text)
                            return int(m[1]) if m else None
                        entry.update(total_messages=num("MESSAGES"), unread_messages=num("UNSEEN"),
                                     uidvalidity=num("UIDVALIDITY"), uidnext=num("UIDNEXT"))
                    except (imaplib.IMAP4.error, MailError):
                        entry["error"] = FOLDER_NOT_FOUND
                out.append(entry)
            return {"folders": out}

    # Incremental monitoring -------------------------------------------------------------------

    def changes(self, folder: str, checkpoint: dict | None, limit: int) -> dict:
        """New messages after a checkpoint (folder, UIDVALIDITY, last delivered UID).

        Stateless: the same checkpoint always yields the same page, so a failed or timed-out poll can
        simply be retried. The returned checkpoint covers only UIDs actually returned in this page."""
        page_size = _validate_limit(limit, self.settings.max_page_size)
        unsupported = {"deleted_uids": None, "flag_changes": None}
        with self.connect() as conn:
            info = self._select(conn, folder)
            base = {"folder": folder, "uidvalidity": info["uidvalidity"], "uidnext": info["uidnext"],
                    "unsupported": ["deleted_uids", "flag_changes"], "missing_uids": []}
            baseline = {"folder": folder, "uidvalidity": info["uidvalidity"],
                        "last_uid": (info["uidnext"] or 1) - 1}
            if checkpoint is None:
                return {**base, "changes": {"new_messages": [], **unsupported}, "has_more": False,
                        "baseline": True, "resync_required": False, "next_state": baseline}
            if info["uidvalidity"] != checkpoint["uidvalidity"]:
                return {**base, "changes": {"new_messages": [], **unsupported}, "has_more": False,
                        "baseline": True, "resync_required": True, "next_state": baseline}
            last = checkpoint["last_uid"]
            # "UID n:*" also matches the highest existing UID when it is below n, hence the filter.
            uids = [u for u in self._uid_search(conn, None, "UID", f"{last + 1}:*") if u > last]
            page = uids[:page_size]
            records = self._fetch(conn, page, _LISTING_ITEMS)
            new = [_listing_record(records[u]) for u in page if u in records and records[u].sections]
            return {**base, "changes": {"new_messages": new, **unsupported},
                    "missing_uids": [u for u in page if u not in records or not records[u].sections],
                    "has_more": len(uids) > len(page), "baseline": False, "resync_required": False,
                    "next_state": {"folder": folder, "uidvalidity": info["uidvalidity"],
                                   "last_uid": page[-1] if page else last}}
