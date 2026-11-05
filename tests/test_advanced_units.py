"""Unit tests for the parsing/criteria/token helpers behind the historical-analysis and monitoring tools."""
import time
from email.message import EmailMessage

import pytest

from bg_imap_mcp.imap_client import (MailError, _bodystructure_has_attachments, _header_map, _iso_internaldate,
                                     _listing_record, _message_summary, _normalized_headers, _parse_fetch,
                                     build_search_criteria, html_to_text)
from bg_imap_mcp.tokens import TokenSigner


class Caps:
    capabilities = ("IMAP4REV1", "LITERAL+")


def test_criteria_dates_flags_sizes():
    args = build_search_criteria(Caps(), {"date_from": "2025-11-05", "date_to": "2026-11-06", "seen": False,
                                          "min_size": 1000, "max_size": 5000}, "1:500")
    assert args == [None, "SINCE", "5-Nov-2025", "BEFORE", "6-Nov-2026", "UNSEEN", "LARGER", "999",
                    "SMALLER", "5001", "UID", "1:500"]


def test_criteria_strings_quoted_and_recipient_matches_cc():
    args = build_search_criteria(Caps(), {"sender": 'a"b', "recipient": "bob", "subject": "x)y"})
    assert args == [None, "FROM", '"a\\"b"', "OR", "TO", '"bob"', "CC", '"bob"', "SUBJECT", '"x)y"']


def test_criteria_unicode_uses_literal_plus():
    args = build_search_criteria(Caps(), {"subject": "café"})
    assert args[:2] == ["CHARSET", "UTF-8"] and args[3] == b"{5+}\r\ncaf\xc3\xa9"


def test_criteria_unicode_without_literal_plus():
    class NoCaps:
        capabilities = ("IMAP4REV1",)
    with pytest.raises(MailError) as info:
        build_search_criteria(NoCaps(), {"text": "日本"})
    assert info.value.code == "UNSUPPORTED_OPERATION"


@pytest.mark.parametrize("filters", [{"date_from": "2025/11/05"}, {"date_from": "2026-01-02", "date_to": "2026-01-01"},
                                     {"sender": "x\r\nA1 DELETE INBOX"}, {"text": ""}, {"min_size": -1},
                                     {"max_size": "10"}])
def test_criteria_rejects_bad_input(filters):
    with pytest.raises(MailError) as info:
        build_search_criteria(Caps(), filters)
    assert info.value.code == "INVALID_ARGUMENT"


def test_empty_criteria_is_all():
    assert build_search_criteria(Caps(), {}) == [None, "ALL"]


def test_parse_fetch_multiple_literals():
    data = [(b'7 (UID 42 FLAGS (\\Seen \\Answered) RFC822.SIZE 1234 INTERNALDATE " 5-Nov-2026 16:40:55 +0000" '
             b'BODYSTRUCTURE (("text" "plain" NIL NIL NIL "7bit" 10 1 NIL NIL NIL NIL)("application" "pdf" '
             b'("name" {9}', b'r\xc3\xa9sum.pdf'),
            (b') NIL NIL "base64" 100 NIL ("attachment" NIL) NIL NIL) "mixed" NIL NIL NIL) BODY[HEADER] {20}',
             b'Subject: hi\r\n\r\n'),
            b')']
    rec = _parse_fetch(data)[42]
    assert rec.flags == ["\\Seen", "\\Answered"] and rec.size == 1234
    assert rec.section("BODY[HEADER") == b"Subject: hi\r\n\r\n"
    assert _bodystructure_has_attachments(rec.bodystructure) is True
    assert _iso_internaldate(rec.internaldate) == "2026-11-05T16:40:55Z"


def test_bodystructure_attachment_heuristic():
    plain = b'BODYSTRUCTURE ("text" "plain" ("charset" "utf-8") NIL NIL "7bit" 5 1 NIL NIL NIL NIL)'
    signed = (b'BODYSTRUCTURE (("text" "plain" NIL NIL NIL "7bit" 5 1 NIL NIL NIL NIL)'
              b'("application" "pkcs7-signature" NIL NIL NIL "base64" 9 NIL NIL NIL NIL) "signed" NIL NIL NIL)')
    assert _bodystructure_has_attachments(plain) is False
    assert _bodystructure_has_attachments(signed) is False
    assert _bodystructure_has_attachments(b"") is None


def test_listing_record_fields():
    hdr = (b"From: =?utf-8?q?Zo=C3=AB?= <zoe@example.org>\r\nTo: a@example.org, B <b@example.org>\r\n"
           b"Cc: c@example.org\r\nSubject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=\r\nDate: Wed, 05 Nov 2026 09:40:54 -0700\r\n"
           b"Message-ID: <m1@example.org>\r\nIn-Reply-To: <m0@example.org>\r\nList-ID: News <news.example.org>\r\n"
           b"Precedence: bulk\r\n\r\n")
    data = [(b'1 (UID 9 FLAGS (\\Flagged) RFC822.SIZE 99 INTERNALDATE "05-Nov-2026 16:40:55 +0000" '
             b'BODY[HEADER.FIELDS (FROM TO)] {%d}' % len(hdr), hdr), b')']
    row = _listing_record(_parse_fetch(data)[9])
    assert row["from"] == "zoe@example.org" and row["from_name"] == "Zoë"
    assert row["to"] == ["a@example.org", "b@example.org"] and row["cc"] == ["c@example.org"]
    assert row["subject"] == "Grüße" and row["date"] == "2026-11-05T16:40:54Z"
    assert row["internal_date"] == "2026-11-05T16:40:55Z"
    assert row["flagged"] and not row["seen"] and row["in_reply_to"] == "<m0@example.org>"
    assert row["list_id"] == "News <news.example.org>" and row["precedence"] == "bulk"


def test_headers_normalized_and_raw():
    raw = (b"Message-ID: <a@x>\r\nReferences: <r1@x>\r\n <r2@x>\r\nList-ID: Dev list <dev.lists.example>\r\n"
           b"List-Unsubscribe: <mailto:u@x>, <https://x/unsub>\r\nDelivered-To: owner@example.org\r\n"
           b"Delivered-To: alias@example.org\r\nPrecedence: List\r\nSubject: s\r\n\r\n")
    hdrs = _header_map(raw, ["Delivered-To", "List-ID", "References"])
    assert hdrs["Delivered-To"] == ["owner@example.org", "alias@example.org"] and "Subject" not in hdrs
    n = _normalized_headers(_header_map(raw, None))
    assert n["references"] == ["<r1@x>", "<r2@x>"] and n["list_id"] == "dev.lists.example"
    assert n["list_unsubscribe"] == ["mailto:u@x", "https://x/unsub"] and n["precedence"] == "list"


def test_headers_with_raw_8bit_bytes_are_json_safe():
    import json
    raw = b"Subject: caf\xe9 \xff\r\nFrom: \xe9 <e@x>\r\n\r\n"
    json.dumps(_header_map(raw, None))
    json.dumps(_message_summary(raw, 1, 10, False))


def test_html_links_and_structure():
    text = html_to_text('<html><head><title>T</title><style>p{}</style></head><body><h1>Hi</h1>'
                        '<p>See <a href="https://example.org/x">the doc</a> and '
                        '<a href="https://example.org/y">https://example.org/y</a>.</p>'
                        '<ul><li>one</li><li>two</li></ul><a href="javascript:alert(1)">bad</a></body></html>')
    assert "T\n" not in text and "p{}" not in text
    assert "the doc (https://example.org/x)" in text
    assert text.count("https://example.org/y") == 1 and "javascript" not in text
    assert "- one\n" in text and "- two" in text


def test_body_offset_pagination():
    msg = EmailMessage()
    msg.set_content("".join(str(i % 10) for i in range(100)))
    first = _message_summary(msg.as_bytes(), 1, 40, True)
    assert first["body_truncated"] and first["next_body_offset"] == 40 and first["body_total_chars"] == 100
    rest = []
    offset = 0
    while offset is not None:
        part = _message_summary(msg.as_bytes(), 1, 40, True, offset)
        rest.append(part["body"])
        offset = part["next_body_offset"]
    assert "".join(rest) == "".join(str(i % 10) for i in range(100))


def test_tokens_roundtrip_tamper_kind_expiry(tmp_path):
    signer = TokenSigner.from_file(tmp_path / "state" / "cursor.key")
    assert oct((tmp_path / "state" / "cursor.key").stat().st_mode & 0o777) == "0o600"
    tok = signer.sign("search", {"folder": "INBOX", "last": 5})
    assert signer.verify(tok, "search")["last"] == 5
    assert TokenSigner.from_file(tmp_path / "state" / "cursor.key").verify(tok, "search")  # persists
    body, mac = tok.split(".")
    forged = body[:-2] + ("A" if body[-2] != "A" else "B") + body[-1] + "." + mac
    for bad, code in ((forged, "INVALID_CURSOR"), ("garbage", "INVALID_CURSOR"), (tok + "x", "INVALID_CURSOR")):
        with pytest.raises(MailError) as info:
            signer.verify(bad, "search")
        assert info.value.code == code
    with pytest.raises(MailError):
        signer.verify(tok, "checkpoint")  # kind confusion
    with pytest.raises(MailError) as info:
        signer.verify(signer.sign("search", {"iat_override": 1}), "search", max_age=-1)
    assert info.value.code == "CURSOR_EXPIRED"
    assert TokenSigner.from_file(tmp_path / "other.key").sign("search", {}) != tok
    with pytest.raises(MailError):
        TokenSigner.from_file(tmp_path / "other.key").verify(tok, "search")  # different key
    assert "password" not in str(signer.verify(tok, "search")) and time.time()


def test_crlf_bodies_normalized():
    raw = b"Subject: s\r\nContent-Type: text/plain\r\n\r\nline one\r\nline two\r\n"
    out = _message_summary(raw, 1, 100, True)
    assert out["body"] == "line one\nline two" and out["body_total_chars"] == 17
