"""Integrity-protected opaque tokens for search cursors and monitoring checkpoints.

A token is base64url(JSON payload) + "." + base64url(HMAC-SHA256). The payload holds only folder,
UIDVALIDITY, UID bounds and the caller's own search filters: never credentials. The HMAC key lives in
the server's state directory (mode 600), so tokens survive restarts; deleting the key invalidates them.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from .imap_client import CURSOR_EXPIRED, INVALID_CURSOR, MailError

VERSION = 1


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class TokenSigner:
    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("token key too short")
        self._key = key

    @classmethod
    def from_file(cls, path: Path) -> TokenSigner:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return cls(path.read_bytes())
        with os.fdopen(fd, "wb") as fh:
            fh.write(secrets.token_bytes(32))
        return cls(path.read_bytes())

    def _mac(self, body: bytes) -> bytes:
        return hmac.new(self._key, body, hashlib.sha256).digest()[:20]

    def sign(self, kind: str, payload: dict) -> str:
        body = json.dumps({"v": VERSION, "k": kind, "iat": int(time.time()), **payload},
                          separators=(",", ":"), sort_keys=True).encode()
        return f"{_b64(body)}.{_b64(self._mac(body))}"

    def verify(self, token: str, kind: str, max_age: int | None = None) -> dict:
        try:
            body_b64, mac_b64 = token.split(".")
            body = _unb64(body_b64)
            ok = hmac.compare_digest(self._mac(body), _unb64(mac_b64))
            payload = json.loads(body) if ok else None
        except (AttributeError, ValueError, TypeError):
            payload = None
        if not payload or payload.get("v") != VERSION or payload.get("k") != kind:
            raise MailError(f"Invalid or tampered {kind} token; start again without it", INVALID_CURSOR)
        if max_age is not None and time.time() - payload.get("iat", 0) > max_age:
            raise MailError(f"{kind} token expired; start the enumeration again", CURSOR_EXPIRED)
        return payload
