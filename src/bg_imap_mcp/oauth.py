"""Built-in single-owner OAuth 2.1 authorization server for remote MCP clients (e.g. ChatGPT).

The MCP SDK supplies the protocol endpoints (metadata, /register, /authorize, /token, /revoke),
PKCE verification and bearer-token checks. This module supplies the policy and storage:

- Dynamic client registration is open (ChatGPT requires it) but redirect URIs must be on an
  allowlisted origin, so codes can only ever be delivered to e.g. https://chatgpt.com.
- /authorize sends the browser to a consent page where the owner must enter a passphrase whose
  scrypt hash is in OAUTH_OWNER_PASSWORD_HASH. Failures are rate limited globally.
- Codes and tokens are random, stored only as SHA-256 hashes in a mode-600 SQLite file, and
  access tokens are bound to this server's /mcp resource URL. Refresh tokens rotate; presenting a
  rotated refresh token revokes the whole grant (token theft detection).
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import anyio
from mcp.server.auth.provider import (AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
                                      RefreshToken, RegistrationError, TokenError, construct_redirect_uri)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

SCOPE = "mail.read"
LOGIN_PATH = "/oauth/login"
DEFAULT_REDIRECT_ORIGINS = "https://chatgpt.com"


class OAuthConfigError(ValueError):
    pass


# --- Owner passphrase (scrypt) -----------------------------------------------------------------

_SCRYPT = {"n": 2**15, "r": 8, "p": 1}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str) -> str:
    """Return 'scrypt:<log2 n>:<r>:<p>:<salt>:<hash>' (no '$', so .env interpolation is not an issue)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, maxmem=128 * 1024 * 1024, dklen=32, **_SCRYPT)
    return f"scrypt:{_SCRYPT['n'].bit_length() - 1}:{_SCRYPT['r']}:{_SCRYPT['p']}:{_b64(salt)}:{_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, log_n, r, p, salt, expected = encoded.split(":")
        if algo != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode("utf-8"), salt=_unb64(salt), n=2 ** int(log_n), r=int(r),
                                p=int(p), maxmem=128 * 1024 * 1024, dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, _unb64(expected))


# --- Configuration -----------------------------------------------------------------------------

def _origin_matches(uri: str, allowed: str) -> bool:
    """allowed is 'scheme://host', 'scheme://host:port' or 'scheme://host:*'."""
    u, a = urlsplit(uri), urlsplit(allowed.replace(":*", ""))
    if u.scheme != a.scheme or (u.hostname or "").lower() != (a.hostname or "").lower():
        return False
    if allowed.endswith(":*"):
        return True
    default = {"https": 443, "http": 80}.get(u.scheme)
    return (u.port or default) == (a.port or default)


@dataclass
class OAuthConfig:
    issuer_url: str  # public base URL, e.g. https://horsetooth.example.ts.net:8443
    owner_password_hash: str
    state_db: Path
    allowed_redirect_origins: list[str] = field(default_factory=lambda: [DEFAULT_REDIRECT_ORIGINS])
    owner_label: str = "the owner"
    access_token_ttl: int = 3600
    refresh_token_ttl: int = 30 * 86400
    code_ttl: int = 300
    max_clients: int = 20

    @property
    def resource_url(self) -> str:
        return self.issuer_url + "/mcp"

    @classmethod
    def from_env(cls, issuer_url: str | None = None) -> OAuthConfig | None:
        issuer = (issuer_url or os.getenv("OAUTH_ISSUER_URL", "")).strip().rstrip("/")
        if not issuer:
            return None
        parts = urlsplit(issuer)
        if parts.scheme != "https" and parts.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise OAuthConfigError("OAUTH_ISSUER_URL must be https (http only for loopback testing)")
        if parts.path or parts.query or parts.fragment:
            raise OAuthConfigError("OAUTH_ISSUER_URL must be a bare origin such as https://host:8443")
        pw_hash = os.getenv("OAUTH_OWNER_PASSWORD_HASH", "").strip()
        if not pw_hash.startswith("scrypt:"):
            raise OAuthConfigError("OAUTH_OWNER_PASSWORD_HASH is missing; run: bg-imap-mcp-auth set-password")
        origins = [o.strip().rstrip("/") for o in
                   os.getenv("OAUTH_ALLOWED_REDIRECT_ORIGINS", DEFAULT_REDIRECT_ORIGINS).split(",") if o.strip()]
        return cls(issuer_url=issuer, owner_password_hash=pw_hash, state_db=default_state_db(),
                   allowed_redirect_origins=origins, owner_label=os.getenv("IMAP_USERNAME", "the owner"))

    def auth_settings(self) -> AuthSettings:
        return AuthSettings(
            issuer_url=self.issuer_url,
            resource_server_url=self.resource_url,
            validate_token_resource=True,
            required_scopes=[SCOPE],
            client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=[SCOPE],
                                                                  default_scopes=[SCOPE]),
            revocation_options=RevocationOptions(enabled=True),
        )


def default_state_db() -> Path:
    if os.getenv("OAUTH_STATE_DB"):
        return Path(os.environ["OAUTH_STATE_DB"]).expanduser()
    base = Path(os.getenv("XDG_STATE_HOME", "~/.local/state")).expanduser()
    return base / "bg-imap-mcp" / "oauth.sqlite3"


# --- Storage -----------------------------------------------------------------------------------

def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Store:
    """SQLite state. Only hashes of codes/tokens are stored."""

    def __init__(self, path: Path):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        self.path = path
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY, info TEXT NOT NULL, created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS codes (
                code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                data TEXT NOT NULL, expires_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS tokens (
                token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL,
                grant_id TEXT NOT NULL, scopes TEXT NOT NULL, resource TEXT, expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS tokens_grant ON tokens(grant_id);
        """)

    def execute(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self._lock:
            return self.db.execute(sql, params).fetchall()

    def purge_expired(self) -> None:
        now = int(time.time())
        self.execute("DELETE FROM codes WHERE expires_at < ?", (now,))
        self.execute("DELETE FROM tokens WHERE expires_at < ?", (now,))

    def revoke_grant(self, grant_id: str) -> None:
        self.execute("DELETE FROM tokens WHERE grant_id = ?", (grant_id,))
        self.execute("DELETE FROM codes WHERE grant_id = ?", (grant_id,))


# --- Provider ----------------------------------------------------------------------------------

@dataclass
class _Pending:
    client_id: str
    params: AuthorizationParams
    expires_at: float
    attempts: int = 0


class OwnerOAuthProvider:
    """OAuthAuthorizationServerProvider for a single mailbox owner."""

    MAX_PENDING = 50
    PENDING_TTL = 600
    MAX_FAILURES = 5
    FAILURE_WINDOW = 900

    def __init__(self, config: OAuthConfig):
        self.config = config
        self.store = Store(config.state_db)
        self.pending: dict[str, _Pending] = {}
        self.failures: deque[float] = deque()

    # Clients -----------------------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        rows = self.store.execute("SELECT info FROM clients WHERE client_id = ?", (client_id,))
        return OAuthClientInformationFull.model_validate_json(rows[0][0]) if rows else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            if not any(_origin_matches(str(uri), o) for o in self.config.allowed_redirect_origins):
                raise RegistrationError("invalid_redirect_uri",
                                        f"redirect_uri origin not allowed: {urlsplit(str(uri)).netloc}")
        if not client_info.redirect_uris:
            raise RegistrationError("invalid_redirect_uri", "redirect_uris required")
        # Anonymous registration is public; cap it and drop stale clients that never got a token.
        count = self.store.execute("SELECT COUNT(*) FROM clients")[0][0]
        if count >= self.config.max_clients:
            self.store.execute("""DELETE FROM clients WHERE created_at < ? AND client_id NOT IN
                                  (SELECT client_id FROM tokens)""", (int(time.time()) - 3600,))
            if self.store.execute("SELECT COUNT(*) FROM clients")[0][0] >= self.config.max_clients:
                raise RegistrationError("invalid_client_metadata", "client registration limit reached")
        self.store.execute("INSERT INTO clients (client_id, info, created_at) VALUES (?, ?, ?)",
                           (client_info.client_id, client_info.model_dump_json(), int(time.time())))

    # Authorization -----------------------------------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource and params.resource.rstrip("/") != self.config.resource_url:
            raise AuthorizeError("invalid_request", "resource does not match this server")
        if params.scopes and set(params.scopes) - {SCOPE}:
            raise AuthorizeError("invalid_scope", f"only {SCOPE} is supported")
        now = time.time()
        for key in [k for k, v in self.pending.items() if v.expires_at < now]:
            del self.pending[key]
        if len(self.pending) >= self.MAX_PENDING:
            raise AuthorizeError("temporarily_unavailable", "too many pending authorizations")
        txn = secrets.token_urlsafe(32)
        self.pending[txn] = _Pending(client.client_id, params, now + self.PENDING_TTL)
        return f"{self.config.issuer_url}{LOGIN_PATH}?txn={txn}"

    def _locked_out(self) -> bool:
        cutoff = time.time() - self.FAILURE_WINDOW
        while self.failures and self.failures[0] < cutoff:
            self.failures.popleft()
        return len(self.failures) >= self.MAX_FAILURES

    async def login_page(self, request: Request) -> Response:
        if request.method == "GET":
            pending = self.pending.get(request.query_params.get("txn", ""))
            if pending is None or pending.expires_at < time.time():
                return _page("Authorization expired", "<p>Start the connection again from the app.</p>", 400)
            return await self._consent(request.query_params["txn"], pending)

        if int(request.headers.get("content-length") or 0) > 4096:
            return _page("Request too large", "", 413)
        form = await request.form()
        txn = str(form.get("txn", ""))
        pending = self.pending.get(txn)
        if pending is None or pending.expires_at < time.time():
            return _page("Authorization expired", "<p>Start the connection again from the app.</p>", 400)
        redirect = str(pending.params.redirect_uri)
        if form.get("action") != "approve":
            del self.pending[txn]
            return RedirectResponse(construct_redirect_uri(redirect, error="access_denied",
                                                           state=pending.params.state), status_code=302)
        if self._locked_out():
            return _page("Too many attempts", "<p>Too many failed sign-ins. Try again later.</p>", 429)
        ok = await anyio.to_thread.run_sync(verify_password, str(form.get("password", "")),
                                            self.config.owner_password_hash)
        if not ok:
            self.failures.append(time.time())
            pending.attempts += 1
            if pending.attempts >= 3:
                del self.pending[txn]
                return _page("Authorization cancelled", "<p>Too many incorrect passphrases.</p>", 401)
            return await self._consent(txn, pending, error="Incorrect passphrase.", status=401)

        del self.pending[txn]
        code = secrets.token_urlsafe(32)
        grant_id = secrets.token_urlsafe(16)
        auth_code = AuthorizationCode(
            code=code, scopes=[SCOPE], expires_at=time.time() + self.config.code_ttl,
            client_id=pending.client_id, code_challenge=pending.params.code_challenge,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            resource=self.config.resource_url, subject="owner")
        self.store.execute("INSERT INTO codes VALUES (?, ?, ?, ?, ?)",
                           (_digest(code), pending.client_id, grant_id, auth_code.model_dump_json(exclude={"code"}),
                            int(auth_code.expires_at)))
        return RedirectResponse(construct_redirect_uri(redirect, code=code, state=pending.params.state),
                                status_code=302)

    async def _consent(self, txn: str, pending: _Pending, error: str = "", status: int = 200) -> Response:
        client = await self.get_client(pending.client_id)
        name = (client.client_name if client else None) or "Unnamed client"
        parts = urlsplit(str(pending.params.redirect_uri))
        dest = parts.netloc
        body = f"""
          <p><b>{html.escape(name)}</b> is requesting <b>read-only</b> access to the mailbox of
             <b>{html.escape(self.config.owner_label)}</b>.</p>
          <p class="muted">After approval you will be returned to <b>{html.escape(dest)}</b>.
             Only approve if you just started this connection yourself.</p>
          {f'<p class="err">{html.escape(error)}</p>' if error else ''}
          <form method="post" action="{LOGIN_PATH}">
            <input type="hidden" name="txn" value="{html.escape(txn)}">
            <label>Owner passphrase<input type="password" name="password" autocomplete="current-password"
                   autofocus></label>
            <div class="row"><button name="action" value="approve">Approve</button>
            <button name="action" value="deny" class="secondary" formnovalidate>Deny</button></div>
          </form>"""
        # CSP form-action also governs the post-submit redirect, so allow exactly the client's origin.
        return _page("Authorize mailbox access", body, status, form_action=f"{parts.scheme}://{parts.netloc}")

    # Codes and tokens --------------------------------------------------------------------------

    async def load_authorization_code(self, client: OAuthClientInformationFull,
                                      authorization_code: str) -> AuthorizationCode | None:
        rows = self.store.execute("SELECT client_id, data FROM codes WHERE code_hash = ?",
                                  (_digest(authorization_code),))
        if not rows or rows[0][0] != client.client_id:
            return None
        return AuthorizationCode.model_validate({**json.loads(rows[0][1]), "code": authorization_code})

    async def exchange_authorization_code(self, client: OAuthClientInformationFull,
                                          authorization_code: AuthorizationCode) -> OAuthToken:
        rows = self.store.execute("DELETE FROM codes WHERE code_hash = ? RETURNING grant_id",
                                  (_digest(authorization_code.code),))
        if not rows:  # single use: a concurrent exchange already consumed it
            raise TokenError("invalid_grant", "authorization code already used")
        return self._issue(client.client_id, rows[0][0], authorization_code.scopes)

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        rows = self.store.execute("""SELECT client_id, grant_id, scopes, resource, expires_at, revoked FROM tokens
                                     WHERE token_hash = ? AND kind = 'refresh'""", (_digest(refresh_token),))
        if not rows:
            return None
        client_id, grant_id, scopes, resource, expires_at, revoked = rows[0]
        if revoked:
            self.store.revoke_grant(grant_id)  # replay of a rotated token: assume theft
            return None
        if client_id != client.client_id or expires_at < time.time():
            return None
        return RefreshToken(token=refresh_token, client_id=client_id, scopes=scopes.split(),
                            expires_at=expires_at, resource=resource, subject="owner")

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken,
                                     scopes: list[str]) -> OAuthToken:
        rows = self.store.execute("""UPDATE tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0
                                     RETURNING grant_id""", (_digest(refresh_token.token),))
        if not rows:
            raise TokenError("invalid_grant", "refresh token already used")
        grant_id = rows[0][0]
        self.store.execute("DELETE FROM tokens WHERE grant_id = ? AND kind = 'access'", (grant_id,))
        return self._issue(client.client_id, grant_id, scopes)

    def _issue(self, client_id: str, grant_id: str, scopes: list[str]) -> OAuthToken:
        self.store.purge_expired()
        now = int(time.time())
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        for token, kind, ttl in ((access, "access", self.config.access_token_ttl),
                                 (refresh, "refresh", self.config.refresh_token_ttl)):
            self.store.execute("INSERT INTO tokens VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
                               (_digest(token), kind, client_id, grant_id, " ".join(scopes),
                                self.config.resource_url, now + ttl, now))
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=self.config.access_token_ttl,
                          refresh_token=refresh, scope=" ".join(scopes))

    async def load_access_token(self, token: str) -> AccessToken | None:
        rows = self.store.execute("""SELECT client_id, scopes, resource, expires_at FROM tokens
                                     WHERE token_hash = ? AND kind = 'access' AND revoked = 0""", (_digest(token),))
        if not rows or rows[0][3] < time.time():
            return None
        client_id, scopes, resource, expires_at = rows[0]
        return AccessToken(token=token, client_id=client_id, scopes=scopes.split(), expires_at=expires_at,
                           resource=resource, subject="owner")

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        rows = self.store.execute("SELECT grant_id FROM tokens WHERE token_hash = ?", (_digest(token.token),))
        if rows:
            self.store.revoke_grant(rows[0][0])


def _page(title: str, body: str, status: int = 200, form_action: str = "") -> HTMLResponse:
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title>
<style>
 :root{{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#5b6475;--accent:#2457d6;--err:#b42318}}
 @media (prefers-color-scheme:dark){{:root{{--bg:#12151b;--card:#1b2029;--fg:#e8ebf1;--muted:#9aa3b5;--accent:#7aa2ff;--err:#ff8a7a}}}}
 body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh}}
 main{{background:var(--card);padding:28px;border-radius:12px;max-width:420px;width:calc(100% - 32px);box-sizing:border-box}}
 h1{{font-size:20px;margin:0 0 12px}} .muted{{color:var(--muted);font-size:14px}} .err{{color:var(--err)}}
 label{{display:block;margin:16px 0}} input[type=password]{{display:block;width:100%;box-sizing:border-box;margin-top:6px;padding:10px;font:inherit;border-radius:8px;border:1px solid var(--muted);background:transparent;color:inherit}}
 .row{{display:flex;gap:12px}} button{{flex:1;padding:10px;font:inherit;border-radius:8px;border:0;background:var(--accent);color:#fff;cursor:pointer}}
 button.secondary{{background:transparent;color:var(--fg);border:1px solid var(--muted)}}
</style></head><body><main><h1>{html.escape(title)}</h1>{body}</main></body></html>"""
    return HTMLResponse(doc, status_code=status, headers={
        "Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                   f"form-action 'self' {form_action}; frame-ancestors 'none'; base-uri 'none'"})


# --- Admin CLI ---------------------------------------------------------------------------------

def _set_env_value(env_file: Path, key: str, value: str) -> None:
    lines = env_file.read_text().splitlines() if env_file.exists() else []
    lines = [ln for ln in lines if not ln.startswith(f"{key}=")] + [f"{key}={value}"]
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(env_file, 0o600)


def admin_main(argv: list[str] | None = None) -> None:
    from dotenv import find_dotenv, load_dotenv
    parser = argparse.ArgumentParser(prog="bg-imap-mcp-auth", description="Manage the built-in OAuth server")
    parser.add_argument("--env-file", default=None, help="path to .env (default: the one the server loads)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("set-password", help="set the owner passphrase (stores only an scrypt hash in .env)")
    sub.add_parser("status", help="list registered clients and active grants")
    rv = sub.add_parser("revoke-all", help="revoke every token (ChatGPT must reconnect)")
    rv.add_argument("--clients", action="store_true", help="also delete client registrations")
    args = parser.parse_args(argv)

    env_file = Path(args.env_file or find_dotenv(usecwd=True) or Path(__file__).resolve().parents[2] / ".env")
    load_dotenv(env_file)

    if args.cmd == "set-password":
        first = getpass.getpass("New owner passphrase (min 16 chars): ")
        if len(first) < 16:
            raise SystemExit("Passphrase too short; use at least 16 characters (a few random words works well)")
        if getpass.getpass("Repeat: ") != first:
            raise SystemExit("Passphrases do not match")
        _set_env_value(env_file, "OAUTH_OWNER_PASSWORD_HASH", hash_password(first))
        print(f"Saved OAUTH_OWNER_PASSWORD_HASH to {env_file}. Restart the server to apply.")
        return

    store = Store(default_state_db())
    if args.cmd == "status":
        print(f"state db: {store.path}")
        for client_id, info, created in store.execute("SELECT client_id, info, created_at FROM clients"):
            meta = json.loads(info)
            grants = store.execute("""SELECT COUNT(DISTINCT grant_id), MAX(created_at) FROM tokens
                                      WHERE client_id = ? AND revoked = 0 AND expires_at > ?""",
                                   (client_id, int(time.time())))[0]
            hosts = sorted({urlsplit(u).netloc for u in meta.get("redirect_uris") or []})
            last = time.strftime("%Y-%m-%d %H:%M", time.localtime(grants[1])) if grants[1] else "-"
            print(f"- {meta.get('client_name') or 'unnamed'} ({client_id[:8]}) redirect={','.join(hosts)} "
                  f"registered={time.strftime('%Y-%m-%d', time.localtime(created))} "
                  f"active_grants={grants[0]} last_token={last}")
    elif args.cmd == "revoke-all":
        store.execute("DELETE FROM tokens")
        store.execute("DELETE FROM codes")
        if args.clients:
            store.execute("DELETE FROM clients")
        print("All tokens revoked" + (" and clients deleted" if args.clients else ""))
