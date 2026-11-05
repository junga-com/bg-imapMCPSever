import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient

from bg_imap_mcp import oauth
from bg_imap_mcp.oauth import OAuthConfig, OwnerOAuthProvider, hash_password, verify_password
from bg_imap_mcp.server import build_server

ISSUER = "https://mail.example.ts.net:8443"
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
PASSWORD = "correct horse battery staple"
PW_HASH = hash_password(PASSWORD)
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}


@pytest.fixture
def config(tmp_path):
    return OAuthConfig(issuer_url=ISSUER, owner_password_hash=PW_HASH, state_db=tmp_path / "state" / "oauth.sqlite3",
                       owner_label="me@example.org")


@pytest.fixture
def client(config):
    server = build_server(config)
    with TestClient(server.streamable_http_app(), base_url=ISSUER, follow_redirects=False) as c:
        c.provider = next(r.endpoint.__self__ for r in server._custom_starlette_routes)
        yield c


def register(c, redirect=REDIRECT, name="ChatGPT"):
    return c.post("/register", json={"redirect_uris": [redirect], "client_name": name,
                                     "grant_types": ["authorization_code", "refresh_token"],
                                     "response_types": ["code"], "token_endpoint_auth_method": "client_secret_post"})


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def start_authorize(c, reg, challenge, **extra):
    params = {"response_type": "code", "client_id": reg["client_id"], "redirect_uri": REDIRECT,
              "code_challenge": challenge, "code_challenge_method": "S256", "state": "st8",
              "scope": "mail.read", "resource": ISSUER + "/mcp", **extra}
    return c.get("/authorize", params=params)


def login(c, location, password=PASSWORD, action="approve"):
    txn = parse_qs(urlsplit(location).query)["txn"][0]
    return c.post("/oauth/login", data={"txn": txn, "password": password, "action": action})


def full_grant(c):
    reg = register(c).json()
    verifier, challenge = pkce()
    r = login(c, start_authorize(c, reg, challenge).headers["location"])
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    tok = c.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                 "client_id": reg["client_id"], "client_secret": reg["client_secret"],
                                 "code_verifier": verifier, "resource": ISSUER + "/mcp"})
    assert tok.status_code == 200, tok.text
    return reg, tok.json(), code, verifier


def mcp_init(c, token):
    headers = dict(MCP_HEADERS, **({"Authorization": f"Bearer {token}"} if token else {}))
    return c.post("/mcp", json=INIT, headers=headers)


def test_password_hashing():
    assert verify_password(PASSWORD, PW_HASH)
    assert not verify_password("wrong", PW_HASH)
    assert not verify_password(PASSWORD, "garbage")
    assert "$" not in PW_HASH and PASSWORD not in PW_HASH


def test_metadata_and_unauthenticated_request(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"].rstrip("/") == ISSUER and meta["registration_endpoint"].startswith(ISSUER)
    prm = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert prm["resource"] == ISSUER + "/mcp" and prm["scopes_supported"] == ["mail.read"]
    r = mcp_init(client, None)
    assert r.status_code == 401
    assert "resource_metadata=" in r.headers["www-authenticate"]


def test_registration_redirect_allowlist(client):
    assert register(client, "https://evil.example/cb").status_code == 400
    assert register(client, "https://chatgpt.com.evil.example/cb").status_code == 400
    assert register(client, "http://chatgpt.com/cb").status_code == 400
    assert register(client).status_code == 201


def test_full_flow_and_tool_access(client):
    reg, tokens, code, verifier = full_grant(client)
    assert tokens["token_type"].lower() == "bearer" and tokens["scope"] == "mail.read"
    assert mcp_init(client, tokens["access_token"]).status_code == 200
    assert mcp_init(client, "not-a-token").status_code == 401
    # Authorization codes are single use.
    again = client.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                        "client_id": reg["client_id"], "client_secret": reg["client_secret"],
                                        "code_verifier": verifier})
    assert again.status_code == 400
    # Only hashes are stored.
    db = client.provider.store
    stored = " ".join(str(r) for r in db.execute("SELECT * FROM tokens"))
    assert tokens["access_token"] not in stored and tokens["refresh_token"] not in stored


def test_consent_page_escapes_and_headers(client):
    reg = register(client, name="<script>x</script>").json()
    r = client.get(start_authorize(client, reg, pkce()[1]).headers["location"])
    assert r.status_code == 200
    assert "<script>x" not in r.text and "&lt;script&gt;" in r.text and "chatgpt.com" in r.text
    assert r.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "form-action 'self' https://chatgpt.com" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_wrong_password_and_deny(client):
    reg = register(client).json()
    loc = start_authorize(client, reg, pkce()[1]).headers["location"]
    assert login(client, loc, "nope").status_code == 401
    r = login(client, loc, action="deny")
    assert r.status_code == 302
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["error"] == ["access_denied"] and q["state"] == ["st8"] and "code" not in q
    assert login(client, loc).status_code == 400  # transaction consumed


def test_txn_cancelled_after_three_failures(client):
    reg = register(client).json()
    loc = start_authorize(client, reg, pkce()[1]).headers["location"]
    for _ in range(3):
        login(client, loc, "nope")
    assert login(client, loc).status_code == 400


def test_global_lockout(client):
    reg = register(client).json()
    for _ in range(OwnerOAuthProvider.MAX_FAILURES):
        login(client, start_authorize(client, reg, pkce()[1]).headers["location"], "nope")
    r = login(client, start_authorize(client, reg, pkce()[1]).headers["location"])
    assert r.status_code == 429


def test_wrong_resource_rejected(client):
    reg = register(client).json()
    r = start_authorize(client, reg, pkce()[1], resource="https://other.example/mcp")
    assert r.status_code == 302 and "error=invalid_request" in r.headers["location"]


def test_refresh_rotation_and_reuse_detection(client):
    reg, tokens, _, _ = full_grant(client)

    def refresh(rt):
        return client.post("/token", data={"grant_type": "refresh_token", "refresh_token": rt,
                                           "client_id": reg["client_id"], "client_secret": reg["client_secret"]})
    r1 = refresh(tokens["refresh_token"])
    assert r1.status_code == 200
    new = r1.json()
    assert mcp_init(client, tokens["access_token"]).status_code == 401  # old access token dropped
    assert mcp_init(client, new["access_token"]).status_code == 200
    assert refresh(tokens["refresh_token"]).status_code == 400  # replay of rotated token ...
    assert refresh(new["refresh_token"]).status_code == 400     # ... revokes the whole grant
    assert mcp_init(client, new["access_token"]).status_code == 401


def test_revocation_endpoint(client):
    reg, tokens, _, _ = full_grant(client)
    r = client.post("/revoke", data={"token": tokens["access_token"], "client_id": reg["client_id"],
                                     "client_secret": reg["client_secret"]})
    assert r.status_code == 200
    assert mcp_init(client, tokens["access_token"]).status_code == 401


def test_expired_access_token(client, monkeypatch):
    _, tokens, _, _ = full_grant(client)
    real = oauth.time.time
    monkeypatch.setattr(oauth.time, "time", lambda: real() + 7200)
    assert mcp_init(client, tokens["access_token"]).status_code == 401


def test_state_db_permissions(config):
    OwnerOAuthProvider(config)
    assert oct(config.state_db.stat().st_mode & 0o777) == "0o600"
    assert oct(config.state_db.parent.stat().st_mode & 0o777) == "0o700"


def test_config_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("OAUTH_STATE_DB", str(tmp_path / "s.db"))
    monkeypatch.delenv("OAUTH_ISSUER_URL", raising=False)
    assert OAuthConfig.from_env() is None
    monkeypatch.setenv("OAUTH_OWNER_PASSWORD_HASH", PW_HASH)
    with pytest.raises(oauth.OAuthConfigError):
        OAuthConfig.from_env("http://public.example")
    with pytest.raises(oauth.OAuthConfigError):
        OAuthConfig.from_env("https://public.example/mcp")
    monkeypatch.delenv("OAUTH_OWNER_PASSWORD_HASH")
    with pytest.raises(oauth.OAuthConfigError, match="set-password"):
        OAuthConfig.from_env(ISSUER)
    monkeypatch.setenv("OAUTH_OWNER_PASSWORD_HASH", PW_HASH)
    cfg = OAuthConfig.from_env(ISSUER + "/")
    assert cfg.resource_url == ISSUER + "/mcp" and cfg.allowed_redirect_origins == ["https://chatgpt.com"]


def test_set_env_value_preserves_other_lines(tmp_path):
    env = tmp_path / ".env"
    env.write_text("IMAP_HOST=h\nOAUTH_OWNER_PASSWORD_HASH=old\nIMAP_PASSWORD=p\n")
    oauth._set_env_value(env, "OAUTH_OWNER_PASSWORD_HASH", "new")
    text = env.read_text()
    assert "IMAP_HOST=h" in text and "IMAP_PASSWORD=p" in text and "old" not in text
    assert re.search(r"^OAUTH_OWNER_PASSWORD_HASH=new$", text, re.M)
    assert oct(env.stat().st_mode & 0o777) == "0o600"


def test_unauthenticated_server_rejects_public_host():
    with TestClient(build_server().streamable_http_app(), base_url=ISSUER) as c:
        assert c.post("/mcp", json=INIT, headers=MCP_HEADERS).status_code == 421
