# bg-imapMCPSever

Read-only MCP server for any standard IMAP-over-TLS mailbox, intended for personal hosting on Linux. No provider details, addresses, or passwords are hardcoded. Written in Python using the official MCP SDK v1 line (pinned to `<2` for API stability).

## Features

Original tools (unchanged arguments and results; new fields are additive):

- `check_connection`: verify IMAP TLS/login
- `list_folders`: folder names (decoded from IMAP modified UTF-7), hierarchy delimiter and flags
- `folder_status`: total and unread counts plus `UIDVALIDITY`
- `list_messages`: latest headers/UIDs with seen flag and size, optionally unread-only
- `search_messages`: plain-text IMAP search in `text` (default), `subject`, `from`, `to` or `body`, optionally unread-only
- `read_message`: subject, sender, recipients, date, text body, attachment names/types/sizes, plus structured addresses, `reply_to`, `internal_date`, `in_reply_to`, `references`, `list_id`, `has_attachments`, `body_format`; optional `uidvalidity` check

Historical analysis and monitoring:

- `get_mailbox_inventory`: every folder with server-reported special use (`\Sent`, `\Trash`, …), hierarchy, counts, `UIDVALIDITY`, `UIDNEXT`, and whether it belongs in a history analysis by default (not Trash/Junk/Drafts)
- `search_messages_advanced`: structured search (delivery-date range, sender, recipient, subject, text, seen, size) returning compact metadata with **complete, deterministic pagination**: the first page fixes an upper UID bound, each `next_cursor` continues from the last UID returned, and every matching message is returned exactly once with no hidden cap. Mail arriving mid-enumeration is excluded (use monitoring for it); expunged messages simply drop out
- `get_messages_batch`: up to 100 messages by UID with per-message status, decoded text bodies (HTML converted to text with link targets), attachment metadata and optional thread/list headers; bodies share an output budget and continue with `body_offset`
- `get_message_headers`: selected or all headers, plus normalized Message-ID/In-Reply-To/References/List-ID/List-Unsubscribe/Auto-Submitted/Precedence/Delivered-To
- `get_mailbox_changes`: polling checkpoint API. A stateless checkpoint (folder, UIDVALIDITY, last delivered UID) returns newer messages oldest first; retrying a checkpoint is safe, it survives restarts, and a UIDVALIDITY change returns `resync_required`. Deletions and flag changes are reported as unsupported (they need CONDSTORE/QRESYNC, which many servers lack)

Common properties:

- Read-only by design: `EXAMINE` and `BODY.PEEK` only; no STORE/COPY/MOVE/EXPUNGE/APPEND. All tools carry the MCP `readOnlyHint` annotation; the Dovecot test suite records every IMAP command to prove it
- Cursors and checkpoints are opaque, HMAC-signed tokens (key in the state directory, mode 600); they contain no credentials
- Errors start with a stable code: `AUTHENTICATION_FAILED`, `FOLDER_NOT_FOUND`, `UIDVALIDITY_CHANGED`, `INVALID_CURSOR`, `CURSOR_EXPIRED`, `MESSAGE_NOT_FOUND`, `MESSAGE_TOO_LARGE`, `IMAP_TIMEOUT`, `IMAP_CONNECTION_ERROR`, `INVALID_ARGUMENT`, `UNSUPPORTED_OPERATION`, `IMAP_ERROR`, `CONFIG_ERROR`
- Tools run in worker threads with at most 3 concurrent IMAP sessions, so a slow full-text search does not block other requests; connection failures are retried with backoff
- Listing/search fetch only header fields, flags, size and BODYSTRUCTURE, never message bodies

**Security:** Email bodies can contain prompt injection. Treat mailbox content as untrusted. The server does not intentionally modify mail, but connecting to a remote service still exposes sensitive mail contents to whichever MCP clients you authorize. This project has not been independently security-audited.

## Install on horsetooth (Ubuntu/Linux)

```bash
git clone https://github.com/junga-com/bg-imapMCPSever.git
cd bg-imapMCPSever
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
chmod 600 .env
$EDITOR .env
pytest -q
```

In `.env`, set `IMAP_HOST`, `IMAP_USERNAME` and `IMAP_PASSWORD` to the actual values from your email provider's mail-client setup page. IMAP TLS commonly uses port `993`; verify your provider's settings. **Do not post passwords in chat or commit `.env`.** An app-specific password, if supported, is preferable.

## Test locally

Start the MCP Inspector (requires Node.js/npm):

```bash
source .venv/bin/activate
npx -y @modelcontextprotocol/inspector
```

In Inspector, select **STDIO**, set command to the absolute path of `.venv/bin/bg-imap-mcp`, and set working directory to this repository so `.env` is loaded. Alternatively, from a terminal in the repository:

```bash
bg-imap-mcp --transport streamable-http --host 127.0.0.1 --port 8765
```

Then connect Inspector to `http://127.0.0.1:8765/mcp` using **Streamable HTTP**, and call `check_connection` and `folder_status` first. The HTTP endpoint is **not authenticated**; it is deliberately restricted to loopback. Never expose it directly to the Internet or bind to `0.0.0.0`.

## Remote access (ChatGPT) with built-in OAuth

ChatGPT's custom MCP connectors need a public HTTPS URL and OAuth (or no auth at all; never use that here). The server includes a small single-owner OAuth 2.1 authorization server, enabled by setting `OAUTH_ISSUER_URL`:

- Dynamic client registration is open, as ChatGPT requires, but redirect URIs must be on an allowlisted origin (`OAUTH_ALLOWED_REDIRECT_ORIGINS`, default `https://chatgpt.com`), so authorization codes can only be delivered there.
- Authorization shows a consent page that requires the **owner passphrase** (stored only as an scrypt hash). Five failures in 15 minutes lock sign-in for everyone; three on one attempt cancel it.
- PKCE (S256) is mandatory. Codes are single use and last 5 minutes. Access tokens last 1 hour and are bound to `<issuer>/mcp`; refresh tokens last 30 days and rotate, and replaying a rotated refresh token revokes the whole grant.
- Codes and tokens are stored only as SHA-256 hashes in a mode-600 SQLite file (`OAUTH_STATE_DB`).
- The server still binds only to loopback. Publish it with a TLS tunnel that terminates on this machine, e.g. Tailscale Funnel.

Setup with Tailscale Funnel. **Use port 443**: ChatGPT does not connect to MCP servers on other ports (with `:8443` it fails with "Couldn't discover OAuth settings" and never sends a request). Funnel is enabled per port, so move any tailnet-only `tailscale serve` on 443 to another port first (e.g. `sudo tailscale serve --https=443 off && sudo tailscale serve --bg --https=8443 http://127.0.0.1:<port>`).

```bash
bg-imap-mcp-auth set-password            # prompts; writes OAUTH_OWNER_PASSWORD_HASH to .env
echo 'OAUTH_ISSUER_URL=https://<machine>.<tailnet>.ts.net' >> .env
bg-imap-mcp --transport streamable-http --port 8765
sudo tailscale funnel --bg --https=443 http://127.0.0.1:8765
```

Then in ChatGPT add a custom MCP server with URL `https://<machine>.<tailnet>.ts.net/mcp` and OAuth authentication, and approve on the consent page.

Run it as a service (systemd user unit; survives reboots with lingering enabled):

```bash
mkdir -p ~/.config/systemd/user && cp scripts/bg-imap-mcp.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now bg-imap-mcp
loginctl enable-linger "$USER"
journalctl --user -u bg-imap-mcp -f       # logs
```

Operations:

- `bg-imap-mcp-auth status` lists registered clients and active grants.
- `bg-imap-mcp-auth revoke-all [--clients]` revokes every token immediately (a kill switch).
- `sudo tailscale funnel --https=443 off` takes the endpoint off the Internet; `systemctl --user stop bg-imap-mcp` stops the server.
- After `bg-imap-mcp-auth set-password` or `.env` changes: `systemctl --user restart bg-imap-mcp`.

When OAuth is enabled, local clients must use OAuth too (MCP Inspector supports it); use the stdio transport for unauthenticated local use.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `IMAP_HOST` | required | IMAP DNS name |
| `IMAP_PORT` | `993` | TLS IMAP port |
| `IMAP_USERNAME` | required | Mailbox login |
| `IMAP_PASSWORD` | required | Mailbox/app password |
| `IMAP_DEFAULT_FOLDER` | `INBOX` | Folder used when a tool call omits `folder` |
| `IMAP_TIMEOUT` | `20` | IMAP socket inactivity timeout (seconds) |
| `IMAP_MAX_RESULTS` | `50` | Hard cap for listing/search results |
| `IMAP_MAX_BODY_CHARS` | `20000` | Cap on returned message body characters |
| `IMAP_MAX_MESSAGE_BYTES` | `3000000` | Cap on fetched message size (see note below) |
| `IMAP_MAX_PAGE_SIZE` | `500` | Maximum `limit` for `search_messages_advanced` / `get_mailbox_changes` |
| `IMAP_MAX_BATCH` | `100` | Maximum UIDs per `get_messages_batch` / `get_message_headers` call |
| `IMAP_BATCH_OUTPUT_CHARS` | `150000` | Body-text budget shared by the messages of one batch |
| `IMAP_CA_FILE` | system trust | CA bundle for servers with a private CA (certificate is still verified) |

**Size note:** `read_message` checks the server-reported `RFC822.SIZE` before downloading, so messages over `IMAP_MAX_MESSAGE_BYTES` are refused without being transferred. Attachment contents are not returned, but the MIME parser processes the full message.

**Body note:** the `text/plain` part is preferred; if it is a short stub (as in much bulk mail) and an HTML part has substantially more text, the HTML is converted to text instead. `body_source` reports which was used.

### Known limitations

- Searches are IMAP substring searches done by the server (no Gmail syntax or boolean expressions). Matching of non-ASCII text depends on the server's charset support. Full-text (`text`/`body`) searches of large folders take tens of seconds; date, sender and subject filters take one or two.
- Date filters use the IMAP INTERNALDATE (delivery time) at day granularity, as the server interprets it (Dovecot compares UTC dates); `date_from` is inclusive, `date_to` exclusive. The `Date:` header is reported separately.
- `has_attachments` in listings is derived from BODYSTRUCTURE (an `attachment` disposition or a non-signature `application/*` part); `get_messages_batch`/`read_message` report the parsed attachments.
- Search cursors expire after 7 days; deleting `cursor.key` in the state directory invalidates all cursors and checkpoints.
- Search/list return the newest UIDs, not necessarily the newest Date headers.
- Attachment contents and HTML originals are not exposed; HTML-only mail gets a basic plaintext extraction.
- Each tool call uses its own IMAP connection (no pooling or caching).
- `read_message` requires the UID **and folder** returned from search/list; IMAP UIDs are scoped to a folder and can be invalidated if its UIDVALIDITY changes.
- Without `OAUTH_ISSUER_URL` the HTTP transport has no authorization and rejects any non-loopback `Host` header; never publish it in that mode.
- The OAuth server is single-owner and not independently audited. Pending authorizations and the sign-in lockout are kept in memory and reset on restart.

## Development

```bash
python -m pip install -e '.[dev]'
pytest -q
```

CI runs tests on Python 3.11 and 3.12. No real IMAP account is used in tests. The acceptance suite in `tests/test_dovecot_integration.py` starts a disposable Dovecot container with a throwaway CA, seeds it through a separate admin connection, and covers pagination under concurrent arrivals/expunges, UIDVALIDITY resets, batch decoding, body continuation, monitoring checkpoints, and read-only command recording:

```bash
BG_IMAP_DOVECOT_TESTS=1 pytest -q   # requires docker and openssl
```
