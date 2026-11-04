# bg-imapMCPSever

Read-only MCP server for any standard IMAP-over-TLS mailbox, intended for personal hosting on Linux. No provider details, addresses, or passwords are hardcoded. Written in Python using the official MCP SDK v1 line (pinned to `<2` for API stability).

## Features

- `check_connection`: verify IMAP TLS/login
- `list_folders`: list server folder entries
- `folder_status`: total and unread counts
- `list_messages`: latest headers/UIDs, optionally unread-only
- `search_messages`: plain-text IMAP `TEXT` search, optionally unread-only
- `read_message`: subject, sender, recipients, date, text body, attachment names/types/sizes
- Read-only by design: uses `EXAMINE` / `select(readonly=True)` and `BODY.PEEK`; no delete, flag, move or send operations
- Configurable message-size and result caps

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

## ChatGPT integration

A local `127.0.0.1` server on horsetooth is not directly reachable from ChatGPT's cloud. To use this server from ChatGPT, deploy a properly authenticated HTTPS MCP endpoint or place it behind a trusted tunnel/reverse proxy that provides authentication and access controls. **A tunnel alone without authentication is insufficient.** Test locally before building this integration. ChatGPT custom connectors and workspace policies may require additional configuration.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `IMAP_HOST` | required | IMAP DNS name |
| `IMAP_PORT` | `993` | TLS IMAP port |
| `IMAP_USERNAME` | required | Mailbox login |
| `IMAP_PASSWORD` | required | Mailbox/app password |
| `IMAP_DEFAULT_FOLDER` | `INBOX` | Reserved default folder setting |
| `IMAP_TIMEOUT` | `20` | IMAP socket timeout (seconds) |
| `IMAP_MAX_RESULTS` | `50` | Hard cap for listing/search results |
| `IMAP_MAX_BODY_CHARS` | `20000` | Cap on returned message body characters |
| `IMAP_MAX_MESSAGE_BYTES` | `3000000` | Cap on fetched message size (see note below) |

**Size note:** the message-byte limit is checked after the server returns the full message, so it is *not* a download-bandwidth guard. Avoid reading unusually large messages. Attachment contents are not returned, but the MIME parser processes the full message.

### Known limitations

- The search API uses simple `TEXT` search; not Gmail syntax or multi-field boolean expressions.
- Search/list return the newest UIDs, not necessarily the newest Date headers.
- Server folder listings are raw IMAP LIST entries rather than decoded folder names.
- Attachment contents and HTML originals are not exposed; HTML-only mail gets a basic plaintext extraction.
- The current version connects separately for each tool call. No caching or incremental synchronization.
- `read_message` requires the UID **and folder** returned from search/list; IMAP UIDs are scoped to a folder and can be invalidated if its UIDVALIDITY changes.
- Local HTTP transport uses no authorization and must never be made public directly.

## Development

```bash
python -m pip install -e '.[dev]'
pytest -q
```

CI runs tests on Python 3.11 and 3.12. No real IMAP account is used in tests.
