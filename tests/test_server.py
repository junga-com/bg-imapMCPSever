import anyio
import pytest
from mcp.server.fastmcp.exceptions import ToolError

from bg_imap_mcp import server

EXPECTED_TOOLS = {"check_connection", "list_folders", "folder_status", "list_messages", "search_messages",
                  "read_message", "search_messages_advanced", "get_messages_batch", "get_message_headers",
                  "get_mailbox_inventory", "get_mailbox_changes"}


def test_tools_are_registered_read_only():
    tools = anyio.run(server.mcp.list_tools)
    assert {t.name for t in tools} == EXPECTED_TOOLS
    for tool in tools:
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.destructiveHint is False


def test_config_error_is_tool_error_without_secrets(monkeypatch):
    monkeypatch.setenv("IMAP_HOST", "")
    monkeypatch.setenv("IMAP_PASSWORD", "hunter2")
    with pytest.raises(ToolError) as exc:
        anyio.run(server.mcp.call_tool, "folder_status", {})
    assert "required" in str(exc.value) and "hunter2" not in str(exc.value)


def test_default_folder_from_settings(monkeypatch):
    for k, v in {"IMAP_HOST": "h", "IMAP_USERNAME": "u", "IMAP_PASSWORD": "p",
                 "IMAP_DEFAULT_FOLDER": "Archive"}.items():
        monkeypatch.setenv(k, v)
    seen = {}
    monkeypatch.setattr(server.IMAPClient, "status", lambda self, folder: seen.setdefault("folder", folder))
    anyio.run(server.mcp.call_tool, "folder_status", {})
    assert seen["folder"] == "Archive"


def test_new_tool_schemas():
    tools = {t.name: t for t in anyio.run(server.mcp.list_tools)}
    adv = tools["search_messages_advanced"].inputSchema["properties"]
    assert {"date_from", "date_to", "sender", "recipient", "seen", "cursor", "sort"} <= set(adv)
    assert tools["get_messages_batch"].inputSchema["required"] == ["uids"]
    assert "checkpoint" in tools["get_mailbox_changes"].inputSchema["properties"]
