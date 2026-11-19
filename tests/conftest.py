from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """A fake home directory with a Cursor MCP config (filesystem server
    scoped to '/', plus a secret-looking token) and a Claude Code settings
    file with a blanket Bash(*) allow rule. Cursor's ~/.cursor/mcp.json is
    used because it's the same path on every OS, unlike Claude Desktop's.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows expanduser reads this, not HOME
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir(parents=True)
    (cursor_dir / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs-everything": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                    },
                    "sketchy-remote": {
                        "command": "npx",
                        "args": ["-y", "some-random-unpinned-package"],
                        "env": {"API_KEY": "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"},
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    claude_code_dir = tmp_path / ".claude"
    claude_code_dir.mkdir(parents=True)
    (claude_code_dir / "settings.json").write_text(
        json.dumps({"permissions": {"allow": ["Bash(*)"], "deny": []}}),
        encoding="utf-8",
    )

    return tmp_path
