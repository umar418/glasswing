from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """A fake home directory with a Claude Desktop config (filesystem server
    scoped to '/', plus a secret-looking token) and a Claude Code settings
    file with a blanket Bash(*) allow rule.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    claude_dir = tmp_path / "Library" / "Application Support" / "Claude"
    claude_dir.mkdir(parents=True)
    (claude_dir / "claude_desktop_config.json").write_text(
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
