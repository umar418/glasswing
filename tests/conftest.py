from __future__ import annotations

import json
from pathlib import Path

import pytest

from glasswing.parsers import secrets as sec

# Fake credentials with realistic shapes. Assembled at runtime so that no
# key-shaped literal sits in the repository for secret scanners to flag.
_BODY = "Qm7xR2kLp9ZtVw4YbN8cJ5hD1sFg6AeU3oTiXy0PqWzMvBnKr"
ANTHROPIC_KEY = "sk-" + "ant-" + "api03-" + _BODY
OPENAI_KEY = "sk-" + "proj-" + _BODY[::-1]
OPAQUE_TOKEN = "u7Hq2LmXz9" + _BODY[10:40]


class Home:
    def __init__(self, root: Path):
        self.root = root

    def write(self, rel: str, content, mode: str = "w") -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if not isinstance(content, (str, bytes)):
            content = json.dumps(content)
        with open(path, "wb" if isinstance(content, bytes) else "w") as f:
            f.write(content)
        return path

    def cursor(self, servers) -> Path:
        """Cursor's ~/.cursor/mcp.json has the same path on every OS."""
        return self.write(".cursor/mcp.json", {"mcpServers": servers})

    def claude_settings(self, settings: dict) -> Path:
        return self.write(".claude/settings.json", settings)

    def scan(self):
        from glasswing.report import render_all
        from glasswing.scanner import run_scan

        result = run_scan()
        data, summary, files = render_all(result)
        return Result(result, data, summary, files)


class Result:
    def __init__(self, scan, data, summary, files):
        self.scan, self.data, self.summary, self.files = scan, data, summary, files
        self.everything = "\n".join(files.values())

    @property
    def rules(self) -> set[str]:
        return {f["rule_id"] for f in self.data["findings"]}

    def findings(self, rule_id: str) -> list[dict]:
        return [f for f in self.data["findings"] if f["rule_id"] == rule_id]

    def server(self, name: str) -> dict:
        return next(s for a in self.data["apps"] for s in a["servers"] if s["name"] == name)


@pytest.fixture
def home(tmp_path, monkeypatch) -> Home:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows resolves ~ from this
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    sec.redact_text.cache_clear()
    return Home(tmp_path)
