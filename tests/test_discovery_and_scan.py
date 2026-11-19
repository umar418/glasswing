import json
import socket

import pytest

from glasswing.report.json_report import render_json
from glasswing.scanner import run_scan
from glasswing.summary.template import build_template_summary


def test_scan_finds_fixture_findings(fake_home):
    result = run_scan()
    rule_ids = {f.rule_id for f in result.findings}
    assert "FS-ROOT-SCOPE" in rule_ids
    assert "SHELL-BLANKET-ALLOW" in rule_ids
    assert "MCP-UNPINNED-UNKNOWN-PUBLISHER" in rule_ids
    assert "SECRET-PLAINTEXT-CONFIG" in rule_ids
    assert result.exposure_level in {"High", "Critical"}


def test_scan_never_crashes_on_malformed_config(fake_home, tmp_path):
    bad_dir = fake_home / "Library" / "Application Support" / "Claude"
    (bad_dir / "claude_desktop_config.json").write_text("{not valid json", encoding="utf-8")
    result = run_scan()  # must not raise
    assert any("claude_desktop_config.json" in w for w in result.warnings)


def test_report_json_never_contains_raw_secret(fake_home):
    result = run_scan()
    template_summary = build_template_summary(result)
    rendered = render_json(result, ai_summary_markdown=None, template_summary=template_summary)
    assert "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE" not in rendered
    data = json.loads(rendered)
    assert data["exposure_level"] in {"High", "Critical"}


def test_no_ai_scan_makes_zero_network_calls(fake_home, monkeypatch):
    def _blocked(*args, **kwargs):
        raise AssertionError("no network call should happen during a --no-ai scan")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    result = run_scan()  # discovery + rules only, no AI call
    build_template_summary(result)  # deterministic, no network
