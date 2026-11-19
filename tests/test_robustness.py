"""Hostile, malformed and oversized input must never crash, hang, or inject."""
import json
import os
import socket
import time

import pytest

FS_ROOT = {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]}}


@pytest.mark.parametrize("content", [
    [], "hi", None, 7,
    {"mcpServers": ["a"]}, {"mcpServers": None}, {"mcpServers": "x"},
    {"mcpServers": {"a": "npx"}}, {"mcpServers": {"a": None}}, {"mcpServers": {"a": []}},
    {"mcpServers": {"a": {"command": "npx", "args": "-y pkg"}}},
    {"mcpServers": {"a": {"command": "npx", "args": [1, None, {"x": 1}, ["y"], True]}}},
    {"mcpServers": {"a": {"command": ["npx", "-y", 3], "args": []}}},
    {"mcpServers": {"a": {"command": 5, "args": {"k": "v"}}}},
    {"mcpServers": {"a": {"command": "x", "env": {"A": 1, "B": None, "C": {"d": 1}}, "headers": [1]}}},
    {"mcpServers": {"a": {"url": 5}}}, {"mcpServers": {"a": {"url": "not a url"}}}, {"mcpServers": {"a": {"url": "https://[bad"}}},
    {"mcpServers": {"": {}}}, {"mcpServers": {"a": {}}},
])
def test_malformed_structures_never_crash(home, content):
    home.write(".cursor/mcp.json", json.dumps(content))
    result = home.scan()
    json.loads(result.files["report.json"])


@pytest.mark.parametrize("raw", [b"", b"   \n", os.urandom(4096), b"{not json", b"\x00\x01\x02", "[" * 3000 + "]" * 3000])
def test_unparseable_files_are_skipped_with_a_note(home, raw):
    home.write(".cursor/mcp.json", raw if isinstance(raw, bytes) else raw.encode())
    home.scan()


def test_bad_file_is_reported_not_hidden(home):
    home.write(".cursor/mcp.json", "{not json")
    assert any("mcp.json" in w for w in home.scan().data["warnings"])


def test_utf8_bom_file_is_still_read(home):
    home.write(".cursor/mcp.json", b"\xef\xbb\xbf" + json.dumps({"mcpServers": FS_ROOT}).encode())
    assert "FS-ROOT-SCOPE" in home.scan().rules


def test_utf16_file_is_still_read(home):
    home.write(".cursor/mcp.json", json.dumps({"mcpServers": FS_ROOT}).encode("utf-16"))
    assert "FS-ROOT-SCOPE" in home.scan().rules


def test_json_with_comments_and_trailing_commas_is_read(home):
    home.write(".cursor/mcp.json", '{\n // note with "quotes" and // slashes\n "mcpServers": { /* block */\n  "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],},\n },\n}')
    assert "FS-ROOT-SCOPE" in home.scan().rules


def test_comment_markers_inside_strings_are_preserved(home):
    home.cursor({"r": {"url": "https://unknown-service.example.net/a//b/*c*/d"}})
    assert home.scan().server("r")["remote_host"] == "unknown-service.example.net"


def test_config_path_that_is_a_directory(home):
    (home.root / ".cursor" / "mcp.json").mkdir(parents=True)
    home.scan()


def test_oversized_file_is_skipped_quickly(home):
    home.write(".cursor/mcp.json", json.dumps({"mcpServers": {}, "junk": "Ab1/" * 2_000_000}))
    start = time.time()
    result = home.scan()
    assert time.time() - start < 10
    assert any("too large" in w for w in result.data["warnings"])


def test_yaml_alias_bomb_does_not_hang(home):
    lines = ['a0: &a0 ["x","y","z","w","v","u","t","s","r","q"]']
    lines += [f"a{i}: &a{i} [" + ",".join([f"*a{i - 1}"] * 10) + "]" for i in range(1, 13)]
    home.write(".continue/config.yaml", "\n".join(lines + ["mcpServers: []"]))
    start = time.time()
    home.scan()
    assert time.time() - start < 10


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlink_loop_in_project_folder(home):
    proj = home.root / "code" / "proj"
    proj.mkdir(parents=True)
    os.symlink(home.root / "code", proj / "loop")
    home.write("code/proj/.mcp.json", {"mcpServers": FS_ROOT})
    assert len(home.scan().findings("FS-ROOT-SCOPE")) == 1


def test_many_servers_in_one_file(home):
    home.cursor({f"s{i}": {"command": "npx", "args": ["-y", f"pkg-{i}"]} for i in range(3000)})
    start = time.time()
    home.scan()
    assert time.time() - start < 30


# ---- injection ---------------------------------------------------------------

XSS = '<script>alert(1)</script>'
ATTR = '"><img src=x onerror=alert(2)>'


def test_html_in_config_values_is_escaped_in_report(home):
    home.cursor({XSS: {"command": "npx", "args": ["-y", "evil-pkg", ATTR], "env": {XSS: "v"}}, "r": {"url": f"https://x.example.net/{XSS}"}})
    home.claude_settings({"permissions": {"allow": [f"Bash(python3:*){XSS}", "Bash(python3:*)"]}})
    if os.name != "nt":  # "<" is not allowed in Windows file names
        home.write("code/<b>bold<b>/.mcp.json", {"mcpServers": {"a" + ATTR: {"command": "npx", "args": ["-y", "p"]}}})
    html = home.scan().files["report.html"]
    assert "<script>alert(1)" not in html
    assert "<img src=x" not in html
    assert "<b>bold" not in html
    assert html.count("<script>") == 1  # only the report's own script


def test_html_in_ai_summary_is_escaped(home):
    from glasswing.report import render_all
    from glasswing.scanner import run_scan

    _, _, files = render_all(run_scan(), ai_text=f"## Hi\n{XSS}\n- [x](javascript:alert(1)) **bold** {ATTR}")
    assert "<script>alert(1)" not in files["report.html"]
    assert "<img src=x" not in files["report.html"]
    assert "<strong>bold</strong>" in files["report.html"]


def test_terminal_markup_in_names_does_not_crash_cli(home, monkeypatch):
    from typer.testing import CliRunner

    from glasswing.cli import app

    home.cursor({"[/bold] oops [red": {"command": "npx", "args": ["-y", "evil-pkg"]}, "[link=file:///etc/passwd]x": {"command": "npx", "args": ["-y", "p2"]}})
    result = CliRunner().invoke(app, ["scan", "--no-ai", "--no-open-report"])
    assert result.exit_code == 0, result.output


# ---- CLI contract ------------------------------------------------------------


def test_json_mode_prints_only_json_and_writes_no_files(home):
    from typer.testing import CliRunner

    from glasswing.cli import app

    home.cursor(FS_ROOT)
    try:
        runner = CliRunner(mix_stderr=False)
    except TypeError:  # newer click keeps the streams separate by default
        runner = CliRunner()
    result = runner.invoke(app, ["scan", "--json", "--no-ai"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["exposure_level"] == "Critical"
    assert not (home.root / ".glasswing" / "reports").exists()


def test_scan_writes_three_report_files(home):
    from typer.testing import CliRunner

    from glasswing.cli import app

    home.cursor(FS_ROOT)
    result = CliRunner().invoke(app, ["scan", "--no-ai", "--no-open-report"])
    assert result.exit_code == 0
    folders = list((home.root / ".glasswing" / "reports").iterdir())
    assert sorted(p.name for p in folders[0].iterdir()) == ["report.html", "report.json", "summary.md"]
    assert "CRITICAL" in result.output.split("Top findings:")[1].splitlines()[1]


def test_offline_scan_opens_no_network_connection(home, monkeypatch):
    from typer.testing import CliRunner

    from glasswing.cli import app

    def blocked(*a, **k):
        raise AssertionError("network access during --no-ai scan")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    home.cursor({**FS_ROOT, "r": {"url": "https://unknown.example.net/mcp"}})
    assert CliRunner().invoke(app, ["scan", "--no-ai", "--no-open-report"]).exit_code == 0


def test_scan_changes_no_config_file(home):
    path = home.cursor(FS_ROOT)
    settings = home.claude_settings({"permissions": {"allow": ["Bash(*)"]}})
    before = (path.read_bytes(), path.stat().st_mtime_ns, settings.read_bytes(), settings.stat().st_mtime_ns)
    home.scan()
    assert before == (path.read_bytes(), path.stat().st_mtime_ns, settings.read_bytes(), settings.stat().st_mtime_ns)


def test_empty_machine_reports_low_and_says_nothing_was_found(home):
    result = home.scan()
    assert result.data["exposure_level"] == "Low"
    assert result.data["findings"] == []
    assert "did not find settings" in result.summary["overall_reason"]


def test_unimplemented_commands_say_so_and_fail(home):
    from typer.testing import CliRunner

    from glasswing.cli import app

    for cmd in (["history"], ["track", "enable"], ["track", "status"]):
        assert CliRunner().invoke(app, cmd).exit_code == 1
