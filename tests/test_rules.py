from glasswing.analysis.capabilities import analyze_server
from glasswing.analysis.models import AppInventory, McpServer, PermissionRule
from glasswing.analysis.rules import compute_exposure_level, evaluate


def _fs_server(path: str) -> McpServer:
    server = McpServer(
        name="fs",
        app_id="claude-desktop",
        app_name="Claude Desktop",
        config_path="/fake/config.json",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", path],
    )
    return analyze_server(server)


def test_root_scope_filesystem_server_flags_critical():
    app = AppInventory(app_id="claude-desktop", app_name="Claude Desktop", found=True, servers=[_fs_server("/")])
    findings = evaluate([app])
    assert any(f.rule_id == "FS-ROOT-SCOPE" and f.severity == "critical" for f in findings)


def test_scoped_filesystem_server_does_not_flag_root_scope():
    app = AppInventory(
        app_id="claude-desktop", app_name="Claude Desktop", found=True, servers=[_fs_server("/Users/alice/projects/app")]
    )
    findings = evaluate([app])
    assert not any(f.rule_id == "FS-ROOT-SCOPE" for f in findings)


def test_unpinned_npx_server_flagged_high():
    server = McpServer(
        name="sketchy",
        app_id="claude-desktop",
        app_name="Claude Desktop",
        config_path="/fake/config.json",
        command="npx",
        args=["-y", "totally-unknown-package"],
    )
    analyze_server(server)
    app = AppInventory(app_id="claude-desktop", app_name="Claude Desktop", found=True, servers=[server])
    findings = evaluate([app])
    assert any(f.rule_id == "MCP-UNPINNED-UNKNOWN-PUBLISHER" for f in findings)


def test_blanket_bash_allow_flagged_critical():
    app = AppInventory(
        app_id="claude-code",
        app_name="Claude Code",
        found=True,
        permissions=[
            PermissionRule(
                app_id="claude-code", app_name="Claude Code", config_path="/fake/settings.json", rule="Bash(*)", kind="allow", broad=True
            )
        ],
    )
    findings = evaluate([app])
    assert any(f.rule_id == "SHELL-BLANKET-ALLOW" and f.severity == "critical" for f in findings)


def test_compute_exposure_level_empty_is_low():
    assert compute_exposure_level([]) == "Low"


def test_compute_exposure_level_scales_with_severity():
    app = AppInventory(app_id="claude-desktop", app_name="Claude Desktop", found=True, servers=[_fs_server("/")])
    findings = evaluate([app])
    assert compute_exposure_level(findings) == "Critical"
