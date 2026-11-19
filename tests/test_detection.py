"""Does Glasswing identify things correctly -- and stay quiet when it should?"""
import json

import pytest

from glasswing.analysis.capabilities import parse_launcher
from glasswing.analysis.rules import classify_permission, compute_exposure_level
from glasswing.discovery.paths import classify_scope

FS = "@modelcontextprotocol/server-filesystem"


def fs(*paths):
    return {"fs": {"command": "npx", "args": ["-y", FS, *paths]}}


# ---- filesystem scope --------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "~", "~/", "$HOME", "${HOME}", "$HOME/", "/Users", "/home", "/Users/alice", "/home/bob/",
                                  "C:\\", "C:/", "c:", "C:\\Users", "C:\\Users\\alice", "%USERPROFILE%", "D:\\"])
def test_broad_filesystem_scope_is_critical(home, path):
    home.cursor(fs(path))
    assert "FS-ROOT-SCOPE" in home.scan().rules, path


def test_own_home_folder_path_is_critical(home):
    home.cursor(fs(str(home.root)))
    assert "FS-ROOT-SCOPE" in home.scan().rules


@pytest.mark.parametrize("path", ["/Users/alice/projects/app", "~/code/site", "/srv/data", "./data", "C:\\Users\\alice\\code\\app",
                                  "/Users/alice/Documents/Clients/Acme", "/home", "~"])
def test_scope_classification_boundaries(path):
    broad = classify_scope(path) in ("disk", "all-users", "home")
    assert broad == (path in ("/home", "~"))


def test_project_folder_scope_is_not_flagged(home):
    home.cursor(fs("/Users/alice/projects/app", "~/code/site"))
    result = home.scan()
    assert not [r for r in result.rules if r.startswith("FS-")]
    assert result.data["exposure_level"] == "Low" or "MCP-UNPINNED-RECOGNISED" in result.rules


def test_one_broad_path_among_several_is_enough(home):
    home.cursor(fs("/Users/alice/projects/app", "~"))
    assert "FS-ROOT-SCOPE" in home.scan().rules


def test_credential_and_personal_folders(home):
    home.cursor({"a": fs("~/.ssh")["fs"], "b": fs("~/Documents")["fs"]})
    rules = home.scan().rules
    assert {"FS-CREDENTIAL-FOLDER", "FS-PERSONAL-FOLDER"} <= rules


def test_docker_bind_mount_of_root_is_critical(home):
    home.cursor({"fs": {"command": "docker", "args": ["run", "-i", "--rm", "-v", "/:/host", "mcp/filesystem", "/host"]}})
    assert "FS-ROOT-SCOPE" in home.scan().rules


def test_docker_mount_flag_form_and_any_image(home):
    home.cursor({"x": {"command": "docker", "args": ["run", "--rm", "--mount", "type=bind,source=/Users,target=/data", "someone/tool:1.2"]}})
    assert "FS-ROOT-SCOPE" in home.scan().rules


def test_docker_project_mount_is_fine(home):
    home.cursor({"fs": {"command": "docker", "args": ["run", "-i", "--rm", "-v", "/Users/alice/projects/app:/data:ro", "mcp/filesystem:1.0.2", "/data"]}})
    assert not home.scan().rules


# ---- launchers and version pinning -------------------------------------------

@pytest.mark.parametrize("command,args,package,pinned", [
    ("npx", ["-y", "some-pkg"], "some-pkg", False),
    ("npx", ["some-pkg"], "some-pkg", False),
    ("npx", ["-y", "some-pkg@1.2.3"], "some-pkg", True),
    ("npx", ["-y", "@scope/pkg@1.2.3"], "@scope/pkg", True),
    ("npx", ["-y", "@scope/pkg"], "@scope/pkg", False),
    ("npx", ["-y", "some-pkg@latest"], "some-pkg", False),
    ("npx", ["-y", "some-pkg@^1.2.0"], "some-pkg", False),
    ("npx", ["--yes", "--package", "real-pkg@2.0.0", "run-it"], "real-pkg", True),
    ("npx.cmd", ["-y", "some-pkg"], "some-pkg", False),
    ("/usr/local/bin/npx", ["-y", "some-pkg@0.4.1"], "some-pkg", True),
    ("bunx", ["some-pkg"], "some-pkg", False),
    ("pnpm", ["dlx", "some-pkg@3.1.0"], "some-pkg", True),
    ("uvx", ["some-pkg"], "some-pkg", False),
    ("uvx", ["some-pkg==1.0.0"], "some-pkg", True),
    ("uvx", ["some-pkg@1.0.0"], "some-pkg", True),
    ("uvx", ["--from", "real-pkg==2.1.0", "entry"], "real-pkg", True),
    ("uv", ["tool", "run", "some-pkg"], "some-pkg", False),
    ("pipx", ["run", "some-pkg==0.9.0"], "some-pkg", True),
    ("docker", ["run", "-i", "--rm", "-e", "A=b", "vendor/image:1.4"], "vendor/image", True),
    ("docker", ["run", "-i", "vendor/image"], "vendor/image", False),
    ("docker", ["run", "-i", "vendor/image:latest"], "vendor/image", False),
    ("docker", ["run", "-i", "vendor/image@sha256:abc123"], "vendor/image", True),
])
def test_launcher_parsing(command, args, package, pinned):
    info = parse_launcher(command, args)
    assert (info["package"], info["pinned"]) == (package, pinned)


@pytest.mark.parametrize("command,args", [("node", ["./server.js"]), ("python3", ["-m", "my_server"]), ("/opt/tool/bin/server", []), ("npx", ["./local-dir"])])
def test_local_programs_are_not_called_downloaded_packages(home, command, args):
    home.cursor({"a": {"command": command, "args": args}})
    result = home.scan()
    assert not [r for r in result.rules if r.startswith("MCP-UNPINNED")]
    assert result.server("a")["source"] == "a program or script on this computer"


def test_unpinned_unrecognised_is_high_recognised_is_low_pinned_is_silent(home):
    home.cursor({
        "u": {"command": "npx", "args": ["-y", "totally-unknown-pkg"]},
        "k": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]},
        "p": {"command": "npx", "args": ["-y", "totally-unknown-pkg@1.2.3"]},
    })
    result = home.scan()
    assert [d.split("'")[1] for f in result.findings("MCP-UNPINNED-UNRECOGNISED") for d in f["details"]] == ["u"]
    assert [d.split("'")[1] for f in result.findings("MCP-UNPINNED-RECOGNISED") for d in f["details"]] == ["k"]
    assert result.findings("MCP-UNPINNED-UNRECOGNISED")[0]["severity"] == "high"


def test_lookalike_package_name_is_not_treated_as_recognised(home):
    home.cursor({"a": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem-pro", "/"]}})
    result = home.scan()
    assert "MCP-UNPINNED-UNRECOGNISED" in result.rules
    assert result.server("a")["capability_basis"] != "recognised package"


# ---- capability claims -------------------------------------------------------

@pytest.mark.parametrize("name", ["lawsuit-notes", "driver-docs", "syntax-checker", "exec-summary", "researcher", "emailer-templates-doc",
                                  "classifier", "dbt-docs-viewer-x", "terminally-ill-care", "webinar", "calendaring"])
def test_capability_is_not_guessed_from_substrings(home, name):
    home.cursor({name: {"command": "node", "args": ["./local.js"]}})
    assert home.scan().server(name)["capability"] == "unknown"


def test_guesses_are_labelled_as_guesses(home):
    home.cursor({"my-postgres": {"command": "node", "args": ["./x.js"]}, "fs": {"command": "npx", "args": ["-y", FS + "@1.0.0", "/tmp/x"]}})
    result = home.scan()
    assert result.server("my-postgres")["capability_basis"] == "guessed from its name"
    assert result.server("fs")["capability_basis"] == "recognised package"


# ---- remote servers ----------------------------------------------------------

def test_remote_server_shapes_across_apps(home):
    home.cursor({"c": {"url": "https://one.example.net/mcp"}})
    home.write("code/p/.vscode/mcp.json", {"servers": {"v": {"type": "http", "url": "https://two.example.net/mcp"}}})
    home.write(".codeium/windsurf/mcp_config.json", {"mcpServers": {"w": {"serverUrl": "https://three.example.net/mcp"}}})
    home.write(".gemini/settings.json", {"mcpServers": {"g": {"httpUrl": "https://four.example.net/mcp", "trust": True}}})
    home.write(".codex/config.toml", '[mcp_servers.x]\nurl = "https://five.example.net/mcp"\n')
    home.write(".continue/config.yaml", "mcpServers:\n  - name: k\n    type: sse\n    url: https://six.example.net/sse\n")
    home.write(".claude.json", {"mcpServers": {"u": {"type": "http", "url": "https://seven.example.net/m"}},
                                "projects": {"/nope": {"mcpServers": {"h": {"type": "sse", "url": "https://eight.example.net/m"}}}}})
    result = home.scan()
    hosts = {s["remote_host"] for a in result.data["apps"] for s in a["servers"]}
    assert hosts == {f"{n}.example.net" for n in ("one", "two", "three", "four", "five", "six", "seven", "eight")}
    assert sum(f["count"] for f in result.findings("MCP-REMOTE-UNRECOGNISED")) == 8
    assert "MCP-SERVER-TRUST-BYPASS" in result.rules


def test_mcp_remote_wrapper_is_reported_by_its_real_destination(home):
    home.cursor({"m": {"command": "npx", "args": ["-y", "mcp-remote", "https://service.example.net/mcp", "--transport", "http-only"]}})
    result = home.scan()
    assert result.server("m")["remote_host"] == "service.example.net"
    assert "MCP-REMOTE-UNRECOGNISED" in result.rules
    assert "MCP-UNPINNED-RECOGNISED" in result.rules and "MCP-UNPINNED-UNRECOGNISED" not in result.rules


@pytest.mark.parametrize("url,rule", [
    ("https://api.githubcopilot.com/mcp/", None),
    ("https://mcp.notion.com/mcp", None),
    ("https://githubcopilot.com.evil.example.net/mcp", "MCP-REMOTE-UNRECOGNISED"),
    ("https://notgithub.com/mcp", "MCP-REMOTE-UNRECOGNISED"),
    ("http://remote.example.net/mcp", "MCP-REMOTE-INSECURE-HTTP"),
    ("http://localhost:3000/mcp", None),
    ("http://127.0.0.1:8080/sse", None),
])
def test_remote_domain_recognition(home, url, rule):
    home.cursor({"r": {"url": url}})
    rules = home.scan().rules
    assert (rule in rules) if rule else (not rules), (url, rules)


# ---- Claude Code permissions -------------------------------------------------

@pytest.mark.parametrize("rule,expected", [
    ("Bash", "SHELL-BLANKET-ALLOW"), ("Bash(*)", "SHELL-BLANKET-ALLOW"), ("Bash(:*)", "SHELL-BLANKET-ALLOW"), ("*", "SHELL-BLANKET-ALLOW"),
    ("Bash(python3:*)", "SHELL-INTERPRETER-WILDCARD"), ("Bash(python *)", "SHELL-INTERPRETER-WILDCARD"), ("Bash(sudo:*)", "SHELL-INTERPRETER-WILDCARD"),
    ("Bash(bash:*)", "SHELL-INTERPRETER-WILDCARD"), ("Bash(node:*)", "SHELL-INTERPRETER-WILDCARD"), ("Bash(npx:*)", "SHELL-INTERPRETER-WILDCARD"),
    ("Bash(curl:*)", "SHELL-NETWORK-WILDCARD"), ("Bash(wget *)", "SHELL-NETWORK-WILDCARD"), ("Bash(rm:*)", "SHELL-DESTRUCTIVE-WILDCARD"),
    ("Edit(//**)", "PERMISSIONS-BROAD-WRITE"), ("Write(~/**)", "PERMISSIONS-BROAD-WRITE"), ("Edit(//Users/alice/**)", "PERMISSIONS-BROAD-WRITE"),
    ("Read(//**)", "PERMISSIONS-BROAD-READ"), ("Read(~/**)", "PERMISSIONS-BROAD-READ"), ("Read(~/.ssh/**)", "PERMISSIONS-BROAD-READ"),
    # narrow or project-relative rules: must stay silent
    ("Bash(npm test:*)", None), ("Bash(npm run build)", None), ("Bash(npx next build:*)", None), ("Bash(python3 scripts/report.py)", None),
    ("Bash(git status)", None), ("Bash(curl -s https://api.example.com/health)", None), ("Bash(pythonista-tool:*)", None),
    ("Bash(rmdir-safe:*)", None), ("Bash(ls:*)", None), ("Bash(git commit:*)", None),
    ("Edit(/src/**)", None), ("Edit(**)", None), ("Write(/)", None), ("Edit(docs/*.md)", None), ("Read(~/projects/**)", None),
    ("Read(//Users/alice/projects/app/**)", None), ("Edit", None), ("Read", None), ("WebFetch(domain:example.com)", None),
    ("mcp__github__create_issue", None), ("WebSearch", None),
])
def test_permission_rule_classification(rule, expected):
    hit = classify_permission(rule)
    assert (hit[0] if hit else None) == expected, rule


def test_only_allow_rules_are_risks(home):
    home.claude_settings({"permissions": {"deny": ["Bash(*)", "Bash(python3:*)"], "ask": ["Bash(sudo:*)", "Edit(//**)"]}})
    assert home.scan().data["findings"] == []


def test_deny_all_shell_cancels_shell_allows_in_same_file(home):
    home.claude_settings({"permissions": {"allow": ["Bash(python3:*)"], "deny": ["Bash"]}})
    assert home.scan().data["findings"] == []


def test_bypass_mode_and_related_settings(home):
    home.claude_settings({"permissions": {"defaultMode": "bypassPermissions", "additionalDirectories": ["~", "/tmp/x"]}, "enableAllProjectMcpServers": True})
    assert {"PERMISSION-PROMPTS-BYPASSED", "PERMISSIONS-BROAD-DIRECTORIES", "MCP-PROJECT-SERVERS-AUTO-APPROVED"} <= home.scan().rules


def test_safe_modes_are_not_flagged(home):
    for mode in ("default", "plan", "acceptEdits", "dontAsk"):
        home.claude_settings({"permissions": {"defaultMode": mode}, "enableAllProjectMcpServers": False})
        assert home.scan().data["findings"] == [], mode


def test_bypass_mode_in_a_project_file_is_not_reported_because_it_has_no_effect(home):
    home.write("code/p/.claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions"}})
    assert home.scan().data["findings"] == []


def test_codex_sandbox_settings(home):
    home.write(".codex/config.toml", 'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n')
    assert "CODEX-NO-SANDBOX-NO-APPROVAL" in home.scan().rules
    home.write(".codex/config.toml", 'sandbox_mode = "danger-full-access"\napproval_policy = "on-request"\n')
    assert home.scan().rules == {"CODEX-SANDBOX-DISABLED"}
    home.write(".codex/config.toml", 'sandbox_mode = "workspace-write"\napproval_policy = "never"\n')
    assert home.scan().rules == set()


# ---- de-duplication and scoring ----------------------------------------------

def test_identical_config_in_many_worktrees_is_reported_once(home):
    for i in range(8):
        home.write(f"code/wt{i}/.mcp.json", {"mcpServers": {"same": {"command": "npx", "args": ["-y", "zzz-unknown"]}}})
    result = home.scan()
    found = result.findings("MCP-UNPINNED-UNRECOGNISED")
    assert len(found) == 1 and found[0]["count"] == 1
    assert sum(len(a["servers"]) for a in result.data["apps"]) == 1
    assert next(a for a in result.data["apps"] if a["app_id"] == "claude-code")["identical_copy_count"] == 7


def test_same_server_in_differing_files_is_listed_once(home):
    for i in range(3):
        home.write(f"code/p{i}/.mcp.json", {"mcpServers": {"same": {"command": "npx", "args": ["-y", "zzz-unknown"]}, f"own{i}": {"command": "node", "args": ["a.js"]}}})
    result = home.scan()
    assert result.server("same")["also_defined_in_count"] == 2
    assert len(result.findings("MCP-UNPINNED-UNRECOGNISED")) == 1


def test_home_level_settings_file_is_not_read_twice(home):
    home.claude_settings({"permissions": {"allow": ["Bash(*)"]}})
    home.write(".claude.json", {"projects": {str(home.root): {}}})
    result = home.scan()
    assert [f["count"] for f in result.findings("SHELL-BLANKET-ALLOW")] == [1]


def test_level_is_the_worst_finding_and_never_inflated_by_count(home):
    home.cursor({f"s{i}": {"command": "npx", "args": ["-y", f"unknown-{i}"]} for i in range(12)})
    result = home.scan()
    assert result.data["exposure_level"] == "High"
    assert result.data["severity_counts"] == {"high": 1} and result.data["findings"][0]["count"] == 12
    assert compute_exposure_level([]) == "Low"


def test_findings_are_ordered_most_serious_first(home):
    home.cursor({**fs("/"), "u": {"command": "npx", "args": ["-y", "unk"]}, "r": {"url": "https://x.example.net/m"}})
    home.claude_settings({"permissions": {"allow": ["Bash(curl:*)"]}})
    ranks = [{"critical": 4, "high": 3, "medium": 2, "low": 1}[f["severity"]] for f in home.scan().data["findings"]]
    assert ranks == sorted(ranks, reverse=True) and ranks[0] == 4


def test_every_finding_has_plain_text_and_a_known_rule(home):
    from glasswing.discovery.registry import load_rules

    home.cursor({**fs("/"), "u": {"command": "npx", "args": ["-y", "unk"]}})
    for f in home.scan().data["findings"]:
        assert f["rule_id"] in load_rules() and len(f["explanation"]) > 40 and len(f["fix"]) > 20


def test_registry_files_are_well_formed():
    from glasswing.discovery.registry import load_apps, load_cloud_checklist, load_known, load_rules

    assert all({"id", "name", "configs", "source"} <= set(a) for a in load_apps())
    assert all(r["severity"] in ("info", "low", "medium", "high", "critical") for r in load_rules().values())
    assert all(item.get("url") or item.get("where") for item in load_cloud_checklist())
    assert all(isinstance(v, str) for v in load_known()["packages"].values())


def test_same_issue_in_several_places_is_one_row_listing_each_place(home):
    home.cursor({"u1": {"command": "npx", "args": ["-y", "unknown-a"]}, "u2": {"command": "npx", "args": ["-y", "unknown-b"]}})
    home.write("code/p1/.claude/settings.local.json", {"permissions": {"allow": ["Bash(python3:*)"]}})
    home.write("code/p2/.claude/settings.local.json", {"permissions": {"allow": ["Bash(python3:*)", "Bash(ls:*)"]}})
    result = home.scan()
    (unpinned,) = result.findings("MCP-UNPINNED-UNRECOGNISED")
    assert unpinned["count"] == 2 and unpinned["subject"] == "Cursor" and len(unpinned["details"]) == 2
    (interp,) = result.findings("SHELL-INTERPRETER-WILDCARD")
    assert interp["count"] == 2 and all("settings.local.json" in d for d in interp["details"])
