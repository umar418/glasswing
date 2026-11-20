"""The assistant plugins must stay consistent with the package they wrap."""
import json
import re
from pathlib import Path

import glasswing

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "glasswing"
SKILL = PLUGIN / "skills" / "glasswing-scan" / "SKILL.md"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_every_manifest_names_the_plugin_and_matches_the_package_version():
    for rel in ("plugin.json", ".claude-plugin/plugin.json", ".codex-plugin/plugin.json"):
        manifest = _json(PLUGIN / rel)
        assert manifest["name"] == "glasswing", rel
        assert manifest["version"] == glasswing.__version__, rel


def test_marketplaces_point_at_the_plugin_folder():
    claude = _json(ROOT / ".claude-plugin" / "marketplace.json")
    assert claude["plugins"][0]["source"] == "./plugins/glasswing" and claude["owner"]["name"]
    codex = _json(ROOT / ".agents" / "plugins" / "marketplace.json")
    assert codex["plugins"][0]["source"] == {"source": "local", "path": "./plugins/glasswing"}
    assert (ROOT / "plugins" / "glasswing").is_dir()


def test_skill_follows_the_agent_skills_format():
    text = SKILL.read_text(encoding="utf-8")
    front = re.match(r"^---\n(.*?)\n---\n", text, re.S).group(1)
    name = re.search(r"^name: (.+)$", front, re.M).group(1).strip()
    description = re.search(r"^description: (.+)$", front, re.M).group(1).strip()
    assert name == SKILL.parent.name and re.fullmatch(r"[a-z0-9-]{1,64}", name)
    assert 40 < len(description) <= 1024


def test_skill_runs_the_offline_read_only_command_and_uses_real_output_fields():
    text = SKILL.read_text(encoding="utf-8")
    assert "glasswing scan --no-ai --json" in text
    from glasswing.report.safe_view import safe_scan
    from glasswing.scanner import run_scan

    data = safe_scan(run_scan())
    for field in ("exposure_level", "findings", "apps", "not_covered"):
        assert f"`{field}`" in text and field in data
