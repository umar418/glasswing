from __future__ import annotations

import json
from pathlib import Path

from glasswing.analysis.models import AppInventory
from glasswing.discovery import paths as paths_mod
from glasswing.discovery.registry import load_apps
from glasswing.parsers.config_parser import parse_app


def _claude_code_known_projects() -> list[Path]:
    """Claude Code keeps a list of project paths it has opened in ~/.claude.json."""
    claude_json = paths_mod.expand_path("~/.claude.json")
    if not claude_json.is_file():
        return []
    try:
        data = json.loads(claude_json.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    projects = data.get("projects", {})
    if not isinstance(projects, dict):
        return []
    out = []
    for key in projects.keys():
        p = Path(key).expanduser()
        if p.is_dir():
            out.append(p)
    return out


def discover_apps(extra_roots: list[str] | None = None) -> list[AppInventory]:
    """Find every known AI app's config(s) and parse what's present.

    Never raises: unreadable/missing files become warnings on the
    corresponding AppInventory, per the "fail soft" principle.
    """
    roots = paths_mod.iter_project_roots(extra_roots)
    project_dirs = paths_mod.find_project_dirs(roots)
    project_dirs.extend(_claude_code_known_projects())
    # de-dupe while preserving order
    seen: set[str] = set()
    unique_dirs = []
    for d in project_dirs:
        key = str(d.resolve()) if d.exists() else str(d)
        if key not in seen:
            seen.add(key)
            unique_dirs.append(d)

    inventories = []
    for app in load_apps():
        inventories.append(parse_app(app, unique_dirs))
    return inventories
