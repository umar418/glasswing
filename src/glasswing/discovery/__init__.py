from __future__ import annotations

import json
from pathlib import Path

from glasswing.analysis.models import AppInventory
from glasswing.discovery import paths as paths_mod
from glasswing.discovery.registry import load_apps
from glasswing.parsers.config_parser import ConfigError, load_config_file, parse_app


def _claude_code_known_projects() -> list[Path]:
    """Claude Code records every project folder it has opened in ~/.claude.json."""
    claude_json = paths_mod.expand_path("~/.claude.json")
    try:
        if not claude_json.is_file():
            return []
        data, _ = load_config_file(claude_json, "json")
    except (ConfigError, OSError):
        return []
    projects = data.get("projects") if isinstance(data, dict) else None
    if not isinstance(projects, dict):
        return []
    out = []
    for key in list(projects.keys())[:5000]:
        try:
            p = Path(key).expanduser()
            if p.is_dir():
                out.append(p)
        except (OSError, ValueError, RuntimeError):
            continue
    return out


def discover_apps(extra_roots: list[str] | None = None) -> list[AppInventory]:
    """Find and parse every known AI app's config. Never raises."""
    roots = paths_mod.iter_project_roots(extra_roots)
    project_dirs = paths_mod.find_project_dirs(roots)
    project_dirs.extend(_claude_code_known_projects())
    home = paths_mod.home_dir()
    seen: set[str] = set()
    unique: list[Path] = []
    for d in project_dirs:
        try:
            key = str(d.resolve())
        except OSError:
            continue
        if key not in seen:
            seen.add(key)
            unique.append(d)

    inventories = []
    for app in load_apps():
        try:
            inventories.append(parse_app(app, unique))
        except Exception as exc:  # one app's parser failing must not hide the others
            inv = AppInventory(app_id=app["id"], app_name=app["name"], found=False)
            inv.errors.append(f"couldn't inspect this app: {exc.__class__.__name__}")
            inventories.append(inv)
    return inventories
