"""Reads AI-app config files (per the apps.yaml registry) into AppInventory
objects. Never raises on a missing/unreadable/malformed file -- records a
warning on the inventory and moves on (fail soft).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from glasswing.analysis.models import AppInventory, McpServer, PermissionRule
from glasswing.discovery.paths import current_os, expand_path
from glasswing.parsers import secrets as secrets_mod

try:
    import tomllib  # Python >= 3.11
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


def _load_structured(path: Path, fmt: str) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace")
    if fmt == "json":
        return json.loads(text)
    if fmt == "yaml":
        return yaml.safe_load(text)
    if fmt == "toml":
        return tomllib.loads(text)
    raise ValueError(f"unsupported config format: {fmt}")


def _is_remote_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


def _build_server(name: str, raw: dict, app_id: str, app_name: str, config_path: str) -> McpServer:
    command = raw.get("command")
    args = raw.get("args") or []
    url = raw.get("url") or raw.get("serverUrl")
    env = raw.get("env") or {}
    transport = raw.get("transport") or ("http" if url else "stdio")
    if url and not raw.get("transport"):
        transport = "sse" if "sse" in str(url) else "http"

    server = McpServer(
        name=name,
        app_id=app_id,
        app_name=app_name,
        config_path=config_path,
        command=command,
        args=list(args) if isinstance(args, list) else [],
        url=url,
        transport=transport,
        env=dict(env) if isinstance(env, dict) else {},
        raw=raw,
    )
    return server


def _extract_servers(mcp_block: dict, app_id: str, app_name: str, config_path: str) -> list[McpServer]:
    servers = []
    if not isinstance(mcp_block, dict):
        return servers
    for name, raw in mcp_block.items():
        if isinstance(raw, dict):
            servers.append(_build_server(name, raw, app_id, app_name, config_path))
    return servers


def _extract_permissions(perm_block: Any, app_id: str, app_name: str, config_path: str) -> list[PermissionRule]:
    rules: list[PermissionRule] = []
    if not isinstance(perm_block, dict):
        return rules
    for kind in ("allow", "deny"):
        for rule in perm_block.get(kind, []) or []:
            if not isinstance(rule, str):
                continue
            broad = _is_broad_permission(rule)
            rules.append(
                PermissionRule(app_id=app_id, app_name=app_name, config_path=config_path, rule=rule, kind=kind, broad=broad)
            )
    return rules


def _is_broad_permission(rule: str) -> bool:
    lowered = rule.lower()
    broad_markers = ["bash(*)", "*(*)", "write(/*)", "write(~)", "write(/)", "bypasspermissions"]
    if any(marker in lowered for marker in broad_markers):
        return True
    if lowered.strip() in {"bash", "*"}:
        return True
    return False


def resolve_config_candidates(app: dict, cfg: dict, project_dirs: list[Path]) -> list[Path]:
    """Return concrete file paths this config entry could live at."""
    raw_path = cfg["path"]
    if cfg.get("project_relative"):
        candidates = []
        for pdir in project_dirs:
            candidates.append(pdir / raw_path)
        return candidates
    return [expand_path(raw_path)]


def parse_app(app: dict, project_dirs: list[Path]) -> AppInventory:
    inv = AppInventory(app_id=app["id"], app_name=app["name"], found=False)
    this_os = current_os()

    for cfg in app.get("configs", []):
        cfg_os = cfg.get("os", "any")
        if cfg_os != "any" and cfg_os != this_os:
            continue

        for path in resolve_config_candidates(app, cfg, project_dirs):
            if not path.is_file():
                continue
            try:
                data = _load_structured(path, cfg["format"])
            except Exception as exc:  # fail soft, never crash the scan
                inv.errors.append(f"couldn't read {path}: {exc}")
                continue

            inv.found = True
            inv.config_paths.append(str(path))

            if not isinstance(data, dict):
                continue

            mcp_key = cfg.get("mcp_key")
            if mcp_key:
                block = data.get(mcp_key, {})
                inv.servers.extend(_extract_servers(block, app["id"], app["name"], str(path)))

            perm_key = cfg.get("permissions_key")
            if perm_key:
                inv.permissions.extend(_extract_permissions(data.get(perm_key), app["id"], app["name"], str(path)))

            try:
                inv.secrets.extend(secrets_mod.scan_mapping(data, str(path)))
            except Exception as exc:  # fail soft
                inv.errors.append(f"secret scan failed on {path}: {exc}")

    return inv
