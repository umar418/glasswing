"""Loaders for the data-driven registry files bundled with glasswing."""
from __future__ import annotations

from functools import lru_cache
from importlib import resources

import yaml


def _load_yaml(filename: str):
    raw = resources.files("glasswing.registry").joinpath(filename).read_text()
    return yaml.safe_load(raw) or []


@lru_cache(maxsize=1)
def load_apps() -> list[dict]:
    return _load_yaml("apps.yaml")


@lru_cache(maxsize=1)
def load_rules() -> dict[str, dict]:
    return {r["id"]: r for r in _load_yaml("rules.yaml")}


@lru_cache(maxsize=1)
def load_servers_table() -> list[dict]:
    return _load_yaml("servers.yaml")


@lru_cache(maxsize=1)
def load_cloud_checklist() -> list[dict]:
    return _load_yaml("cloud_checklist.yaml")
