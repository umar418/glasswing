"""Persisted user settings: ~/.glasswing/config.json. Never holds secrets --
API keys stay in environment variables.
"""
from __future__ import annotations

import json
from pathlib import Path

from glasswing.discovery.paths import home_dir

AI_PROVIDERS = ("auto", "ollama", "anthropic", "none")
DEFAULTS = {"ai_provider": "auto", "consented_providers": [], "extra_project_roots": []}


def app_dir() -> Path:
    return home_dir() / ".glasswing"


def config_path() -> Path:
    return app_dir() / "config.json"


def reports_dir() -> Path:
    return app_dir() / "reports"


def load_config() -> dict:
    merged = dict(DEFAULTS)
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
        if isinstance(data, dict):
            merged.update({k: v for k, v in data.items() if k in DEFAULTS and isinstance(v, type(DEFAULTS[k]))})
    except (OSError, ValueError):
        pass
    if merged["ai_provider"] not in AI_PROVIDERS:
        merged["ai_provider"] = "auto"
    return merged


def save_config(config: dict) -> None:
    app_dir().mkdir(parents=True, exist_ok=True)
    config_path().write_text(json.dumps(config, indent=2), encoding="utf-8")


def mark_consented(provider: str) -> None:
    config = load_config()
    if provider not in config["consented_providers"]:
        config["consented_providers"].append(provider)
    save_config(config)
