"""Persisted user config: ~/.glasswing/config.json.

Holds AI summary provider choice/consent and a couple of scan knobs. Never
holds secrets -- API keys stay in environment variables.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

APP_DIR = Path.home() / ".glasswing"
CONFIG_PATH = APP_DIR / "config.json"
REPORTS_DIR = APP_DIR / "reports"

DEFAULTS: dict[str, Any] = {
    "ai_provider": None,  # null | "ollama" | "anthropic" | "openai" | "gemini"
    "consented_providers": [],  # providers the user has explicitly approved a cloud call for
    "extra_project_roots": [],
    "history_lookback_days": 90,
}


def load_config() -> dict:
    if not CONFIG_PATH.is_file():
        return dict(DEFAULTS)
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return dict(DEFAULTS)
    merged = dict(DEFAULTS)
    merged.update(data)
    return merged


def save_config(config: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")


def mark_consented(provider: str) -> None:
    config = load_config()
    if provider not in config["consented_providers"]:
        config["consented_providers"].append(provider)
    save_config(config)


def has_consented(provider: str) -> bool:
    return provider in load_config().get("consented_providers", [])
