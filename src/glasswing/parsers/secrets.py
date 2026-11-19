"""Secret detection and masking.

Hard rule: full secret values must never appear in any output. Every match
is masked to a short, non-reversible-looking preview before it leaves this
module.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache
from importlib import resources
from typing import Iterable

import yaml

from glasswing.analysis.models import SecretFinding


_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def redact_url_path_ids(value: str) -> str:
    """A remote MCP URL often embeds a per-connection token directly in the
    path (e.g. https://host/mcp/c/<uuid>) -- that segment is effectively a
    bearer credential, not just an identifier, so mask it like any secret.
    """
    if value.startswith("http://") or value.startswith("https://"):
        return _UUID_RE.sub("<redacted-id>", value)
    return value


def mask_secret(value: str) -> str:
    """Mask a secret value, keeping only a short prefix/suffix hint."""
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    prefix = value[:3]
    suffix = value[-4:]
    return f"{prefix}…{suffix}"


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@lru_cache(maxsize=1)
def _load_patterns() -> list[dict]:
    raw = resources.files("glasswing.registry").joinpath("secret_patterns.yaml").read_text()
    return yaml.safe_load(raw) or []


@lru_cache(maxsize=1)
def _compiled_patterns() -> list[tuple[dict, re.Pattern]]:
    out = []
    for p in _load_patterns():
        out.append((p, re.compile(p["pattern"])))
    return out


def scan_text(text: str, source_path: str, key_hint: str | None = None) -> list[SecretFinding]:
    """Scan a blob of text for secret-looking values. Returns masked findings only."""
    if not text:
        return []
    findings: list[SecretFinding] = []
    seen: set[str] = set()
    for pattern, compiled in _compiled_patterns():
        high_entropy_only = pattern.get("high_entropy_only", False)
        group = pattern.get("group", 0)
        for m in compiled.finditer(text):
            try:
                value = m.group(group)
            except IndexError:
                continue
            if not value or value in seen:
                continue
            if high_entropy_only and _shannon_entropy(value) < 4.3:
                continue
            seen.add(value)
            findings.append(
                SecretFinding(
                    pattern_id=pattern["id"],
                    pattern_name=pattern["name"],
                    source_path=source_path,
                    masked_value=mask_secret(value),
                    key_hint=key_hint,
                )
            )
    return findings


def safe_arg(arg: str) -> str:
    """Redact one command-line argument for display: full mask if it looks
    like a secret, otherwise strip any opaque URL-path token (a connection
    id in a remote MCP URL can itself act as a bearer credential).
    """
    if scan_text(arg, source_path="<arg>"):
        return "<redacted: looks like a secret>"
    return redact_url_path_ids(arg)


def safe_command_line(command: str | None, args: Iterable[str]) -> str:
    parts = [p for p in [command, *[safe_arg(a) for a in args]] if p]
    return " ".join(parts)


def scan_mapping(data, source_path: str, _key: str | None = None) -> list[SecretFinding]:
    """Recursively scan a parsed JSON/YAML structure (dict/list/str) for secrets."""
    findings: list[SecretFinding] = []
    if isinstance(data, dict):
        for k, v in data.items():
            findings.extend(scan_mapping(v, source_path, str(k)))
    elif isinstance(data, list):
        for item in data:
            findings.extend(scan_mapping(item, source_path, _key))
    elif isinstance(data, str):
        findings.extend(scan_text(data, source_path, key_hint=_key))
    return findings
