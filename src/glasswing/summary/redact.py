"""The redaction pass for AI summaries: builds the only thing ever sent to a
model. It starts from the already-redacted safe view (no secrets, no raw
arguments) and additionally hides the home folder and the names of files in
sensitive folders.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from glasswing.discovery.paths import home_dir

SENSITIVE_PATH_KEYWORDS = [
    "medical", "health", "patient", "hipaa", "legal", "client", "case", "contract", "tax", "payroll", "bank",
    "statement", "invoice", "passport", "ssn", "password", ".env", "secrets", ".ssh", ".aws", "keychain", "wallet",
]
_PATH_RE = re.compile(r"(?:~|/|[A-Za-z]:\\)[^\s,;:()\"']*")


def _hash_name(name: str) -> str:
    return f"<name-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:8]}>{Path(name).suffix}"


def redact_path(raw: str | None) -> str | None:
    if not raw:
        return raw
    text = raw.replace(str(home_dir()), "~").replace(str(Path.home()), "~")
    parts = text.replace("\\", "/").split("/")
    for i, part in enumerate(parts[:-1]):
        if any(kw in part.lower() for kw in SENSITIVE_PATH_KEYWORDS):
            parts[i + 1:] = [_hash_name(p) if p else p for p in parts[i + 1:]]
            break
    return "/".join(parts)


def redact_for_model(text: str | None) -> str | None:
    if not text:
        return text
    return _PATH_RE.sub(lambda m: redact_path(m.group(0)) or "", text)


def build_redacted_payload(data: dict) -> dict:
    """`data` is safe_view.safe_scan(...). Deterministic; shown to the user before any cloud call."""
    apps = []
    for app in data["apps"]:
        if not app["found"]:
            continue
        apps.append({
            "app": app["app_name"],
            "allow_rule_count": app["permission_rule_counts"].get("allow", 0),
            "servers": [
                {"name": redact_for_model(s["name"]), "what_it_does": s["capability_label"], "how_we_know": s["capability_basis"],
                 "source": s["source"], "file_scope": s["scope_label"]}
                for s in app["servers"]
            ],
        })
    return {
        "exposure_level": data["exposure_level"],
        "severity_counts": data["severity_counts"],
        "apps": apps,
        "findings": [
            {"rule_id": f["rule_id"], "severity": f["severity"], "title": f["title"], "where": redact_for_model(f["subject"]),
             "times_seen": f["count"], "fix": f["fix"]}
            for f in data["findings"]
        ],
        "activity": "not collected by this version",
        "could_not_see": data["not_covered"],
    }
