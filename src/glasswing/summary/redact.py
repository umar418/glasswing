"""Redaction pass: the only thing ever sent to a cloud AI summary provider.

Hard rules enforced here:
- home directory is replaced with ~
- file names inside sensitive-keyword folders are hashed, not shown in full
- no secret values (findings already carry masked values only)
- no raw argument values, ever
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from glasswing.analysis.models import Finding, ScanResult
from glasswing.analysis.rules import SENSITIVE_PATH_KEYWORDS

_HOME = str(Path.home())


def _hash_name(name: str) -> str:
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:8]
    suffix = Path(name).suffix
    return f"<redacted-{digest}>{suffix}"


def redact_path(raw: str | None) -> str | None:
    if not raw:
        return raw
    text = raw.replace(_HOME, "~")
    lowered = text.lower()
    if any(kw in lowered for kw in SENSITIVE_PATH_KEYWORDS):
        parts = text.replace("\\", "/").split("/")
        parts[-1] = _hash_name(parts[-1]) if parts[-1] else parts[-1]
        text = "/".join(parts)
    return text


def redact_text(raw: str | None) -> str | None:
    if not raw:
        return raw
    return raw.replace(_HOME, "~")


def redact_finding(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "title": finding.title,
        "subject": redact_path(finding.subject),
        "detail": redact_path(finding.detail),
    }


def build_redacted_payload(scan: ScanResult) -> dict:
    """The exact, structured, secret-free payload a cloud AI summary call
    would receive. Deterministic and safe to show the user before consent.
    """
    severity_counts: dict[str, int] = {}
    for f in scan.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    apps_summary = []
    for app in scan.apps:
        if not app.found:
            continue
        apps_summary.append(
            {
                "app": app.app_name,
                "server_count": len(app.servers),
                "capabilities": sorted({s.capability for s in app.servers}),
                "secret_count": len(app.secrets) + sum(len(s.secrets) for s in app.servers),
            }
        )

    return {
        "exposure_level": scan.exposure_level,
        "os": scan.os_name,
        "severity_counts": severity_counts,
        "apps": apps_summary,
        "findings": [redact_finding(f) for f in scan.findings],
        "activity_event_count": len(scan.activity),
        "warnings": [redact_text(w) for w in scan.warnings],
    }
