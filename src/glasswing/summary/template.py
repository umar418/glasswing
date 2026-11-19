"""Deterministic, no-AI summary. The tool must be fully useful without any
AI provider -- this is what --no-ai (and the no-provider-available default)
produces.
"""
from __future__ import annotations

from glasswing.analysis.models import ScanResult

LEVEL_REASON = {
    "Low": "No major gaps were found in what your AI tools can reach.",
    "Moderate": "A few settings are broader than they need to be, but nothing critical.",
    "High": "One or more AI tools have broad, risky access that's worth fixing soon.",
    "Critical": "At least one AI tool can reach your whole disk, run arbitrary commands, or has an exposed credential.",
}


def build_template_summary(scan: ScanResult) -> dict:
    apps_found = [a for a in scan.apps if a.found]
    by_app: dict[str, list[str]] = {}
    for app in apps_found:
        caps = sorted({s.capability for s in app.servers if s.capability != "unknown"})
        if caps:
            by_app[app.app_name] = caps

    top_fixes = sorted(scan.findings, key=lambda f: -_severity_rank(f.severity))[:5]

    return {
        "overall_level": scan.exposure_level,
        "overall_reason": LEVEL_REASON.get(scan.exposure_level, ""),
        "reach_by_app": by_app,
        "notable_activity": [],  # activity history ships in a later phase
        "top_fixes": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "subject": f.subject,
                "fix": f.fix,
            }
            for f in top_fixes
        ],
        "cannot_see": [
            "Cloud connectors that run on a provider's own servers (e.g. Gmail connected inside claude.ai or ChatGPT) -- "
            "see the cloud checklist section of the report.",
            "Activity from before this scan's lookback window, or from apps not yet in glasswing's registry.",
        ],
    }


def _severity_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0)
