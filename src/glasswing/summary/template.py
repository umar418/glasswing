"""Deterministic, no-AI summary built from the safe view of a scan. This is
what --no-ai produces, and the fallback whenever no AI provider is used.
"""
from __future__ import annotations

_ORDER = ["critical", "high", "medium", "low", "info"]


def _reason(data: dict) -> str:
    counts = data["severity_counts"]
    found = [a for a in data["apps"] if a["found"]]
    if not found:
        return "Glasswing did not find settings for any of the AI apps it checks, so there was nothing to assess."
    if not data["findings"]:
        return "Glasswing found no risky settings in the AI apps it checked. That is not a guarantee of safety: see what this scan could not see."
    top = next(s for s in _ORDER if counts.get(s))
    parts = ", ".join(f"{counts[s]} {s}" for s in _ORDER if counts.get(s))
    lead = data["findings"][0]
    return f"The level is set by the most serious issue found ({top}): {lead['title'].lower()}. In total: {parts}."


def build_template_summary(data: dict) -> dict:
    reach = []
    for app in data["apps"]:
        if not app["found"]:
            continue
        servers = [
            {"name": s["name"], "what": s["capability_label"], "basis": s["capability_basis"], "source": s["source"], "scope": s["scope_label"]}
            for s in app["servers"]
        ]
        reach.append({"app": app["app_name"], "servers": servers, "allow_rules": app["permission_rule_counts"].get("allow", 0)})
    return {
        "overall_level": data["exposure_level"],
        "overall_reason": _reason(data),
        "reach": reach,
        "top_fixes": [
            {"rule_id": f["rule_id"], "severity": f["severity"], "title": f["title"], "subject": f["subject"], "fix": f["fix"], "count": f["count"]}
            for f in data["findings"][:5]
        ],
        "cannot_see": data["not_covered"],
    }
