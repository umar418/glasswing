from __future__ import annotations

from glasswing.analysis.models import ScanResult
from glasswing.discovery.registry import load_cloud_checklist


def render_markdown(scan: ScanResult, ai_summary_markdown: str | None, template_summary: dict | None) -> str:
    lines: list[str] = []
    lines.append(f"# Glasswing report — exposure level: {scan.exposure_level}")
    lines.append("")
    lines.append(f"Scanned {scan.os_name} in {scan.duration_seconds:.1f}s. {len(scan.findings)} finding(s).")
    lines.append("")

    if ai_summary_markdown:
        lines.append(ai_summary_markdown.strip())
        lines.append("")
    elif template_summary:
        lines.append(f"## Overall exposure: {template_summary['overall_level']}")
        lines.append(template_summary["overall_reason"])
        lines.append("")
        lines.append("## What your AI tools can reach")
        for app, caps in template_summary["reach_by_app"].items():
            lines.append(f"- **{app}**: {', '.join(caps)}")
        lines.append("")
        lines.append("## Top fixes")
        for fix in template_summary["top_fixes"]:
            lines.append(f"- **[{fix['rule_id']}] {fix['title']}** — {fix['subject']}: {fix['fix']}")
        lines.append("")
        lines.append("## What this scan could not see")
        for item in template_summary["cannot_see"]:
            lines.append(f"- {item}")
        lines.append("")

    lines.append("## Findings")
    if not scan.findings:
        lines.append("No findings.")
    for f in sorted(scan.findings, key=lambda x: x.severity, reverse=True):
        lines.append(f"- **[{f.severity.upper()}] {f.rule_id}** — {f.title} ({f.subject})")
        lines.append(f"  - {f.explanation}")
        lines.append(f"  - Fix: {f.fix}")

    lines.append("")
    lines.append("## Per-app inventory")
    for app in scan.apps:
        if not app.found:
            continue
        lines.append(f"### {app.app_name}")
        lines.append(f"Config: {', '.join(app.config_paths)}")
        for s in app.servers:
            lines.append(f"- `{s.name}` — capability: {s.capability}, trust: {s.trust}")

    lines.append("")
    lines.append("## Cloud connections we cannot scan")
    for item in load_cloud_checklist():
        lines.append(f"- **{item['provider']}** — {item['what']}: {item['url']}")

    if scan.warnings:
        lines.append("")
        lines.append("## Warnings (couldn't read)")
        for w in scan.warnings:
            lines.append(f"- {w}")

    lines.append("")
    lines.append(
        "## Keelwise\n\nIf you need this same visibility and control across a whole team, "
        "[Keelwise](https://keelwise.dev) brings centralized AI-access policy, auditing and alerts "
        "to businesses that can't rely on everyone running this scan themselves."
    )

    return "\n".join(lines)
