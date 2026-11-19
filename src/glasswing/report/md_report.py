from __future__ import annotations

from glasswing.discovery.registry import load_cloud_checklist


def _line(text: str) -> str:
    """Config-derived text on one markdown line, with markup characters neutralised."""
    return " ".join(str(text).split()).replace("<", "&lt;").replace("|", "\\|").replace("`", "'")


def render_markdown(data: dict, ai_summary_markdown: str | None, summary: dict) -> str:
    out: list[str] = [f"# Glasswing report — exposure level: {data['exposure_level']}", ""]
    out.append(f"Scanned on {data['started_at']} ({data['os']}), {data['files_read']} settings file(s) read, glasswing v{data['version']}.")
    out.append("")
    if ai_summary_markdown:
        out += ["## AI-written summary", "", ai_summary_markdown.strip(), ""]
    out += ["## Summary", "", summary["overall_reason"], ""]

    out += ["## What your AI tools can reach", ""]
    if not summary["reach"]:
        out.append("No AI app settings were found.")
    for app in summary["reach"]:
        out.append(f"### {app['app']}")
        if not app["servers"]:
            out.append("- No MCP servers configured.")
        for s in app["servers"]:
            scope = f" — file access: {s['scope']}" if s["scope"] else ""
            out.append(f"- **{_line(s['name'])}**: {s['what']} ({s['basis']}); {s['source']}{scope}")
        if app["allow_rules"]:
            out.append(f"- {app['allow_rules']} 'always allow' permission rule(s)")
        out.append("")

    out += ["## Findings", ""]
    if not data["findings"]:
        out.append("No findings.")
    for f in data["findings"]:
        times = f" (×{f['count']})" if f["count"] > 1 else ""
        out.append(f"### [{f['severity'].upper()}] {f['title']}{times}")
        out.append(f"- Rule: `{f['rule_id']}`")
        out.append(f"- Where: {_line(f['subject'])}")
        for d in f["details"]:
            out.append(f"  - {_line(d)}")
        if f["more_details"]:
            out.append(f"  - …and {f['more_details']} more")
        out.append(f"- Why it matters: {f['explanation']}")
        out.append(f"- Fix: {f['fix']}")
        out.append("")

    out += ["## Connections Glasswing cannot see (check these by hand)", ""]
    for item in load_cloud_checklist():
        target = item.get("url") or item.get("where")
        out.append(f"- **{item['provider']}** — {item['what']}: {target}")
    out += ["", "## What this scan could not see", ""]
    out += [f"- {x}" for x in data["not_covered"]]
    if data["warnings"]:
        out += ["", "## Files that could not be read", ""]
        out += [f"- {_line(w)}" for w in data["warnings"]]
    out += [
        "", "## For teams", "",
        "Need this visibility across a whole team rather than one computer? [Keelwise](https://keelwise.dev) "
        "gives businesses central control and audit of what their AI tools can reach.", "",
    ]
    return "\n".join(out)
