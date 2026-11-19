from __future__ import annotations

from glasswing.analysis.models import ScanResult
from glasswing.parsers.secrets import scrub


def render_all(scan: ScanResult, ai_text: str | None = None) -> tuple[dict, dict, dict[str, str]]:
    """-> (safe data, summary, {filename: content}). The single path every output
    takes: built from the redacted view, then scrubbed of any detected raw secret."""
    from glasswing.report.html import render_html
    from glasswing.report.json_report import render_json
    from glasswing.report.md_report import render_markdown
    from glasswing.report.safe_view import safe_scan
    from glasswing.summary.template import build_template_summary

    raw = scan.raw_secrets
    data = safe_scan(scan)
    summary = build_template_summary(data)
    if ai_text:
        ai_text = scrub(ai_text, raw)
    files = {
        "report.html": scrub(render_html(data, ai_text, summary), raw),
        "report.json": scrub(render_json(data, ai_text, summary), raw),
        "summary.md": scrub(render_markdown(data, ai_text, summary), raw),
    }
    return data, summary, files
