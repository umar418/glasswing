from __future__ import annotations

import json

from glasswing.analysis.models import ScanResult
from glasswing.report.safe_view import safe_scan


def render_json(scan: ScanResult, ai_summary_markdown: str | None, template_summary: dict | None) -> str:
    data = safe_scan(scan)
    data["ai_summary_markdown"] = ai_summary_markdown
    data["template_summary"] = template_summary
    return json.dumps(data, indent=2)
