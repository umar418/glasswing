from __future__ import annotations

import json


def render_json(data: dict, ai_summary_markdown: str | None, template_summary: dict | None) -> str:
    out = dict(data)
    out["ai_summary_markdown"] = ai_summary_markdown
    out["template_summary"] = template_summary
    return json.dumps(out, indent=2, ensure_ascii=False)
