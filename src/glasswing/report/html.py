"""Single self-contained HTML report. No external assets, no network calls
-- CSS and the tiny bit of JS (sort/filter the findings table) are inlined.
"""
from __future__ import annotations

import html as html_mod
import re

from jinja2 import Template

from glasswing.analysis.models import ScanResult
from glasswing.discovery.registry import load_cloud_checklist
from glasswing.report.safe_view import safe_scan

_TEMPLATE = Template(
    r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Glasswing report — {{ exposure_level }} exposure</title>
<style>
:root {
  --bg: #fafafa; --fg: #1b1b1f; --muted: #6b6b76; --card: #ffffff;
  --border: #e3e3e8; --accent: #4f46e5;
  --info: #6b7280; --low: #2563eb; --medium: #d97706; --high: #dc2626; --critical: #7f1d1d;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #14141a; --fg: #ececf1; --muted: #a3a3ad; --card: #1d1d25; --border: #2d2d38; --accent: #818cf8; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; line-height:1.5; }
.wrap { max-width: 920px; margin: 0 auto; padding: 32px 20px 80px; }
h1 { font-size: 1.6rem; margin-bottom: 4px; }
h2 { font-size: 1.15rem; margin-top: 2.5rem; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
.meta { color: var(--muted); font-size: 0.9rem; }
.badge { display:inline-block; padding: 4px 12px; border-radius: 999px; font-weight:600; font-size:0.85rem; color:#fff; }
.badge.Low { background: var(--low); } .badge.Moderate { background: var(--medium); }
.badge.High { background: var(--high); } .badge.Critical { background: var(--critical); }
.card { background: var(--card); border:1px solid var(--border); border-radius: 10px; padding: 16px 20px; margin: 12px 0; }
table { width:100%; border-collapse: collapse; font-size: 0.92rem; }
th, td { text-align:left; padding: 8px 10px; border-bottom:1px solid var(--border); vertical-align: top; }
th { cursor:pointer; user-select:none; color: var(--muted); font-weight:600; }
.sev { font-weight:700; }
.sev.info { color: var(--info);} .sev.low { color: var(--low);} .sev.medium { color: var(--medium);}
.sev.high { color: var(--high);} .sev.critical { color: var(--critical);}
.pill { font-size:0.75rem; padding:2px 8px; border-radius:6px; background:var(--border); color:var(--muted); }
.filters { margin: 10px 0; display:flex; gap:8px; flex-wrap:wrap; }
.filters button { border:1px solid var(--border); background:var(--card); color:var(--fg); border-radius:6px; padding:4px 10px; cursor:pointer; font-size:0.85rem; }
.filters button.active { background:var(--accent); color:#fff; border-color:var(--accent); }
code { background: var(--border); padding: 1px 5px; border-radius: 4px; font-size: 0.85em; }
footer { margin-top: 3rem; color: var(--muted); font-size: 0.82rem; }
.keelwise { border:1px dashed var(--accent); }
ul { margin: 6px 0; padding-left: 1.3rem; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Glasswing report</h1>
  <p class="meta">macOS/Windows/Linux local scan · v{{ version }} · {{ os_name }} · {{ "%.1f"|format(duration) }}s · {{ generated_at }}</p>
  <p><span class="badge {{ exposure_level }}">{{ exposure_level }} exposure</span></p>

  <h2>AI Summary</h2>
  <div class="card">{{ summary_html|safe }}</div>

  <h2>Findings ({{ findings|length }})</h2>
  <div class="filters" id="sevFilters">
    <button data-sev="all" class="active">All</button>
    <button data-sev="critical">Critical</button>
    <button data-sev="high">High</button>
    <button data-sev="medium">Medium</button>
    <button data-sev="low">Low</button>
    <button data-sev="info">Info</button>
  </div>
  <table id="findingsTable">
    <thead><tr><th data-k="severity">Severity</th><th data-k="rule_id">Rule</th><th data-k="title">Finding</th><th data-k="subject">Where</th></tr></thead>
    <tbody>
    {% for f in findings %}
      <tr data-sev="{{ f.severity }}">
        <td class="sev {{ f.severity }}">{{ f.severity|upper }}</td>
        <td><code>{{ f.rule_id }}</code></td>
        <td><strong>{{ f.title }}</strong><br><span class="meta">{{ f.explanation }}</span><br><span class="meta">Fix: {{ f.fix }}</span></td>
        <td>{{ f.subject }}{% if f.detail %}<br><span class="pill">{{ f.detail }}</span>{% endif %}</td>
      </tr>
    {% else %}
      <tr><td colspan="4">No findings.</td></tr>
    {% endfor %}
    </tbody>
  </table>

  <h2>Per-app inventory</h2>
  {% for app in apps %}
    {% if app.found %}
    <div class="card">
      <strong>{{ app.app_name }}</strong>
      <div class="meta">{{ app.config_paths|join(", ") }}</div>
      {% if app.servers %}
      <table>
        <thead><tr><th>Server</th><th>Capability</th><th>Trust</th><th>Scope</th></tr></thead>
        <tbody>
        {% for s in app.servers %}
          <tr><td>{{ s.name }}</td><td><span class="pill">{{ s.capability }}</span></td><td><span class="pill">{{ s.trust }}</span></td>
          <td>{% if s.scope_is_root_or_home %}<span class="sev critical">whole drive/home</span>{% else %}{{ s.scope_paths|join(", ") or "—" }}{% endif %}</td></tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}<div class="meta">No MCP servers configured.</div>{% endif %}
      {% if app.permissions %}
      <div class="meta">Permission rules: {{ app.permissions|length }} ({{ app.permissions|selectattr("broad")|list|length }} broad)</div>
      {% endif %}
    </div>
    {% endif %}
  {% endfor %}

  <h2>Activity timeline</h2>
  <div class="card">
  {% if activity %}
    <table>
      <thead><tr><th>Time</th><th>App</th><th>Tool</th><th>Target</th></tr></thead>
      <tbody>
      {% for e in activity %}
        <tr><td>{{ e.timestamp or "—" }}</td><td>{{ e.app }}</td><td>{{ e.tool or e.action_type }}</td><td>{{ e.target or "—" }}</td></tr>
      {% endfor %}
      </tbody>
    </table>
  {% else %}
    <p class="meta">No activity history collected in this release yet — activity-log parsing ships in a later version. Nothing was hidden; there's simply nothing to show here.</p>
  {% endif %}
  </div>

  <h2>Cloud connections we can't scan</h2>
  <div class="card">
    <p class="meta">These run on the provider's own servers, so glasswing cannot see them locally. Check each by hand:</p>
    <ul>
    {% for item in cloud_checklist %}
      <li><strong>{{ item.provider }}</strong> — {{ item.what }}: <code>{{ item.url }}</code></li>
    {% endfor %}
    </ul>
  </div>

  <h2>What this scan could not see</h2>
  <div class="card">
    <ul>
      <li>Anything run through a cloud connector on a provider's own servers (see above).</li>
      <li>Activity-log history (ships in a later glasswing release).</li>
      <li>The contents of your files — glasswing classifies only file paths and logged arguments, never file content.</li>
      <li>Any app not yet in glasswing's registry.</li>
    </ul>
  </div>

  {% if warnings %}
  <h2>Scan warnings</h2>
  <div class="card"><ul>{% for w in warnings %}<li>{{ w }}</li>{% endfor %}</ul></div>
  {% endif %}

  <h2>Keelwise</h2>
  <div class="card keelwise">
    <p>Need this same visibility across a whole team instead of one machine at a time? <strong><a href="https://keelwise.dev" target="_blank" rel="noopener">Keelwise</a></strong> gives
    businesses centralized policy, auditing and alerts for what every employee's AI tools can reach — built for teams in medical, legal and finance.</p>
  </div>

  <footer>
    Generated locally by glasswing v{{ version }}. Nothing in this report left your machine unless you explicitly chose a cloud AI summary.
    Scanned {{ os_name }} in {{ "%.2f"|format(duration) }}s.
  </footer>
</div>
<script>
(function () {
  var buttons = document.querySelectorAll('#sevFilters button');
  var rows = document.querySelectorAll('#findingsTable tbody tr');
  buttons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      buttons.forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      var sev = btn.getAttribute('data-sev');
      rows.forEach(function (row) {
        row.style.display = (sev === 'all' || row.getAttribute('data-sev') === sev) ? '' : 'none';
      });
    });
  });
  var table = document.getElementById('findingsTable');
  var order = {critical:4, high:3, medium:2, low:1, info:0};
  table.querySelectorAll('th').forEach(function (th, idx) {
    var asc = true;
    th.addEventListener('click', function () {
      var tbody = table.querySelector('tbody');
      var rowsArr = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
      rowsArr.sort(function (a, b) {
        var av = a.children[idx].innerText.trim(), bv = b.children[idx].innerText.trim();
        if (idx === 0) { av = order[av.toLowerCase()] || 0; bv = order[bv.toLowerCase()] || 0; }
        if (av < bv) return asc ? -1 : 1;
        if (av > bv) return asc ? 1 : -1;
        return 0;
      });
      rowsArr.forEach(function (r) { tbody.appendChild(r); });
      asc = !asc;
    });
  });
})();
</script>
</body>
</html>
"""
)


def _simple_markdown_to_html(text: str) -> str:
    """Minimal markdown renderer for our own AI-generated summaries: headers,
    bold, and bullet lists only. Good enough for the five-section summary
    shape we ask providers for; escapes everything else as plain text.
    """
    lines = text.strip().splitlines()
    out: list[str] = []
    in_list = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if in_list:
                out.append("</ul>")
                in_list = False
            continue
        header_match = re.match(r"^(#{1,4})\s+(.*)", stripped)
        bullet_match = re.match(r"^[-*]\s+(.*)", stripped)
        if header_match:
            if in_list:
                out.append("</ul>")
                in_list = False
            level = min(len(header_match.group(1)) + 2, 5)
            out.append(f"<h{level}>{_inline_md(header_match.group(2))}</h{level}>")
        elif bullet_match:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline_md(bullet_match.group(1))}</li>")
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<p>{_inline_md(stripped)}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def _inline_md(text: str) -> str:
    escaped = html_mod.escape(text)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


def _template_summary_to_html(summary: dict) -> str:
    parts = [f"<h3>Overall exposure: {html_mod.escape(summary['overall_level'])}</h3>"]
    parts.append(f"<p>{html_mod.escape(summary['overall_reason'])}</p>")
    parts.append("<h4>What your AI tools can reach</h4><ul>")
    for app, caps in summary["reach_by_app"].items():
        parts.append(f"<li><strong>{html_mod.escape(app)}</strong>: {html_mod.escape(', '.join(caps))}</li>")
    parts.append("</ul>")
    if summary["top_fixes"]:
        parts.append("<h4>Top fixes</h4><ul>")
        for fix in summary["top_fixes"]:
            parts.append(
                f"<li><code>{html_mod.escape(fix['rule_id'])}</code> <strong>{html_mod.escape(fix['title'])}</strong> "
                f"— {html_mod.escape(fix['subject'])}: {html_mod.escape(fix['fix'])}</li>"
            )
        parts.append("</ul>")
    parts.append("<h4>What this scan could not see</h4><ul>")
    for item in summary["cannot_see"]:
        parts.append(f"<li>{html_mod.escape(item)}</li>")
    parts.append("</ul>")
    return "\n".join(parts)


def render_html(scan: ScanResult, ai_summary_markdown: str | None, template_summary: dict | None) -> str:
    data = safe_scan(scan)
    if ai_summary_markdown:
        summary_html = _simple_markdown_to_html(ai_summary_markdown)
    elif template_summary:
        summary_html = _template_summary_to_html(template_summary)
    else:
        summary_html = "<p>No summary available.</p>"

    return _TEMPLATE.render(
        version=scan.version,
        os_name=scan.os_name,
        duration=scan.duration_seconds,
        generated_at=data["started_at"],
        exposure_level=scan.exposure_level,
        summary_html=summary_html,
        findings=data["findings"],
        apps=data["apps"],
        activity=data["activity"],
        cloud_checklist=load_cloud_checklist(),
        warnings=data["warnings"],
    )
