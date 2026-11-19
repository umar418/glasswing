"""Single self-contained HTML report: no external assets, no network.

Every value is HTML-escaped by Jinja autoescaping. Config files are
untrusted input (a cloned repo can ship its own .mcp.json), so nothing from
them may ever reach the page as markup.
"""
from __future__ import annotations

import html as html_mod
import re

from jinja2 import Environment
from markupsafe import Markup

from glasswing.discovery.registry import load_cloud_checklist

_ENV = Environment(autoescape=True)
_TEMPLATE = _ENV.from_string(
    r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>Glasswing report — {{ d.exposure_level }} exposure</title>
<style>
:root { --bg:#f7f7f5; --fg:#1c1c21; --muted:#62626d; --card:#fff; --border:#e2e2e6; --accent:#3f4bd8;
  --info:#6b7280; --low:#2563eb; --medium:#b45309; --high:#c2410c; --critical:#b91c1c; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#131318; --fg:#ececf1; --muted:#a3a3ad; --card:#1c1c24; --border:#2e2e3a; --accent:#8b93ff;
    --low:#60a5fa; --medium:#f59e0b; --high:#fb923c; --critical:#f87171; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
.wrap { max-width:900px; margin:0 auto; padding:32px 16px 80px; }
h1 { font-size:1.5rem; margin:0 0 4px; } h2 { font-size:1.15rem; margin:2.4rem 0 .6rem; }
h3 { font-size:1rem; margin:1rem 0 .3rem; }
.meta { color:var(--muted); font-size:.88rem; overflow-wrap:anywhere; }
.badge { display:inline-block; padding:5px 14px; border-radius:999px; font-weight:700; color:#fff; }
.badge.Low { background:#2563eb; } .badge.Moderate { background:#b45309; } .badge.High { background:#c2410c; } .badge.Critical { background:#b91c1c; }
.card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px 18px; margin:10px 0; overflow-wrap:anywhere; }
.sev { font-weight:700; font-size:.78rem; letter-spacing:.04em; }
.sev.info{color:var(--info);} .sev.low{color:var(--low);} .sev.medium{color:var(--medium);} .sev.high{color:var(--high);} .sev.critical{color:var(--critical);}
.finding { border-left:4px solid var(--border); }
.finding.critical{border-left-color:var(--critical);} .finding.high{border-left-color:var(--high);} .finding.medium{border-left-color:var(--medium);} .finding.low{border-left-color:var(--low);}
.finding h3 { margin:.1rem 0 .3rem; }
code, .mono { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.84em; }
code { background:var(--border); padding:1px 5px; border-radius:4px; }
.filters { display:flex; gap:8px; flex-wrap:wrap; margin:8px 0; }
.filters button, .filters select { border:1px solid var(--border); background:var(--card); color:var(--fg); border-radius:6px; padding:5px 11px; font:inherit; font-size:.85rem; cursor:pointer; }
.filters button[aria-pressed="true"] { background:var(--accent); color:#fff; border-color:var(--accent); }
table { width:100%; border-collapse:collapse; font-size:.9rem; } th,td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--border); vertical-align:top; }
th { color:var(--muted); font-weight:600; } .scroll { overflow-x:auto; }
ul { margin:6px 0; padding-left:1.25rem; } .fix { margin-top:.4rem; }
a { color:var(--accent); } footer { margin-top:3rem; color:var(--muted); font-size:.82rem; }
.keelwise { border-style:dashed; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Glasswing report</h1>
  <p class="meta">{{ d.started_at }} · {{ d.os }} · {{ d.files_read }} settings file(s) read in {{ "%.1f"|format(d.duration_seconds) }}s · glasswing v{{ d.version }}</p>
  <p><span class="badge {{ d.exposure_level }}">{{ d.exposure_level }} exposure</span></p>

  <h2>{{ "AI-written summary" if ai_html else "Summary" }}</h2>
  <div class="card">
    {% if ai_html %}{{ ai_html }}<p class="meta">Written by an AI model from the findings below. If it disagrees with the findings, trust the findings.</p>
    {% else %}
      <p>{{ s.overall_reason }}</p>
      {% if s.top_fixes %}<h3>Fix these first</h3><ol>
        {% for f in s.top_fixes %}<li><strong>{{ f.title }}</strong>{% if f.count > 1 %} (×{{ f.count }}){% endif %} <span class="meta">— {{ f.subject }}</span><br>{{ f.fix }}</li>{% endfor %}
      </ol>{% endif %}
    {% endif %}
  </div>

  <h2>Findings ({{ d.findings|length }})</h2>
  {% if d.findings %}
  <div class="filters" id="filters">
    <button data-sev="all" aria-pressed="true">All</button>
    {% for sev in ["critical","high","medium","low"] %}{% if d.severity_counts.get(sev) %}<button data-sev="{{ sev }}" aria-pressed="false">{{ sev|capitalize }} ({{ d.severity_counts[sev] }})</button>{% endif %}{% endfor %}
    <select id="appFilter" aria-label="Filter by app"><option value="">All apps</option>{% for a in d.apps if a.found %}<option>{{ a.app_name }}</option>{% endfor %}</select>
    <select id="sortBy" aria-label="Sort findings"><option value="sev">Most serious first</option><option value="app">By app</option></select>
  </div>
  <div id="findings">
  {% for f in d.findings %}
    <div class="card finding {{ f.severity }}" data-sev="{{ f.severity }}" data-subject="{{ f.subject }}" data-order="{{ loop.index }}">
      <span class="sev {{ f.severity }}">{{ f.severity|upper }}</span> <code>{{ f.rule_id }}</code>{% if f.count > 1 %} <span class="meta">seen {{ f.count }} times</span>{% endif %}
      <h3>{{ f.title }}</h3>
      <div class="meta">Where: {{ f.subject }}</div>
      {% if f.details %}<ul class="mono">{% for x in f.details %}<li>{{ x }}</li>{% endfor %}{% if f.more_details %}<li>…and {{ f.more_details }} more</li>{% endif %}</ul>{% endif %}
      <div>{{ f.explanation }}</div>
      <div class="fix"><strong>Fix:</strong> {{ f.fix }}</div>
    </div>
  {% endfor %}
  </div>
  {% else %}<div class="card">No risky settings were found in the apps checked.</div>{% endif %}

  <h2>Apps checked</h2>
  {% for a in d.apps %}
    <div class="card">
      <strong>{{ a.app_name }}</strong>
      {% if not a.found %}<span class="meta"> — no settings found on this computer</span>
      {% else %}
        <div class="meta">{{ a.config_paths|length }} settings file(s){% if a.identical_copy_count %}, plus {{ a.identical_copy_count }} identical copies (not counted twice){% endif %}:
          {{ a.config_paths[:4]|join(", ") }}{% if a.config_paths|length > 4 %} and {{ a.config_paths|length - 4 }} more{% endif %}</div>
        {% if a.servers %}<div class="scroll"><table>
          <thead><tr><th>Server</th><th>What it can do</th><th>Where it comes from</th><th>File access</th></tr></thead><tbody>
          {% for sv in a.servers %}<tr>
            <td><strong>{{ sv.name }}</strong>{% if sv.also_defined_in_count %}<br><span class="meta">also in {{ sv.also_defined_in_count }} other file(s)</span>{% endif %}</td>
            <td>{{ sv.capability_label }}<br><span class="meta">{{ sv.capability_basis }}</span></td>
            <td>{{ sv.source }}{% if sv.remote_host %}<br><span class="meta mono">{{ sv.remote_host }}</span>{% elif sv.package %}<br><span class="meta mono">{{ sv.package }}</span>{% endif %}</td>
            <td>{% if sv.scope_label %}<span class="sev high">{{ sv.scope_label }}</span>{% elif sv.scope_paths %}{{ sv.scope_paths|join(", ") }}{% else %}—{% endif %}</td>
          </tr>{% endfor %}</tbody></table></div>
        {% else %}<div class="meta">No MCP servers configured.</div>{% endif %}
        {% if a.permission_rule_counts %}<div class="meta">Permission rules: {% for k, v in a.permission_rule_counts.items() %}{{ v }} {{ k }}{% if not loop.last %}, {% endif %}{% endfor %}. Risky ones are listed under Findings.</div>{% endif %}
      {% endif %}
    </div>
  {% endfor %}

  <h2>Activity</h2>
  <div class="card"><p>This version does not read activity logs, so it cannot tell you what your AI tools actually opened or ran. It reports what they are <em>able</em> to do.</p></div>

  <h2>Connections Glasswing cannot see</h2>
  <div class="card">
    <p>These live on each provider's own servers. Check them by hand:</p>
    <ul>{% for item in checklist %}<li><strong>{{ item.provider }}</strong> — {{ item.what }}:
      {% if item.url %}<a href="{{ item.url }}" rel="noopener noreferrer">{{ item.url }}</a>{% else %}{{ item.where }}{% endif %}</li>{% endfor %}</ul>
  </div>

  <h2>What this scan could not see</h2>
  <div class="card"><ul>{% for x in d.not_covered %}<li>{{ x }}</li>{% endfor %}</ul></div>

  {% if d.warnings %}<h2>Files that could not be read</h2>
  <div class="card"><ul>{% for w in d.warnings %}<li>{{ w }}</li>{% endfor %}</ul></div>{% endif %}

  <h2>For teams</h2>
  <div class="card keelwise"><p>Need this visibility across a whole team rather than one computer?
    <a href="https://keelwise.dev" rel="noopener noreferrer">Keelwise</a> gives businesses central control and audit of what their AI tools can reach.</p></div>

  <footer>Generated on this computer by glasswing v{{ d.version }}. Passwords and keys are masked, so this file is safe to share.
    {{ "An AI summary was requested, so the redacted findings were sent to the model you approved." if ai_html else "Nothing was sent anywhere." }}</footer>
</div>
<script>
(function () {
  var box = document.getElementById('findings'); if (!box) return;
  var cards = [].slice.call(box.children), sev = 'all', app = '';
  var rank = {critical: 4, high: 3, medium: 2, low: 1, info: 0};
  function apply() {
    cards.forEach(function (c) {
      var ok = (sev === 'all' || c.dataset.sev === sev) && (!app || c.dataset.subject.indexOf(app) === 0);
      c.style.display = ok ? '' : 'none';
    });
  }
  document.querySelectorAll('#filters button').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('#filters button').forEach(function (x) { x.setAttribute('aria-pressed', 'false'); });
      b.setAttribute('aria-pressed', 'true'); sev = b.dataset.sev; apply();
    });
  });
  document.getElementById('appFilter').addEventListener('change', function (e) { app = e.target.value; apply(); });
  document.getElementById('sortBy').addEventListener('change', function (e) {
    var byApp = e.target.value === 'app';
    cards.sort(function (a, b) {
      if (byApp && a.dataset.subject !== b.dataset.subject) return a.dataset.subject < b.dataset.subject ? -1 : 1;
      return (rank[b.dataset.sev] - rank[a.dataset.sev]) || (a.dataset.order - b.dataset.order);
    }).forEach(function (c) { box.appendChild(c); });
  });
})();
</script>
</body>
</html>
"""
)


def _inline_md(text: str) -> str:
    escaped = html_mod.escape(text)
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)


def markdown_to_html(text: str) -> str:
    """Tiny renderer for AI summaries: headings, bold, bullets. All text is escaped first,
    so model output can never inject markup, links or scripts."""
    out: list[str] = []
    in_list = False
    for line in text.strip().splitlines():
        stripped = line.strip()
        header = re.match(r"^(#{1,4})\s+(.*)", stripped)
        bullet = re.match(r"^(?:[-*]|\d+\.)\s+(.*)", stripped)
        if in_list and not bullet:
            out.append("</ul>")
            in_list = False
        if not stripped:
            continue
        if header:
            out.append(f"<h3>{_inline_md(header.group(2))}</h3>")
        elif bullet:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline_md(bullet.group(1))}</li>")
        else:
            out.append(f"<p>{_inline_md(stripped)}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def render_html(data: dict, ai_summary_markdown: str | None, summary: dict) -> str:
    ai_html = Markup(markdown_to_html(ai_summary_markdown)) if ai_summary_markdown else None
    return _TEMPLATE.render(d=data, s=summary, ai_html=ai_html, checklist=load_cloud_checklist())
