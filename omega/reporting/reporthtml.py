"""omega/reporting/reporthtml — standalone dark-theme HTML report.

Renders findings + evidence links into a single self-contained HTML
file (no external assets): severity filter via inline JS, dark
theme, per-finding detail with PoC/corroboration sections. English
content (source policy), title labels generic.
"""
import html as _h
import json

__all__ = ["render_html"]


def _esc(s):
    return _h.escape(str(s or ""))


def render_html(findings, target="", extra_sections=None):
    rows = []
    for f in findings or []:
        sev = _esc(f.get("severity", "INFO"))
        rows.append(f"""
<div class="f {sev.lower()}">
  <h3>[{sev}] {_esc(f.get('title'))}</h3>
  <p class="meta">{_esc(f.get('cwe'))} · {_esc(f.get('source'))} ·
     {_esc(f.get('verification'))} · {_esc(f.get('strength', ''))}</p>
  <p><b>Location:</b> {_esc(f.get('location'))}</p>
  <pre>{_esc(f.get('evidence'))}</pre>
  <p class="mc">{_esc(f.get('manual_check'))}</p>
</div>""")
    body = "\n".join(rows) or "<p>No findings.</p>"
    extras = "\n".join(f"<section><h2>{_esc(t)}</h2><pre>{_esc(c)}"
                       f"</pre></section>"
                       for t, c in (extra_sections or []))
    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>OMEGA report — {_esc(target)}</title>
<style>
body{{background:#0d1117;color:#c9d1d9;font-family:monospace;
margin:2rem;max-width:60rem}}
h1,h2{{color:#58a6ff}} .f{{border:1px solid #30363d;border-radius:6px;
padding:1rem;margin:1rem 0}}
.CRITICAL{{border-color:#f85149}} .HIGH{{border-color:#d29922}}
.MEDIUM{{border-color:#58a6ff}} pre{{white-space:pre-wrap;
background:#161b22;padding:.5rem;border-radius:4px}}
.meta{{color:#8b949e}} button{{margin-right:.5rem}}
</style></head><body>
<h1>OMEGA engagement report</h1>
<p>target: {_esc(target)} — self-contained, filter by severity:</p>
<button onclick="show('all')">all</button>
<button onclick="show('critical')">critical</button>
<button onclick="show('high')">high</button>
<button onclick="show('medium')">medium</button>
<script>
function show(k){{document.querySelectorAll('.f').forEach(d=>{{
d.style.display = (k==='all'||d.classList.contains(k))?'block':'none';
}});}}
</script>
{extras}
{body}
</body></html>"""
