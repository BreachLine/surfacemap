"""Web UI dashboard for SurfaceMap scan results."""

from __future__ import annotations

import json
from html import escape
from typing import Any

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse
except ImportError:
    raise ImportError("FastAPI is required. Install with: pip install 'surfacemap[ui]'")

from surfacemap import __version__
from surfacemap.storage.db import ScanDatabase

ui_app = FastAPI(title="SurfaceMap Dashboard", version=__version__)

_db: ScanDatabase | None = None


async def get_db() -> ScanDatabase:
    global _db
    if _db is None:
        _db = ScanDatabase()
        await _db.initialize()
    return _db


_BASE_CSS = """
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:'Inter',system-ui,sans-serif; background:#0a0a0f; color:#e0e0e0; }
    .container { max-width:1200px; margin:0 auto; padding:2rem; }
    .header { display:flex; justify-content:space-between; align-items:center; margin-bottom:2rem; border-bottom:1px solid #1a1a2e; padding-bottom:1rem; }
    .header h1 { color:#00d4ff; font-size:1.5rem; }
    .header .version { color:#666; font-size:0.85rem; }
    .card { background:#111122; border:1px solid #1a1a2e; border-radius:8px; padding:1.5rem; margin-bottom:1rem; }
    .card h2 { color:#00d4ff; margin-bottom:1rem; font-size:1.1rem; }
    table { width:100%; border-collapse:collapse; }
    th { text-align:left; padding:0.75rem; color:#888; font-size:0.85rem; border-bottom:1px solid #1a1a2e; }
    td { padding:0.75rem; border-bottom:1px solid #0d0d1a; font-size:0.9rem; }
    tr:hover { background:#1a1a2e; }
    a { color:#00d4ff; text-decoration:none; }
    a:hover { text-decoration:underline; }
    .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; }
    .badge-critical { background:#ff000033; color:#ff4444; }
    .badge-high { background:#ff440033; color:#ff8844; }
    .badge-medium { background:#ffaa0033; color:#ffaa00; }
    .badge-low { background:#0088ff33; color:#4488ff; }
    .badge-info { background:#33333366; color:#888; }
    .stat-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:1rem; margin-bottom:2rem; }
    .stat-card { background:#111122; border:1px solid #1a1a2e; border-radius:8px; padding:1.25rem; text-align:center; }
    .stat-card .number { font-size:2rem; font-weight:700; color:#00d4ff; }
    .stat-card .label { color:#666; font-size:0.85rem; margin-top:0.25rem; }
    .filter-bar { display:flex; gap:0.5rem; margin-bottom:1rem; flex-wrap:wrap; }
    .filter-bar input, .filter-bar select { background:#0d0d1a; border:1px solid #1a1a2e; color:#e0e0e0; padding:0.5rem; border-radius:4px; font-size:0.85rem; }
    .filter-bar input { flex:1; min-width:200px; }
    .empty { text-align:center; padding:3rem; color:#666; }
"""


@ui_app.get("/", response_class=HTMLResponse)
async def dashboard():
    db = await get_db()
    scans = await db.list_scans(limit=50)

    rows = ""
    for s in scans:
        grade = s.get("risk_grade", "-") or "-"
        grade_class = {"A": "low", "B": "low", "C": "medium", "D": "high", "F": "critical"}.get(grade, "info")
        risk_score = s.get("risk_score", "-") or "-"
        started = s.get("started_at", "-") or "-"
        rows += f"""<tr>
            <td><a href="/scans/{escape(s['scan_id'])}">{escape(s['scan_id'])}</a></td>
            <td>{escape(str(s['target']))}</td>
            <td>{s.get('total_assets', 0)}</td>
            <td>{s.get('live_assets', 0)}</td>
            <td><span class="badge badge-{grade_class}">{escape(str(grade))} ({escape(str(risk_score))})</span></td>
            <td>{escape(started[:19]) if started != "-" else "-"}</td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="6" class="empty">No scans yet. Run: surfacemap discover target.com --tree</td></tr>'

    return f"""<!DOCTYPE html>
<html><head><title>SurfaceMap Dashboard</title><style>{_BASE_CSS}</style></head>
<body><div class="container">
    <div class="header"><h1>SurfaceMap Dashboard</h1><span class="version">v{__version__}</span></div>
    <div class="card"><h2>Recent Scans</h2>
        <table><thead><tr><th>Scan ID</th><th>Target</th><th>Assets</th><th>Live</th><th>Risk</th><th>Date</th></tr></thead>
        <tbody>{rows}</tbody></table>
    </div>
</div></body></html>"""


@ui_app.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(scan_id: str):
    db = await get_db()
    scan = await db.get_scan(scan_id)
    if not scan:
        return HTMLResponse("<h1>Scan not found</h1>", status_code=404)

    assets = scan.get("assets", [])

    # Stats
    type_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for a in assets:
        t = a.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
        s = a.get("severity", "info")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    stat_cards = f"""
        <div class="stat-card"><div class="number">{len(assets)}</div><div class="label">Total Assets</div></div>
        <div class="stat-card"><div class="number">{severity_counts.get('critical', 0)}</div><div class="label">Critical</div></div>
        <div class="stat-card"><div class="number">{severity_counts.get('high', 0)}</div><div class="label">High</div></div>
        <div class="stat-card"><div class="number">{severity_counts.get('medium', 0)}</div><div class="label">Medium</div></div>
        <div class="stat-card"><div class="number">{scan.get('risk_score', '-') or '-'}</div><div class="label">Risk Score ({scan.get('risk_grade', '-') or '-'})</div></div>
    """

    asset_rows = ""
    for a in assets[:500]:
        sev = a.get("severity", "info")
        asset_rows += f"""<tr class="asset-row" data-type="{escape(a.get('type', ''))}" data-severity="{escape(sev)}" data-source="{escape(a.get('source', ''))}">
            <td>{escape(a.get('value', '')[:80])}</td>
            <td>{escape(a.get('type', ''))}</td>
            <td>{escape(a.get('status', ''))}</td>
            <td><span class="badge badge-{escape(sev)}">{escape(sev)}</span></td>
            <td>{escape(a.get('source', ''))}</td>
        </tr>"""

    # Build type filter options
    type_options = "".join(f'<option value="{escape(t)}">{escape(t)} ({c})</option>' for t, c in sorted(type_counts.items(), key=lambda x: -x[1]))
    sev_options = "".join(f'<option value="{escape(s)}">{escape(s)} ({c})</option>' for s, c in severity_counts.items())

    filter_js = """
    <script>
    function filterAssets() {
        const search = document.getElementById('search').value.toLowerCase();
        const typeFilter = document.getElementById('typeFilter').value;
        const sevFilter = document.getElementById('sevFilter').value;
        document.querySelectorAll('.asset-row').forEach(row => {
            const text = row.textContent.toLowerCase();
            const type = row.dataset.type;
            const sev = row.dataset.severity;
            const show = text.includes(search) && (!typeFilter || type === typeFilter) && (!sevFilter || sev === sevFilter);
            row.style.display = show ? '' : 'none';
        });
    }
    </script>
    """

    exec_summary_html = ""
    if scan.get("executive_summary"):
        exec_summary_html = f'<div class="card"><h2>Executive Summary</h2><p style="line-height:1.6">{escape(scan["executive_summary"])}</p></div>'

    truncation_notice = ""
    if len(assets) > 500:
        truncation_notice = f'<p style="text-align:center;padding:1rem;color:#666">Showing first 500 of {len(assets)} assets</p>'

    return f"""<!DOCTYPE html>
<html><head><title>Scan {scan_id} - SurfaceMap</title><style>{_BASE_CSS}</style></head>
<body><div class="container">
    <div class="header"><h1><a href="/">SurfaceMap</a> / {escape(scan.get('target', ''))}</h1><span class="version">{escape(scan_id)}</span></div>
    <div class="stat-grid">{stat_cards}</div>

    {exec_summary_html}

    <div class="card"><h2>Assets ({len(assets)})</h2>
        <div class="filter-bar">
            <input type="text" id="search" placeholder="Search assets..." oninput="filterAssets()">
            <select id="typeFilter" onchange="filterAssets()"><option value="">All Types</option>{type_options}</select>
            <select id="sevFilter" onchange="filterAssets()"><option value="">All Severities</option>{sev_options}</select>
        </div>
        <table><thead><tr><th>Value</th><th>Type</th><th>Status</th><th>Severity</th><th>Source</th></tr></thead>
        <tbody>{asset_rows}</tbody></table>
        {truncation_notice}
    </div>
</div>{filter_js}</body></html>"""
