"""Web UI dashboard for SurfaceMap — dark theme, mind map toggle, asset explorer."""

from __future__ import annotations

import json
import os
from html import escape
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, FileResponse
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


# ── Shared CSS ──
_CSS = """
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Inter',-apple-system,system-ui,sans-serif; background:#0a0a0f; color:#e2e8f0; line-height:1.6; }
a { color:#22d3ee; text-decoration:none; }
a:hover { text-decoration:underline; color:#67e8f9; }

/* Layout */
.container { max-width:1400px; margin:0 auto; padding:1.5rem 2rem; }
.header { display:flex; justify-content:space-between; align-items:center; padding:1rem 0 1.5rem; border-bottom:1px solid #1e293b; margin-bottom:1.5rem; }
.header h1 { font-size:1.4rem; font-weight:700; }
.header h1 span { color:#22d3ee; }
.header .meta { color:#64748b; font-size:0.8rem; }

/* Cards */
.card { background:#0f172a; border:1px solid #1e293b; border-radius:12px; padding:1.5rem; margin-bottom:1.25rem; }
.card h2 { color:#22d3ee; font-size:1rem; font-weight:600; margin-bottom:1rem; }

/* Stats grid */
.stat-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:1rem; margin-bottom:1.5rem; }
.stat-card { background:#0f172a; border:1px solid #1e293b; border-radius:12px; padding:1.25rem; text-align:center; transition:border-color 0.2s; }
.stat-card:hover { border-color:#22d3ee33; }
.stat-card .num { font-size:2.2rem; font-weight:800; background:linear-gradient(135deg,#22d3ee,#a78bfa); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.stat-card .lbl { color:#64748b; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; margin-top:0.25rem; }

/* Table */
table { width:100%; border-collapse:collapse; font-size:0.85rem; }
th { text-align:left; padding:0.6rem 0.75rem; color:#64748b; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; border-bottom:1px solid #1e293b; position:sticky; top:0; background:#0f172a; }
td { padding:0.6rem 0.75rem; border-bottom:1px solid #1e293b08; }
tr:hover { background:#1e293b40; }

/* Badges */
.badge { display:inline-block; padding:2px 10px; border-radius:9999px; font-size:0.7rem; font-weight:600; letter-spacing:0.02em; }
.badge-critical { background:#ef444420; color:#f87171; border:1px solid #ef444430; }
.badge-high { background:#f9731620; color:#fb923c; border:1px solid #f9731630; }
.badge-medium { background:#eab30820; color:#fbbf24; border:1px solid #eab30830; }
.badge-low { background:#3b82f620; color:#60a5fa; border:1px solid #3b82f630; }
.badge-info { background:#64748b15; color:#94a3b8; border:1px solid #64748b20; }
.badge-live { background:#22c55e20; color:#4ade80; border:1px solid #22c55e30; }
.badge-down { background:#ef444415; color:#f87171; border:1px solid #ef444420; }

/* Filter bar */
.filter-bar { display:flex; gap:0.5rem; margin-bottom:1rem; flex-wrap:wrap; }
.filter-bar input, .filter-bar select { background:#1e293b; border:1px solid #334155; color:#e2e8f0; padding:0.5rem 0.75rem; border-radius:8px; font-size:0.8rem; outline:none; }
.filter-bar input:focus, .filter-bar select:focus { border-color:#22d3ee; }
.filter-bar input { flex:1; min-width:200px; }

/* Toggle tabs */
.tabs { display:flex; gap:0.5rem; margin-bottom:1.5rem; }
.tab { padding:0.5rem 1.25rem; border-radius:8px; font-size:0.85rem; font-weight:500; cursor:pointer; border:1px solid #1e293b; background:#0f172a; color:#94a3b8; transition:all 0.15s; }
.tab:hover { border-color:#334155; color:#e2e8f0; }
.tab.active { background:#22d3ee15; border-color:#22d3ee40; color:#22d3ee; }

/* Mind map iframe */
.mindmap-frame { width:100%; height:calc(100vh - 200px); border:1px solid #1e293b; border-radius:12px; background:#0a0a0f; }

/* Empty state */
.empty { text-align:center; padding:4rem 2rem; color:#475569; }
.empty h3 { font-size:1.1rem; margin-bottom:0.5rem; color:#64748b; }
.empty code { background:#1e293b; padding:0.25rem 0.75rem; border-radius:6px; font-size:0.85rem; color:#22d3ee; }
"""


@ui_app.get("/", response_class=HTMLResponse)
async def dashboard():
    db = await get_db()
    scans = await db.list_scans(limit=50)

    rows = ""
    for s in scans:
        total = s.get("total_assets", 0)
        live = s.get("live_assets", 0)
        started = str(s.get("started_at", "-") or "-")[:19]
        rows += f"""<tr>
            <td><a href="/scans/{escape(s['scan_id'])}">{escape(s['scan_id'][:12])}</a></td>
            <td><strong>{escape(str(s.get('target','-')))}</strong></td>
            <td>{total}</td>
            <td><span class="badge badge-live">{live}</span></td>
            <td>{escape(started)}</td>
            <td><a href="/scans/{escape(s['scan_id'])}">View</a></td>
        </tr>"""

    if not rows:
        rows = f"""<tr><td colspan="6"><div class="empty">
            <h3>No scans yet</h3>
            <p>Run a discovery scan first:</p><br>
            <code>surfacemap discover "Company Name" --domain example.com</code>
        </div></td></tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SurfaceMap Dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{_CSS}</style></head>
<body><div class="container">
    <div class="header">
        <h1><span>SurfaceMap</span> Dashboard</h1>
        <div class="meta">v{__version__} | BreachLine Labs</div>
    </div>

    <div class="stat-grid">
        <div class="stat-card"><div class="num">{len(scans)}</div><div class="lbl">Total Scans</div></div>
        <div class="stat-card"><div class="num">{sum(s.get('total_assets',0) for s in scans)}</div><div class="lbl">Total Assets</div></div>
        <div class="stat-card"><div class="num">{sum(s.get('live_assets',0) for s in scans)}</div><div class="lbl">Live Assets</div></div>
    </div>

    <div class="card">
        <h2>Scan History</h2>
        <table>
            <thead><tr><th>ID</th><th>Target</th><th>Assets</th><th>Live</th><th>Date</th><th>Action</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>
</div></body></html>"""


def _render_status_rows(status_counts: dict) -> str:
    rows = []
    for s, c in sorted(status_counts.items(), key=lambda x: -x[1]):
        cls = "live" if s == "live" else "down" if s == "down" else "info"
        rows.append(
            f'<div style="display:flex;justify-content:space-between;padding:0.3rem 0;'
            f'border-bottom:1px solid #1e293b08">'
            f'<span class="badge badge-{cls}">{escape(s)}</span>'
            f'<span style="font-weight:600">{c}</span></div>'
        )
    return "".join(rows)


@ui_app.get("/scans/{{scan_id}}", response_class=HTMLResponse)
async def scan_detail(scan_id: str):
    db = await get_db()
    scan = await db.get_scan(scan_id)
    if not scan:
        return HTMLResponse("<h1>Scan not found</h1>", status_code=404)

    assets = scan.get("assets", [])
    target = escape(str(scan.get("target", "")))

    # Stats
    type_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    sev_counts: dict[str, int] = {}
    for a in assets:
        t = a.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
        st = a.get("status", "unknown")
        status_counts[st] = status_counts.get(st, 0) + 1
        sv = a.get("severity", "info")
        sev_counts[sv] = sev_counts.get(sv, 0) + 1

    live = status_counts.get("live", 0)
    crit = sev_counts.get("critical", 0)
    high = sev_counts.get("high", 0)

    # Stat cards
    stat_html = f"""
        <div class="stat-card"><div class="num">{len(assets)}</div><div class="lbl">Total Assets</div></div>
        <div class="stat-card"><div class="num" style="-webkit-text-fill-color:#4ade80">{live}</div><div class="lbl">Live</div></div>
        <div class="stat-card"><div class="num" style="-webkit-text-fill-color:#f87171">{crit}</div><div class="lbl">Critical</div></div>
        <div class="stat-card"><div class="num" style="-webkit-text-fill-color:#fb923c">{high}</div><div class="lbl">High</div></div>
        <div class="stat-card"><div class="num">{len(type_counts)}</div><div class="lbl">Asset Types</div></div>
    """

    # Asset rows
    asset_rows = ""
    for a in assets[:500]:
        sv = a.get("severity", "info")
        st = a.get("status", "unknown")
        st_class = "live" if st == "live" else "down" if st == "down" else "info"
        techs = ", ".join(a.get("technologies", [])[:3])
        asset_rows += f"""<tr class="asset-row" data-type="{escape(a.get('type',''))}" data-sev="{escape(sv)}" data-status="{escape(st)}">
            <td style="max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{escape(a.get('value','')[:80])}</td>
            <td><span class="badge badge-info">{escape(a.get('type',''))}</span></td>
            <td><span class="badge badge-{st_class}">{escape(st)}</span></td>
            <td><span class="badge badge-{sv}">{escape(sv)}</span></td>
            <td style="color:#64748b;font-size:0.8rem">{escape(techs)}</td>
            <td style="color:#64748b;font-size:0.8rem">{escape(a.get('source',''))}</td>
        </tr>"""

    # Type filter options
    type_opts = "".join(f'<option value="{escape(t)}">{escape(t)} ({c})</option>' for t, c in sorted(type_counts.items(), key=lambda x: -x[1]))
    sev_opts = "".join(f'<option value="{escape(s)}">{escape(s)} ({c})</option>' for s, c in sev_counts.items())
    status_opts = "".join(f'<option value="{escape(s)}">{escape(s)} ({c})</option>' for s, c in status_counts.items())

    # Check for mind map file
    mindmap_path = f"output/{scan_id[:12]}_mindmap.html"
    has_mindmap = Path(mindmap_path).exists()
    # Also check with full scan_id
    for f in Path("output").glob("*mindmap*"):
        has_mindmap = True
        mindmap_path = str(f)
        break

    mindmap_tab = ""
    mindmap_content = ""
    if has_mindmap:
        mindmap_tab = '<div class="tab" onclick="toggleView(\'mindmap\')">Mind Map</div>'
        mindmap_content = f'<div id="mindmap-view" style="display:none"><iframe class="mindmap-frame" src="/mindmap/{scan_id}"></iframe></div>'

    trunc = f'<p style="text-align:center;padding:1rem;color:#475569">Showing {min(len(assets),500)} of {len(assets)} assets</p>' if len(assets) > 500 else ""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{target} — SurfaceMap</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{_CSS}</style></head>
<body><div class="container">
    <div class="header">
        <h1><a href="/" style="color:#e2e8f0"><span>SurfaceMap</span></a> / {target}</h1>
        <div class="meta">{escape(scan_id[:12])}</div>
    </div>

    <div class="stat-grid">{stat_html}</div>

    <div class="tabs">
        <div class="tab active" onclick="toggleView('dashboard')">Dashboard</div>
        <div class="tab" onclick="toggleView('assets')">Assets ({len(assets)})</div>
        {mindmap_tab}
    </div>

    <div id="dashboard-view">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
            <div class="card"><h2>By Type</h2>
                {''.join(f'<div style="display:flex;justify-content:space-between;padding:0.3rem 0;border-bottom:1px solid #1e293b08"><span>{escape(t)}</span><span style="color:#22d3ee;font-weight:600">{c}</span></div>' for t,c in sorted(type_counts.items(), key=lambda x:-x[1])[:10])}
            </div>
            <div class="card"><h2>By Status</h2>
                {_render_status_rows(status_counts)}
            </div>
        </div>
    </div>

    <div id="assets-view" style="display:none">
        <div class="card">
            <div class="filter-bar">
                <input type="text" id="search" placeholder="Search assets..." oninput="filterAssets()">
                <select id="typeF" onchange="filterAssets()"><option value="">All Types</option>{type_opts}</select>
                <select id="sevF" onchange="filterAssets()"><option value="">All Severities</option>{sev_opts}</select>
                <select id="statusF" onchange="filterAssets()"><option value="">All Status</option>{status_opts}</select>
            </div>
            <div style="max-height:70vh;overflow-y:auto">
            <table><thead><tr><th>Asset</th><th>Type</th><th>Status</th><th>Severity</th><th>Tech</th><th>Source</th></tr></thead>
            <tbody>{asset_rows}</tbody></table>
            </div>
            {trunc}
        </div>
    </div>

    {mindmap_content}

</div>
<script>
function toggleView(view) {{
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    ['dashboard','assets','mindmap'].forEach(v => {{
        const el = document.getElementById(v+'-view');
        if (el) el.style.display = v === view ? '' : 'none';
    }});
    event.target.classList.add('active');
}}
function filterAssets() {{
    const q = document.getElementById('search').value.toLowerCase();
    const tf = document.getElementById('typeF').value;
    const sf = document.getElementById('sevF').value;
    const stf = document.getElementById('statusF').value;
    document.querySelectorAll('.asset-row').forEach(r => {{
        const ok = r.textContent.toLowerCase().includes(q)
            && (!tf || r.dataset.type === tf)
            && (!sf || r.dataset.sev === sf)
            && (!stf || r.dataset.status === stf);
        r.style.display = ok ? '' : 'none';
    }});
}}
</script>
</body></html>"""


@ui_app.get("/mindmap/{{scan_id}}")
async def serve_mindmap(scan_id: str):
    """Serve mind map HTML file for iframe embedding."""
    output_dir = Path("output")
    # Try to find matching mind map
    for f in sorted(output_dir.glob("*mindmap*"), key=lambda p: p.stat().st_mtime, reverse=True):
        return FileResponse(str(f), media_type="text/html")
    return HTMLResponse("<h2 style='color:#64748b;text-align:center;padding:4rem'>No mind map generated yet</h2>")


@ui_app.get("/health")
async def health():
    return {"status": "ok", "version": __version__}
