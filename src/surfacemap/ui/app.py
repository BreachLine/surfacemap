"""SurfaceMap Web UI — serves mind map as the main dashboard.

The mind map HTML already contains: stats, tech panel, executive summary,
attack paths, and the interactive D3.js tree. No need for a separate dashboard.
"""

from __future__ import annotations

import os
from html import escape
from pathlib import Path

try:
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, FileResponse
except ImportError:
    raise ImportError("FastAPI required. Install: pip install 'surfacemap[api]'")

from surfacemap import __version__
from surfacemap.storage.db import ScanDatabase

ui_app = FastAPI(title="SurfaceMap", version=__version__)

_db: ScanDatabase | None = None

OUTPUT_DIR = Path(os.environ.get("SURFACEMAP_OUTPUT", "output"))


async def get_db() -> ScanDatabase:
    global _db
    if _db is None:
        _db = ScanDatabase()
        await _db.initialize()
    return _db


@ui_app.get("/", response_class=HTMLResponse)
async def index():
    """List scans — each links to its mind map."""
    db = await get_db()
    scans = await db.list_scans(limit=50)

    if not scans:
        return HTMLResponse(_empty_page())

    rows = ""
    for s in scans:
        sid = escape(s["scan_id"])
        target = escape(str(s.get("target", "-")))
        total = s.get("total_assets", 0)
        live = s.get("live_assets", 0)
        date = str(s.get("started_at", "-") or "-")[:19]
        rows += (
            f'<tr onclick="location.href=\'/scan/{sid}\'" style="cursor:pointer">'
            f"<td>{target}</td><td>{total}</td><td>{live}</td><td>{date}</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SurfaceMap</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#09090b;color:#e4e4e7;font-family:Inter,-apple-system,system-ui,sans-serif}}
.wrap{{max-width:900px;margin:0 auto;padding:3rem 2rem}}
h1{{font-size:1.3rem;font-weight:600;margin-bottom:2rem}}
h1 span{{color:#22d3ee}}
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;padding:0.6rem;color:#71717a;font-size:0.75rem;text-transform:uppercase;
    letter-spacing:0.05em;border-bottom:1px solid #27272a}}
td{{padding:0.6rem;border-bottom:1px solid #18181b;font-size:0.85rem}}
tr:hover{{background:#18181b}}
.sub{{color:#52525b;font-size:0.8rem;margin-top:0.25rem}}
</style></head>
<body><div class="wrap">
<h1><span>SurfaceMap</span> Scans</h1>
<p class="sub">Click a scan to open its interactive mind map.</p><br>
<table><thead><tr><th>Target</th><th>Assets</th><th>Live</th><th>Date</th></tr></thead>
<tbody>{rows}</tbody></table>
</div></body></html>"""


@ui_app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_mindmap(scan_id: str):
    """Serve the mind map HTML directly as the scan view."""
    # Find the mind map file
    mindmap_file = _find_mindmap(scan_id)
    if mindmap_file:
        return FileResponse(str(mindmap_file), media_type="text/html")

    # No mind map file — generate one from DB
    db = await get_db()
    scan = await db.get_scan(scan_id)
    if not scan:
        return HTMLResponse("<h1 style='color:#e4e4e7;background:#09090b;padding:3rem;font-family:system-ui'>Scan not found</h1>", 404)

    # Rebuild ScanResult and generate mind map
    try:
        from surfacemap.core.models import ScanResult, Asset, AssetType, AssetStatus, Severity
        result = ScanResult(target=scan.get("target", ""), scan_id=scan_id)
        for a in scan.get("assets", []):
            asset = Asset(
                value=a.get("value", ""),
                type=AssetType(a.get("type", "domain")),
                status=AssetStatus(a.get("status", "unknown")),
                parent=a.get("parent", ""),
                source=a.get("source", ""),
                severity=Severity(a.get("severity", "info")),
                technologies=a.get("technologies", []),
                notes=a.get("notes", ""),
            )
            result.add_asset(asset)
        result.compute_stats()

        from surfacemap.output.mindmap import generate_html_mindmap
        OUTPUT_DIR.mkdir(exist_ok=True)
        path = generate_html_mindmap(result, OUTPUT_DIR / f"{scan_id[:12]}_mindmap.html")
        return FileResponse(str(path), media_type="text/html")
    except Exception as exc:
        return HTMLResponse(f"<h1 style='color:#f87171;background:#09090b;padding:3rem;font-family:system-ui'>Error generating mind map: {exc}</h1>", 500)


@ui_app.get("/health")
async def health():
    return {"status": "ok", "version": __version__}


def _find_mindmap(scan_id: str) -> Path | None:
    """Find mind map file for a scan ID."""
    if not OUTPUT_DIR.exists():
        return None
    # Try exact match
    exact = OUTPUT_DIR / f"{scan_id[:12]}_mindmap.html"
    if exact.exists():
        return exact
    # Try partial match
    for f in sorted(OUTPUT_DIR.glob("*mindmap*.html"), key=lambda p: p.stat().st_mtime, reverse=True):
        if scan_id[:8] in f.name:
            return f
    # Return latest
    maps = sorted(OUTPUT_DIR.glob("*mindmap*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    return maps[0] if maps else None


def _empty_page() -> str:
    return """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SurfaceMap</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#09090b;color:#e4e4e7;font-family:Inter,-apple-system,system-ui,sans-serif;
     display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{text-align:center}
h1{font-size:1.3rem;margin-bottom:1rem}
h1 span{color:#22d3ee}
p{color:#52525b;margin-bottom:1.5rem}
code{background:#18181b;padding:0.3rem 0.8rem;border-radius:6px;font-size:0.85rem;color:#22d3ee}
</style></head>
<body><div class="box">
<h1><span>SurfaceMap</span></h1>
<p>No scans yet. Run a discovery first:</p>
<code>surfacemap discover "Company Name"</code>
</div></body></html>"""
