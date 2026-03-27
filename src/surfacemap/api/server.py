"""FastAPI server for SurfaceMap.

Provides REST API endpoints for running scans, retrieving results,
and health checks. Install with: pip install 'surfacemap[api]'
"""

from __future__ import annotations

import asyncio
from typing import Any

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
except ImportError:
    raise ImportError(
        "FastAPI is required for the API server. "
        "Install with: pip install 'surfacemap[api]'"
    )

from surfacemap import __version__
from surfacemap.discovery.engine import DiscoveryEngine
from surfacemap.storage.db import ScanDatabase

app = FastAPI(
    title="SurfaceMap API",
    description="LLM-driven attack surface discovery API",
    version=__version__,
)

# In-memory store for active scans
_active_scans: dict[str, dict[str, Any]] = {}
_db: ScanDatabase | None = None


async def get_db() -> ScanDatabase:
    """Get or initialize the database connection."""
    global _db
    if _db is None:
        _db = ScanDatabase()
        await _db.initialize()
    return _db


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {
        "status": "ok",
        "version": __version__,
        "service": "surfacemap",
    }


@app.post("/discover")
async def discover(
    target: str,
    domain: str | None = None,
) -> JSONResponse:
    """Start a new discovery scan.

    Args:
        target: Company name or domain to scan.
        domain: Primary domain (if target is a company name).

    Returns:
        JSON with scan_id and status.
    """
    effective_domain = domain or target
    engine = DiscoveryEngine(target=target, domain=effective_domain)

    # Start scan in background
    scan_id = engine.result.scan_id
    _active_scans[scan_id] = {"status": "running", "target": target}

    async def run_scan() -> None:
        try:
            result = await engine.run()
            db = await get_db()
            await db.save_scan(result)
            _active_scans[scan_id] = {
                "status": "completed",
                "target": target,
                "stats": result.compute_stats(),
            }
        except Exception as e:
            _active_scans[scan_id] = {
                "status": "failed",
                "target": target,
                "error": str(e),
            }

    asyncio.create_task(run_scan())

    return JSONResponse(
        status_code=202,
        content={
            "scan_id": scan_id,
            "status": "running",
            "target": target,
            "domain": effective_domain,
            "message": "Scan started. Poll GET /scans/{scan_id} for results.",
        },
    )


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str) -> JSONResponse:
    """Get scan results by ID.

    Args:
        scan_id: The unique scan identifier.

    Returns:
        Full scan results if completed, or current status.
    """
    # Check active scans first
    if scan_id in _active_scans:
        active = _active_scans[scan_id]
        if active["status"] == "running":
            return JSONResponse(
                status_code=200,
                content={"scan_id": scan_id, "status": "running"},
            )
        elif active["status"] == "failed":
            return JSONResponse(
                status_code=200,
                content={
                    "scan_id": scan_id,
                    "status": "failed",
                    "error": active.get("error", "Unknown error"),
                },
            )

    # Check database
    try:
        db = await get_db()
        result = await db.get_scan(scan_id)
        if result:
            return JSONResponse(status_code=200, content=result)
    except Exception:
        pass

    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")


@app.get("/scans")
async def list_scans(limit: int = 20) -> JSONResponse:
    """List recent scans.

    Args:
        limit: Maximum number of scans to return.

    Returns:
        List of scan summaries.
    """
    try:
        db = await get_db()
        scans = await db.list_scans(limit=limit)
        return JSONResponse(status_code=200, content={"scans": scans})
    except Exception as e:
        return JSONResponse(
            status_code=200,
            content={"scans": [], "error": str(e)},
        )
