"""SQLite storage for scan results.

Uses aiosqlite for async database operations. Stores scan metadata
and individual assets, supports diffing between scans.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from surfacemap.core.config import get_config

logger = logging.getLogger(__name__)


class ScanDatabase:
    """Async SQLite database for persisting scan results."""

    def __init__(self, db_path: Path | None = None) -> None:
        config = get_config()
        self.db_path = str(db_path or config.db_path)

    async def initialize(self) -> None:
        """Create database tables if they don't exist."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    total_assets INTEGER DEFAULT 0,
                    live_assets INTEGER DEFAULT 0,
                    risk_score INTEGER,
                    risk_grade TEXT,
                    executive_summary TEXT,
                    stats_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    value TEXT NOT NULL,
                    type TEXT NOT NULL,
                    status TEXT DEFAULT 'unknown',
                    severity TEXT DEFAULT 'info',
                    parent TEXT,
                    source TEXT,
                    technologies TEXT,
                    ports TEXT,
                    ip_addresses TEXT,
                    notes TEXT,
                    metadata_json TEXT,
                    fingerprint TEXT NOT NULL,
                    discovered_at TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_assets_scan_id
                ON assets(scan_id)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_assets_type
                ON assets(type)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_assets_fingerprint
                ON assets(fingerprint)
            """)
            await db.commit()
            logger.info("Database initialized at %s", self.db_path)

    async def save_scan(self, result: Any) -> None:
        """Save a complete scan result to the database.

        Args:
            result: A ScanResult instance.
        """
        stats = result.compute_stats()

        async with aiosqlite.connect(self.db_path) as db:
            # Insert scan record
            await db.execute(
                """
                INSERT OR REPLACE INTO scans
                (scan_id, target, started_at, completed_at, total_assets,
                 live_assets, risk_score, risk_grade, executive_summary, stats_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.target,
                    result.started_at,
                    result.completed_at,
                    stats["total_assets"],
                    stats["live_assets"],
                    getattr(result, "risk_score", None),
                    getattr(result, "risk_grade", None),
                    getattr(result, "executive_summary", None),
                    json.dumps(stats),
                ),
            )

            # Insert assets
            for asset in result.assets:
                await db.execute(
                    """
                    INSERT INTO assets
                    (scan_id, value, type, status, severity, parent, source,
                     technologies, ports, ip_addresses, notes, metadata_json,
                     fingerprint, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.scan_id,
                        asset.value,
                        asset.type.value,
                        asset.status.value,
                        asset.severity.value,
                        asset.parent,
                        asset.source,
                        json.dumps(asset.technologies),
                        json.dumps(asset.ports),
                        json.dumps(asset.ip_addresses),
                        asset.notes,
                        json.dumps(asset.metadata),
                        asset.fingerprint,
                        asset.discovered_at,
                    ),
                )

            await db.commit()
            logger.info(
                "Saved scan %s with %d assets",
                result.scan_id,
                len(result.assets),
            )

    async def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve a scan and its assets by ID.

        Args:
            scan_id: The unique scan identifier.

        Returns:
            Dict with scan data and assets, or None if not found.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            # Get scan record
            cursor = await db.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            )
            scan_row = await cursor.fetchone()

            if not scan_row:
                return None

            scan_data = dict(scan_row)
            if scan_data.get("stats_json"):
                scan_data["stats"] = json.loads(scan_data.pop("stats_json"))

            # Get assets
            cursor = await db.execute(
                "SELECT * FROM assets WHERE scan_id = ? ORDER BY type, value",
                (scan_id,),
            )
            asset_rows = await cursor.fetchall()

            assets = []
            for row in asset_rows:
                asset = dict(row)
                # Parse JSON fields
                for field in ("technologies", "ports", "ip_addresses", "metadata_json"):
                    if field in asset and asset[field]:
                        try:
                            parsed = json.loads(asset[field])
                            key = "metadata" if field == "metadata_json" else field
                            asset[key] = parsed
                        except json.JSONDecodeError:
                            pass
                if "metadata_json" in asset:
                    del asset["metadata_json"]
                assets.append(asset)

            scan_data["assets"] = assets
            return scan_data

    async def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent scans with summary info.

        Args:
            limit: Maximum number of scans to return.

        Returns:
            List of scan summary dicts.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT scan_id, target, started_at, completed_at,
                       total_assets, live_assets, risk_score, risk_grade
                FROM scans
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def diff_scans(
        self, scan_id_old: str, scan_id_new: str
    ) -> dict[str, Any]:
        """Compare two scans and return the differences.

        Args:
            scan_id_old: The older scan ID.
            scan_id_new: The newer scan ID.

        Returns:
            Dict with 'added', 'removed', and 'changed' asset lists.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            # Get fingerprints for old scan
            cursor = await db.execute(
                "SELECT fingerprint, value, type, status, severity "
                "FROM assets WHERE scan_id = ?",
                (scan_id_old,),
            )
            old_rows = await cursor.fetchall()
            old_map = {row["fingerprint"]: dict(row) for row in old_rows}

            # Get fingerprints for new scan
            cursor = await db.execute(
                "SELECT fingerprint, value, type, status, severity "
                "FROM assets WHERE scan_id = ?",
                (scan_id_new,),
            )
            new_rows = await cursor.fetchall()
            new_map = {row["fingerprint"]: dict(row) for row in new_rows}

            old_fps = set(old_map.keys())
            new_fps = set(new_map.keys())

            added = [new_map[fp] for fp in (new_fps - old_fps)]
            removed = [old_map[fp] for fp in (old_fps - new_fps)]

            # Check for status/severity changes on assets that exist in both
            changed = []
            for fp in old_fps & new_fps:
                old_asset = old_map[fp]
                new_asset = new_map[fp]
                if (
                    old_asset["status"] != new_asset["status"]
                    or old_asset["severity"] != new_asset["severity"]
                ):
                    changed.append({
                        "asset": new_asset,
                        "old_status": old_asset["status"],
                        "new_status": new_asset["status"],
                        "old_severity": old_asset["severity"],
                        "new_severity": new_asset["severity"],
                    })

            return {
                "old_scan": scan_id_old,
                "new_scan": scan_id_new,
                "added": added,
                "removed": removed,
                "changed": changed,
                "summary": {
                    "total_added": len(added),
                    "total_removed": len(removed),
                    "total_changed": len(changed),
                },
            }
